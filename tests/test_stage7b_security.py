"""Tests for Stage 7b security features.

Covers:
- Part 0a: lockfile_missing_integrity (WARN) and lockfile_resolved_mismatch (BLOCK).
- Part 0b: Cache key bound to (name, version, hash); integrity verification failure
  deletes corrupted cached tarball; alias attack prevention.
- Part 0c: Streaming tarball download size cap enforcement.
- Part 0d: Metadata TTL (1 hour in live mode, kept in evaluation mode).
- Part 0e: Base lockfile path relative to repo root, subdirectory support, outside-repo refusal.
- Part 0f: User-Agent header formatting.
"""

from __future__ import annotations

import io
import json
import tarfile
import time
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest
from typer.testing import CliRunner

from release_sentinel import __version__
from release_sentinel.cli import app
from release_sentinel.lockfile import (
    LockfileError,
    is_resolved_path_matching,
    read_lockfile_from_git,
    scan_lockfile_diff,
)
from release_sentinel.models import Decision
from release_sentinel.policy import load_policy
from release_sentinel.registry import (
    _USER_AGENT,
    MAX_TARBALL_BYTES,
    IntegrityError,
    NpmRegistryClient,
    RegistryError,
)

runner = CliRunner()


def _make_tarball_bytes(files: dict[str, str | bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, content in files.items():
            data = content.encode("utf-8") if isinstance(content, str) else content
            info = tarfile.TarInfo(name=f"package/{name}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class TestStage7bPart0Security:
    def test_user_agent_format(self):
        assert f"release-sentinel/{__version__}" in _USER_AGENT
        assert "https://github.com/Aryan2569/release-sentinel" in _USER_AGENT

    def test_is_resolved_path_matching(self):
        # Unscoped package
        assert is_resolved_path_matching(
            "lodash", "4.17.21", "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
        )
        assert not is_resolved_path_matching(
            "lodash", "4.17.21", "https://registry.npmjs.org/evil/-/evil-1.0.0.tgz"
        )
        assert not is_resolved_path_matching(
            "lodash", "4.17.21", "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"
        )
        # Scoped package
        assert is_resolved_path_matching(
            "@types/node", "20.0.0", "https://registry.npmjs.org/@types/node/-/node-20.0.0.tgz"
        )
        assert not is_resolved_path_matching(
            "@types/node", "20.0.0", "https://registry.npmjs.org/@types/evil/-/evil-1.0.0.tgz"
        )
        assert not is_resolved_path_matching(
            "@types/node", "20.0.0", "https://registry.npmjs.org/@evil/node/-/node-20.0.0.tgz"
        )

    def test_lockfile_resolved_mismatch_blocks_both_profiles(self, tmp_path):
        base_json = json.dumps({"name": "test-repo", "lockfileVersion": 2, "packages": {}})
        head_json = json.dumps({
            "name": "test-repo",
            "lockfileVersion": 2,
            "packages": {
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/evil/-/evil-1.0.0.tgz",
                    "integrity": "sha512-fakehash",
                }
            },
        })

        # Test under default profile
        pol_default = load_policy(profile="default")
        rep_def = scan_lockfile_diff(
            base_json, head_json, policy=pol_default, cache_dir=tmp_path
        )
        assert rep_def.decision == Decision.BLOCK
        assert any(
            p.get("decision") == "BLOCK" and "lockfile_resolved_mismatch" in p.get("evidence", [])
            for p in rep_def.package_results
        )

        # Test under strict profile
        pol_strict = load_policy(profile="strict")
        rep_strict = scan_lockfile_diff(
            base_json, head_json, policy=pol_strict, cache_dir=tmp_path
        )
        assert rep_strict.decision == Decision.BLOCK
        assert any(
            p.get("decision") == "BLOCK" and "lockfile_resolved_mismatch" in p.get("evidence", [])
            for p in rep_strict.package_results
        )

    def test_lockfile_missing_integrity_warns(self, tmp_path):
        base_json = json.dumps({"name": "test-repo", "lockfileVersion": 2, "packages": {}})
        head_json = json.dumps({
            "name": "test-repo",
            "lockfileVersion": 2,
            "packages": {
                "node_modules/clean-pkg": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/clean-pkg/-/clean-pkg-1.0.0.tgz",
                    # integrity omitted
                }
            },
        })

        clean_tarball = _make_tarball_bytes({
            "package.json": json.dumps({"name": "clean-pkg", "version": "1.0.0"}),
            "index.js": "module.exports = 42;\n",
        })

        mock_client = MagicMock(spec=NpmRegistryClient)
        mock_client.is_host_allowed.return_value = True
        mock_tar_path = tmp_path / "clean-pkg-1.0.0.tgz"
        mock_tar_path.write_bytes(clean_tarball)
        mock_client.download_tarball_url.return_value = mock_tar_path
        mock_client.download_tarball.return_value = mock_tar_path
        mock_client.get_metadata.return_value = {"versions": {"1.0.0": {}}, "time": {}}

        pol_default = load_policy(profile="default")
        rep = scan_lockfile_diff(
            base_json,
            head_json,
            policy=pol_default,
            registry_client=mock_client,
            cache_dir=tmp_path,
        )
        assert rep.decision == Decision.WARN
        pkg_res = rep.package_results[0]
        assert "lockfile_missing_integrity" in pkg_res["evidence"]

    def test_cache_safety_alias_attack(self, tmp_path):
        client = NpmRegistryClient(cache_dir=tmp_path)

        evil_bytes = _make_tarball_bytes({
            "package.json": json.dumps({"name": "evil", "version": "1.0.0"}),
            "index.js": "console.log('pwned');\n",
        })
        lodash_bytes = _make_tarball_bytes({
            "package.json": json.dumps({"name": "lodash", "version": "4.17.21"}),
            "index.js": "module.exports = {};\n",
        })

        def mock_send(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            if "evil-1.0.0.tgz" in url_str:
                return httpx.Response(200, content=evil_bytes, request=request)
            if "lodash-4.17.21.tgz" in url_str:
                return httpx.Response(200, content=lodash_bytes, request=request)
            return httpx.Response(404, request=request)

        mock_transport = httpx.MockTransport(mock_send)
        client._http = httpx.Client(transport=mock_transport)

        # 1. Attacker tries to download evil tarball under lodash alias
        path_alias = client.download_tarball_url(
            name="lodash",
            version="4.17.21",
            tarball_url="https://registry.npmjs.org/evil/-/evil-1.0.0.tgz",
        )
        assert path_alias.exists()

        # 2. Honest request downloads lodash from official URL
        path_real = client.download_tarball_url(
            name="lodash",
            version="4.17.21",
            tarball_url="https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
        )
        assert path_real.exists()

        # Cache paths must differ because keys are bound to URL/integrity!
        assert path_alias != path_real
        # Official lodash cached file must contain honest lodash bytes, not evil bytes
        assert path_real.read_bytes() == lodash_bytes

    def test_cache_integrity_failure_deletes_file(self, tmp_path):
        client = NpmRegistryClient(cache_dir=tmp_path)
        corrupted_bytes = b"corrupted tarball content"

        def mock_send(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=corrupted_bytes, request=request)

        mock_transport = httpx.MockTransport(mock_send)
        client._http = httpx.Client(transport=mock_transport)

        with pytest.raises(IntegrityError):
            client.download_tarball_url(
                name="some-pkg",
                version="1.0.0",
                tarball_url="https://registry.npmjs.org/some-pkg/-/some-pkg-1.0.0.tgz",
                integrity="sha512-validHashThatDoesNotMatch=",
            )

        # Verify that corrupted file was deleted and not left in cache
        pkg_dir = tmp_path / "some-pkg"
        if pkg_dir.exists():
            assert not list(pkg_dir.glob("*.tgz"))

    def test_streaming_download_size_cap(self, tmp_path):
        client = NpmRegistryClient(cache_dir=tmp_path)

        def mock_send(request: httpx.Request) -> httpx.Response:
            # Generate a stream exceeding MAX_TARBALL_BYTES
            chunk = b"X" * (1024 * 1024)  # 1 MB

            def generator():
                for _ in range(MAX_TARBALL_BYTES // (1024 * 1024) + 2):
                    yield chunk

            return httpx.Response(
                200,
                content=generator(),
                headers={"content-type": "application/octet-stream"},
                request=request,
            )

        mock_transport = httpx.MockTransport(mock_send)
        client._http = httpx.Client(transport=mock_transport)

        with pytest.raises(RegistryError, match="exceeds per-tarball limit"):
            client.download_tarball_url(
                name="oversized-pkg",
                version="1.0.0",
                tarball_url="https://registry.npmjs.org/oversized-pkg/-/oversized-pkg-1.0.0.tgz",
            )

    def test_metadata_ttl_live_vs_evaluation_mode(self, tmp_path):
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        cached_pkg = cache_dir / "my-pkg"
        cached_pkg.mkdir()
        meta_file = cached_pkg / "packument.json"
        meta_file.write_text(json.dumps({"name": "my-pkg", "version": "old"}), encoding="utf-8")

        # Set mtime to 2 hours ago (> 3600s TTL)
        two_hours_ago = time.time() - 7200
        import os

        os.utime(meta_file, (two_hours_ago, two_hours_ago))

        fetch_count = 0

        def mock_send(request: httpx.Request) -> httpx.Response:
            nonlocal fetch_count
            fetch_count += 1
            return httpx.Response(
                200,
                json={"name": "my-pkg", "version": "fresh"},
                request=request,
            )

        # 1. Evaluation mode: keeps cached packument even if older than TTL
        eval_client = NpmRegistryClient(cache_dir=cache_dir, evaluation_mode=True)
        eval_client._http = httpx.Client(transport=httpx.MockTransport(mock_send))
        now = datetime.now(UTC)
        meta_eval = eval_client.get_metadata("my-pkg", as_of=now)
        assert meta_eval["version"] == "old"
        assert fetch_count == 0

        # 2. Live mode: re-fetches metadata when expired
        live_client = NpmRegistryClient(cache_dir=cache_dir, evaluation_mode=False)
        live_client._http = httpx.Client(transport=httpx.MockTransport(mock_send))
        meta_live = live_client.get_metadata("my-pkg", as_of=now)
        assert meta_live["version"] == "fresh"
        assert fetch_count == 1

    def test_base_lockfile_path_validation(self, tmp_path):
        # Refuses path traversal or empty relative path
        with pytest.raises(LockfileError, match="Invalid repository-relative lockfile path"):
            read_lockfile_from_git("main", lockfile_rel_path="../outside/package-lock.json")

        with pytest.raises(LockfileError, match="Invalid repository-relative lockfile path"):
            read_lockfile_from_git("main", lockfile_rel_path="")

    def test_cli_diff_outside_repo_refusal(self, tmp_path):
        outside_file = tmp_path / "outside-package-lock.json"
        outside_file.write_text(
            json.dumps({"name": "outside", "lockfileVersion": 2, "packages": {}}),
            encoding="utf-8",
        )
        res = runner.invoke(app, ["lockfile", "--head", str(outside_file), "--base-ref", "HEAD"])
        assert res.exit_code == 2
        assert "outside git repo" in res.output or "Error" in res.output


class TestStage7bPart1Hygiene:
    def test_requirements_action_lock_exists_and_hashed(self):
        lock_path = Path("requirements-action.lock")
        assert lock_path.exists(), "requirements-action.lock must exist"
        content = lock_path.read_text(encoding="utf-8")
        assert "--hash=sha256:" in content
        # Must contain all direct dependencies
        for pkg in ("typer", "rich", "httpx", "pydantic", "node-semver"):
            assert pkg in content

    def test_dependabot_config(self):
        import yaml

        dep_path = Path(".github/dependabot.yml")
        assert dep_path.exists(), ".github/dependabot.yml must exist"
        data = yaml.safe_load(dep_path.read_text(encoding="utf-8"))
        assert data.get("version") == 2
        ecosystems = {u.get("package-ecosystem") for u in data.get("updates", [])}
        assert "pip" in ecosystems
        assert "github-actions" in ecosystems

    def test_pinned_action_shas(self):
        import re
        from pathlib import Path

        target_files = list(Path(".github/workflows").glob("*.yml")) + [Path("action.yml")]
        sha_re = re.compile(
            r"uses:\s*([a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+)@([a-f0-9]{40})\s*#\s*v[0-9]+(\.[0-9]+)*"
        )

        for path in target_files:
            content = path.read_text(encoding="utf-8")
            for line in content.splitlines():
                stripped = line.strip()
                if not stripped.startswith("uses:"):
                    continue
                # Local actions starting with ./ are exempt
                action_ref = stripped.split("uses:", 1)[1].strip()
                if action_ref.startswith("./") or action_ref.startswith("."):
                    continue
                match = sha_re.search(line)
                assert match is not None, (
                    f"Action not pinned by 40-char SHA with # vX.Y.Z comment in {path}: {line}"
                )

    def test_workflow_permissions(self):
        import yaml

        for path in (
            Path(".github/workflows/ci.yml"),
            Path(".github/workflows/release-sentinel-example.yml"),
        ):
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            perms = data.get("permissions", {})
            assert perms.get("contents") == "read", f"Workflow {path} missing contents: read"

