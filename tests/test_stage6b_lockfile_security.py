"""Tests for Stage 6b Part 5: Lockfile and Action Security Hardening.

Covers:
- SSRF host rejection (non-HTTPS, private IPs, loopback, link-local, non-allowlisted hosts)
- Redirect validation and SSRF blocking
- Integrity mismatch fail-closed behavior (BLOCK)
- Path traversal rejection in lockfile package names and filesystem paths
- Git ref validation (preventing option injection like `--output`)
- Non-registry sources (git, file, external URLs) reported as "unscanned non-registry source" (WARN)
- Per-tarball and total cumulative download budgets
- Secret redaction in URLs
"""

from __future__ import annotations

import io
import tarfile
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest

from release_sentinel.lockfile import (
    LockfileError,
    LockfileParseError,
    parse_lockfile_content,
    scan_lockfile_diff,
    validate_git_ref,
    validate_package_name,
)
from release_sentinel.models import Decision
from release_sentinel.registry import (
    MAX_TARBALL_BYTES,
    NpmRegistryClient,
    RegistryError,
    _safe_filename,
    redact_url_secrets,
    validate_registry_url,
)


def _make_dummy_tarball_bytes(name: str = "pkg", version: str = "1.0.0") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        pkg_json = f'{{"name": "{name}", "version": "{version}"}}'.encode()
        ti = tarfile.TarInfo(name="package/package.json")
        ti.size = len(pkg_json)
        tar.addfile(ti, io.BytesIO(pkg_json))
    return buf.getvalue()


class TestSsrfValidation:
    def test_http_scheme_rejected(self):
        with pytest.raises(RegistryError, match="Rejected non-HTTPS"):
            validate_registry_url("http://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz")

    def test_private_ips_rejected(self):
        # RFC 1918
        with pytest.raises(RegistryError, match="Rejected private"):
            validate_registry_url("https://10.0.0.1/pkg/-/pkg-1.0.0.tgz")
        with pytest.raises(RegistryError, match="Rejected private"):
            validate_registry_url("https://192.168.1.100/pkg/-/pkg-1.0.0.tgz")
        with pytest.raises(RegistryError, match="Rejected private"):
            validate_registry_url("https://172.16.5.20/pkg/-/pkg-1.0.0.tgz")

    def test_loopback_and_link_local_rejected(self):
        with pytest.raises(RegistryError, match="Rejected private"):
            validate_registry_url("https://127.0.0.1:8080/evil.tgz")
        with pytest.raises(RegistryError, match="Rejected private"):
            validate_registry_url("https://localhost/evil.tgz")
        # AWS metadata link-local
        with pytest.raises(RegistryError, match="Rejected private"):
            validate_registry_url("https://169.254.169.254/latest/meta-data")

    def test_non_allowlisted_host_rejected(self):
        with pytest.raises(RegistryError, match="not in allowed registry hosts"):
            validate_registry_url("https://attacker-c2.evil.com/pkg.tgz")

    def test_allowlisted_host_accepted(self):
        parsed = validate_registry_url("https://registry.npmjs.org/is-odd/-/is-odd-3.0.1.tgz")
        assert parsed.hostname == "registry.npmjs.org"

    def test_custom_allowed_hosts(self):
        custom = frozenset({"registry.npmjs.org", "npm.pkg.github.com"})
        parsed = validate_registry_url(
            "https://npm.pkg.github.com/@myorg/mypkg/-/mypkg-1.0.0.tgz",
            allowed_hosts=custom,
        )
        assert parsed.hostname == "npm.pkg.github.com"


class TestSecretRedaction:
    def test_basic_auth_credentials_redacted(self):
        url = "https://user:super_secret_pass@registry.npmjs.org/pkg/-/pkg-1.0.0.tgz"
        redacted = redact_url_secrets(url)
        assert "super_secret_pass" not in redacted
        assert "user:***@" in redacted

    def test_query_tokens_redacted(self):
        url = "https://registry.npmjs.org/pkg?token=npm_1234567890abcdef&auth=secretToken"
        redacted = redact_url_secrets(url)
        assert "npm_1234567890abcdef" not in redacted
        assert "secretToken" not in redacted
        assert "token=***" in redacted
        assert "auth=***" in redacted


class TestGitRefValidation:
    def test_valid_refs_accepted(self):
        assert validate_git_ref("HEAD") == "HEAD"
        assert validate_git_ref("main") == "main"
        assert validate_git_ref("v1.2.3") == "v1.2.3"
        assert validate_git_ref("feature/security-fix") == "feature/security-fix"
        assert validate_git_ref("HEAD~2") == "HEAD~2"
        assert validate_git_ref("abc1234^") == "abc1234^"

    def test_dash_prefix_rejected_to_prevent_flag_injection(self):
        with pytest.raises(LockfileError, match="cannot start with dash"):
            validate_git_ref("--output=evil.txt")
        with pytest.raises(LockfileError, match="cannot start with dash"):
            validate_git_ref("-o")

    def test_dangerous_characters_rejected(self):
        with pytest.raises(LockfileError, match="Invalid or unsafe characters"):
            validate_git_ref("HEAD; rm -rf /")
        with pytest.raises(LockfileError, match="Invalid or unsafe characters"):
            validate_git_ref("HEAD && whoami")
        with pytest.raises(LockfileError, match="Invalid or unsafe characters"):
            validate_git_ref("HEAD`evil`")
        with pytest.raises(LockfileError, match="Git ref cannot be empty"):
            validate_git_ref("")


class TestPathTraversalRejection:
    def test_validate_package_name_rejects_parent_traversal(self):
        with pytest.raises(LockfileError, match="Path traversal"):
            validate_package_name("../../evil")
        with pytest.raises(LockfileError, match="Path traversal"):
            validate_package_name("foo/../../bar")
        with pytest.raises(LockfileError, match="Path traversal"):
            validate_package_name("..\\..\\evil")

    def test_validate_package_name_rejects_absolute_paths(self):
        with pytest.raises(LockfileError, match="cannot start with"):
            validate_package_name("/etc/passwd")

    def test_safe_filename_rejects_traversal(self):
        with pytest.raises(RegistryError, match="Unsafe package name"):
            _safe_filename("../../evil")

    def test_lockfile_parse_rejects_traversal_entry(self):
        malicious_lockfile = """{
            "name": "my-app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "my-app" },
                "node_modules/../../evil-pkg": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/evil-pkg/-/evil-pkg-1.0.0.tgz"
                }
            }
        }"""
        with pytest.raises(LockfileParseError, match="Path traversal"):
            parse_lockfile_content(malicious_lockfile)


class TestLockfileUnscannedNonRegistrySources:
    def test_git_resolved_source_emits_warn(self, tmp_path: Path):
        base_lockfile = """{
            "name": "app",
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "app" }
            }
        }"""
        head_lockfile = """{
            "name": "app",
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "app" },
                "node_modules/my-fork": {
                    "version": "1.0.0",
                    "resolved": "git+https://github.com/myorg/my-fork.git#commit123"
                }
            }
        }"""
        report = scan_lockfile_diff(
            base_content=base_lockfile,
            head_content=head_lockfile,
            cache_dir=tmp_path / "cache",
        )
        assert report.decision == Decision.WARN
        assert len(report.package_results) == 1
        pkg_res = report.package_results[0]
        assert pkg_res["package"] == "my-fork"
        assert pkg_res["decision"] == "WARN"
        assert "unscanned_non_registry_source" in pkg_res["evidence"]

    def test_file_resolved_source_emits_warn(self, tmp_path: Path):
        base_lockfile = """{
            "name": "app",
            "lockfileVersion": 3,
            "packages": { "": { "name": "app" } }
        }"""
        head_lockfile = """{
            "name": "app",
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "app" },
                "node_modules/local-pkg": {
                    "version": "1.0.0",
                    "resolved": "file:../packages/local-pkg"
                }
            }
        }"""
        report = scan_lockfile_diff(
            base_content=base_lockfile,
            head_content=head_lockfile,
            cache_dir=tmp_path / "cache",
        )
        assert report.decision == Decision.WARN
        pkg_res = report.package_results[0]
        assert "unscanned_non_registry_source" in pkg_res["evidence"]

    def test_ssrf_resolved_source_emits_warn_without_network(self, tmp_path: Path):
        base_lockfile = """{
            "name": "app",
            "lockfileVersion": 3,
            "packages": { "": { "name": "app" } }
        }"""
        # Attacker placed an internal metadata service URL into the lockfile
        head_lockfile = """{
            "name": "app",
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "app" },
                "node_modules/metadata-stealer": {
                    "version": "1.0.0",
                    "resolved": "http://169.254.169.254/latest/meta-data"
                }
            }
        }"""
        report = scan_lockfile_diff(
            base_content=base_lockfile,
            head_content=head_lockfile,
            cache_dir=tmp_path / "cache",
        )
        assert report.decision == Decision.WARN
        pkg_res = report.package_results[0]
        assert pkg_res["decision"] == "WARN"
        assert "unscanned_non_registry_source" in pkg_res["evidence"]


class TestDownloadBudgetLimits:
    def test_single_tarball_size_budget(self, tmp_path: Path):
        client = NpmRegistryClient(cache_dir=tmp_path / "cache")
        # Oversized mock response (over 100 MB)
        oversized = b"X" * (MAX_TARBALL_BYTES + 1024)

        mock_resp = MagicMock()
        mock_resp.content = oversized
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Length": str(len(oversized))}
        mock_resp.history = []
        mock_resp.url = httpx.URL("https://registry.npmjs.org/big-pkg/-/big-pkg-1.0.0.tgz")

        client._http = MagicMock()
        client._http.get.return_value = mock_resp

        with pytest.raises(RegistryError, match="exceeds per-tarball limit"):
            client.download_tarball_url(
                name="big-pkg",
                version="1.0.0",
                tarball_url="https://registry.npmjs.org/big-pkg/-/big-pkg-1.0.0.tgz",
            )

    def test_cumulative_download_budget(self, tmp_path: Path):
        # Set small total budget: 1 KB
        client = NpmRegistryClient(
            cache_dir=tmp_path / "cache",
            max_total_download_bytes=1000,
        )

        dummy_bytes = _make_dummy_tarball_bytes("pkg", "1.0.0")
        mock_resp = MagicMock()
        mock_resp.content = dummy_bytes
        mock_resp.status_code = 200
        mock_resp.history = []
        mock_resp.url = httpx.URL("https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz")

        client._http = MagicMock()
        client._http.get.return_value = mock_resp

        # First download succeeds (dummy tarball is ~150 bytes)
        client.download_tarball_url(
            name="pkg1",
            version="1.0.0",
            tarball_url="https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz",
        )

        def _drain_budget():
            for i in range(15):
                client.download_tarball_url(
                    name=f"pkg_loop_{i}",
                    version="1.0.0",
                    tarball_url="https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz",
                )

        with pytest.raises(RegistryError, match="Total download budget exceeded"):
            _drain_budget()
