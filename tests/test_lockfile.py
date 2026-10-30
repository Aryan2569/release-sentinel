"""Unit tests for lockfile parsing, diffing, and scanning (Stage 6 Part 1).

Tests use benign, public package names (Rule 6).
Tarball extraction and inspection occur in-memory without running any code (Rule 1).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from release_sentinel.extractor import ReleaseContents
from release_sentinel.lockfile import (
    LockfileBudgetExceededError,
    LockfilePackage,
    LockfileParseError,
    UnsupportedLockfileError,
    check_supported_lockfile_path,
    diff_lockfiles,
    parse_lockfile_content,
    read_lockfile_from_path,
    scan_lockfile_diff,
)
from release_sentinel.models import Decision

# ---------------------------------------------------------------------------
# Sample Fixtures
# ---------------------------------------------------------------------------

LOCKFILE_V1 = json.dumps({
    "name": "example-app",
    "version": "1.0.0",
    "lockfileVersion": 1,
    "dependencies": {
        "lodash": {
            "version": "4.17.20",
            "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
            "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==",  # noqa: E501  # noqa: E501
        },
        "chalk": {
            "version": "4.1.0",
            "resolved": "https://registry.npmjs.org/chalk/-/chalk-4.1.0.tgz",
            "integrity": "sha512-qwx12ZsWLofyMT8FccNeBCSWi9GUMziFQ+RwBKFVPKUWhjjIIFBYD9vNPnQ8GbpFXVW302U4L4XrSDy6aW4RnA==",  # noqa: E501  # noqa: E501
            "dependencies": {
                "ansi-styles": {
                    "version": "4.3.0",
                    "resolved": "https://registry.npmjs.org/ansi-styles/-/ansi-styles-4.3.0.tgz",
                }
            },
        },
    },
})

LOCKFILE_V2 = json.dumps({
    "name": "example-app",
    "version": "1.0.0",
    "lockfileVersion": 2,
    "packages": {
        "": {
            "name": "example-app",
            "version": "1.0.0",
        },
        "node_modules/lodash": {
            "version": "4.17.21",
            "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
            "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==",  # noqa: E501  # noqa: E501
        },
        "node_modules/express": {
            "version": "4.18.2",
            "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
            "integrity": "sha512-5/psL6iVEKi52nK95Gsv5Mzh80BofcGZQ22lDYhXRyknHZg33Hphq9PcwUVCx4b0v50iTqE22/OOShxCvtgoOQ==",  # noqa: E501  # noqa: E501
        },
        "node_modules/@types/node": {
            "version": "20.11.0",
            "resolved": "https://registry.npmjs.org/@types/node/-/node-20.11.0.tgz",
        },
    },
    "dependencies": {
        "lodash": {"version": "4.17.21"},
    },
})

LOCKFILE_V3 = json.dumps({
    "name": "example-app",
    "version": "1.0.0",
    "lockfileVersion": 3,
    "packages": {
        "": {
            "name": "example-app",
            "version": "1.0.0",
        },
        "node_modules/lodash": {
            "version": "4.17.21",
            "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
            "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==",  # noqa: E501  # noqa: E501
        },
        "node_modules/chalk": {
            "version": "5.0.0",
            "resolved": "https://registry.npmjs.org/chalk/-/chalk-5.0.0.tgz",
        },
    },
})


# ---------------------------------------------------------------------------
# Test Lockfile Parsing
# ---------------------------------------------------------------------------


class TestLockfileParsing:
    def test_parse_v1_lockfile(self):
        pkgs = parse_lockfile_content(LOCKFILE_V1)
        assert "lodash" in pkgs
        assert pkgs["lodash"].version == "4.17.20"
        assert pkgs["lodash"].integrity is not None
        assert "chalk" in pkgs
        assert pkgs["chalk"].version == "4.1.0"
        # Nested dependency ANSI-styles parsed
        assert "ansi-styles" in pkgs
        assert pkgs["ansi-styles"].version == "4.3.0"

    def test_parse_v2_lockfile(self):
        pkgs = parse_lockfile_content(LOCKFILE_V2)
        assert "lodash" in pkgs
        assert pkgs["lodash"].version == "4.17.21"
        assert "express" in pkgs
        assert pkgs["express"].version == "4.18.2"
        assert "@types/node" in pkgs
        assert pkgs["@types/node"].version == "20.11.0"
        # Root package excluded
        assert "" not in pkgs
        assert "example-app" not in pkgs

    def test_parse_v3_lockfile(self):
        pkgs = parse_lockfile_content(LOCKFILE_V3)
        assert "lodash" in pkgs
        assert pkgs["lodash"].version == "4.17.21"
        assert "chalk" in pkgs
        assert pkgs["chalk"].version == "5.0.0"

    def test_invalid_json_raises_parse_error(self):
        with pytest.raises(LockfileParseError, match="Failed to parse lockfile JSON"):
            parse_lockfile_content("{invalid-json")


# ---------------------------------------------------------------------------
# Test Unsupported Lockfiles (Yarn / pnpm)
# ---------------------------------------------------------------------------


class TestUnsupportedLockfiles:
    def test_yarn_lock_rejected(self):
        with pytest.raises(UnsupportedLockfileError, match="Yarn lockfile"):
            check_supported_lockfile_path("path/to/yarn.lock")

    def test_pnpm_lock_yaml_rejected(self):
        with pytest.raises(UnsupportedLockfileError, match="pnpm lockfile"):
            check_supported_lockfile_path("pnpm-lock.yaml")

    def test_pnpm_lock_yml_rejected(self):
        with pytest.raises(UnsupportedLockfileError, match="pnpm lockfile"):
            check_supported_lockfile_path("/some/repo/pnpm-lock.yml")

    def test_read_from_dir_detects_yarn_and_pnpm(self, tmp_path: Path):
        yarn_dir = tmp_path / "yarn_project"
        yarn_dir.mkdir()
        (yarn_dir / "yarn.lock").write_text("yarn lock content", encoding="utf-8")

        with pytest.raises(UnsupportedLockfileError, match="Yarn lockfile"):
            read_lockfile_from_path(yarn_dir)

        pnpm_dir = tmp_path / "pnpm_project"
        pnpm_dir.mkdir()
        (pnpm_dir / "pnpm-lock.yaml").write_text("pnpm lock content", encoding="utf-8")

        with pytest.raises(UnsupportedLockfileError, match="pnpm lockfile"):
            read_lockfile_from_path(pnpm_dir)


# ---------------------------------------------------------------------------
# Test Lockfile Diffing
# ---------------------------------------------------------------------------


class TestLockfileDiffing:
    def test_detect_added_upgraded_downgraded_removed(self):
        base_pkgs = {
            "lodash": LockfilePackage("lodash", "4.17.20"),
            "chalk": LockfilePackage("chalk", "5.0.0"),
            "old-pkg": LockfilePackage("old-pkg", "1.0.0"),
            "same-pkg": LockfilePackage("same-pkg", "2.0.0"),
        }
        head_pkgs = {
            "lodash": LockfilePackage("lodash", "4.17.21"),  # upgraded
            "chalk": LockfilePackage("chalk", "4.1.0"),   # downgraded
            "new-pkg": LockfilePackage("new-pkg", "1.0.0"),  # added
            "same-pkg": LockfilePackage("same-pkg", "2.0.0"),  # unchanged
        }

        changes = diff_lockfiles(base_pkgs, head_pkgs)
        by_name = {c.name: c for c in changes}

        assert "same-pkg" not in by_name  # unchanged is not in changes

        assert by_name["lodash"].change_type == "upgraded"
        assert by_name["lodash"].old_version == "4.17.20"
        assert by_name["lodash"].new_version == "4.17.21"

        assert by_name["chalk"].change_type == "downgraded"
        assert by_name["chalk"].old_version == "5.0.0"
        assert by_name["chalk"].new_version == "4.1.0"

        assert by_name["new-pkg"].change_type == "added"
        assert by_name["new-pkg"].old_version is None
        assert by_name["new-pkg"].new_version == "1.0.0"

        assert by_name["old-pkg"].change_type == "removed"
        assert by_name["old-pkg"].old_version == "1.0.0"
        assert by_name["old-pkg"].new_version is None

    def test_max_packages_budget_capping(self):
        base = {}
        head = {f"pkg-{i}": LockfilePackage(f"pkg-{i}", "1.0.0") for i in range(250)}

        with pytest.raises(LockfileBudgetExceededError, match="exceed max-packages limit"):
            diff_lockfiles(base, head, max_packages=200)

        # Under limit passes
        changes = diff_lockfiles(base, head, max_packages=300)
        assert len(changes) == 250


# ---------------------------------------------------------------------------
# Test Lockfile Diff Scanning (End-to-End Mocked)
# ---------------------------------------------------------------------------


class TestLockfileDiffScanning:
    def test_scan_diff_clean_upgrade_allows(self, monkeypatch, tmp_path: Path):
        base_json = json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/lodash": {
                    "version": "4.17.20",
                    "integrity": "sha512-olddummy",
                },
            },
        })
        head_json = json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "integrity": "sha512-fKT/8IBcj35qo6Q9skSbU/BH890j6k2W9aPInUQdecI7OPhTkUd2Xv/WFqggO0v7fY1Rz9ha8qrRihLqaMnRgw==",  # noqa: E501  # noqa: E501
                },
            },
        })

        mock_client = MagicMock()
        # Mock tarball downloads returning ReleaseContents directly via extraction
        old_tar = tmp_path / "old.tgz"
        new_tar = tmp_path / "new.tgz"
        old_tar.write_bytes(b"dummy-old")
        new_tar.write_bytes(b"dummy-new")
        mock_client.download_tarball.side_effect = lambda name, version, *a, **kw: old_tar if version == "4.17.20" else new_tar  # noqa: E501

        # Mock extract_release_in_memory returning clean releases
        def mock_extract(tar_path, config=None):
            if tar_path == old_tar:
                return ReleaseContents(files={
                    "package.json": b'{"name": "lodash", "version": "4.17.20"}',
                    "index.js": b"module.exports = {};",
                })
            return ReleaseContents(files={
                "package.json": b'{"name": "lodash", "version": "4.17.21"}',
                "index.js": b"module.exports = { a: 1 };",
            })

        monkeypatch.setattr(
            "release_sentinel.lockfile.extract_release_in_memory", mock_extract
        )

        report = scan_lockfile_diff(
            base_content=base_json,
            head_content=head_json,
            registry_client=mock_client,
        )

        assert report.total_packages_scanned == 1
        assert report.decision == Decision.ALLOW
        assert len(report.package_results) == 1
        assert report.package_results[0]["package"] == "lodash"
        assert report.package_results[0]["decision"] == "ALLOW"

    def test_budget_exceeded_fails_closed_to_warn(self):
        base_json = json.dumps({"lockfileVersion": 3, "packages": {}})
        head_json = json.dumps({
            "lockfileVersion": 3,
            "packages": {f"node_modules/pkg-{i}": {"version": "1.0.0"} for i in range(250)},
        })

        mock_client = MagicMock()
        mock_client.download_tarball.return_value = Path("dummy.tgz")
        report = scan_lockfile_diff(
            base_content=base_json,
            head_content=head_json,
            max_packages=200,
            registry_client=mock_client,
        )

        assert report.decision == Decision.WARN
        assert report.has_budget_exceeded is True
        assert any("max-packages limit" in lim for lim in report.limitations)

    def test_integrity_mismatch_fails_closed_to_block(self, monkeypatch, tmp_path: Path):
        base_json = json.dumps({"lockfileVersion": 3, "packages": {}})
        head_json = json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/bad-pkg": {
                    "version": "1.0.0",
                    "integrity": "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",  # noqa: E501  # noqa: E501
                },
            },
        })

        mock_client = MagicMock()
        tar = tmp_path / "bad.tgz"
        tar.write_bytes(b"content-mismatch")
        mock_client.download_tarball.return_value = tar

        report = scan_lockfile_diff(
            base_content=base_json,
            head_content=head_json,
            registry_client=mock_client,
        )

        assert report.decision == Decision.BLOCK
        assert len(report.package_results) == 1
        pkg_res = report.package_results[0]
        assert pkg_res["package"] == "bad-pkg"
        assert pkg_res["decision"] == "BLOCK"
        assert "integrity_mismatch" in pkg_res["evidence"]

    def test_added_package_diffs_against_earlier_version(self, monkeypatch, tmp_path: Path):
        base_json = json.dumps({"lockfileVersion": 3, "packages": {}})
        head_json = json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/added-pkg": {
                    "version": "2.0.0",
                    "integrity": "sha512-ILBGG5cRPZBU3O9DyuuRYA+PRPmNdXhOS29lKOCbotgLBcbcxVmUf6thnYxej1vfzsIZLPOwbuY78JwIc89vpg==",  # noqa: E501  # noqa: E501
                },
            },
        })

        mock_client = MagicMock()
        # Mock metadata showing an established package satisfying maturity rule (Stage 7a Part 0b)
        mock_client.get_metadata.return_value = {
            "versions": {
                "1.0.0": {},
                "1.0.1": {},
                "1.0.2": {},
                "1.0.3": {},
                "2.0.0": {},
            },
            "time": {
                "created": "2020-01-01T00:00:00.000Z",
                "1.0.0": "2020-01-01T00:00:00.000Z",
                "1.0.1": "2020-06-01T00:00:00.000Z",
                "1.0.2": "2021-01-01T00:00:00.000Z",
                "1.0.3": "2021-06-01T00:00:00.000Z",
                "2.0.0": "2022-01-01T00:00:00.000Z",
            },
        }
        old_tar = tmp_path / "1.0.3.tgz"
        new_tar = tmp_path / "2.0.0.tgz"
        old_tar.write_bytes(b"dummy-1")
        new_tar.write_bytes(b"dummy-2")
        mock_client.download_tarball.side_effect = lambda name, version, *a, **kw: old_tar if version == "1.0.3" else new_tar  # noqa: E501

        def mock_extract(tar_path, config=None):
            if tar_path == old_tar:
                return ReleaseContents(files={
                    "package.json": b'{"name": "added-pkg", "version": "1.0.3"}',
                    "index.js": b"module.exports = 1;",
                })
            return ReleaseContents(files={
                "package.json": b'{"name": "added-pkg", "version": "2.0.0"}',
                "index.js": b"module.exports = 2;",
            })

        monkeypatch.setattr("release_sentinel.lockfile.extract_release_in_memory", mock_extract)

        report = scan_lockfile_diff(
            base_content=base_json,
            head_content=head_json,
            registry_client=mock_client,
        )

        assert report.decision == Decision.ALLOW
        assert len(report.package_results) == 1
        pkg_res = report.package_results[0]
        assert pkg_res["old_version"] == "1.0.3"  # Resolved earlier version
        assert pkg_res["new_version"] == "2.0.0"
        assert pkg_res["decision"] == "ALLOW"



class TestLockfileTamperingChecks:
    """Document current behavior for lockfile tampering scenarios (Stage 7g Step 4)."""

    def test_tamper_same_version_different_integrity_currently_allow(self):
        """Case (a): Same name and version has different integrity than base.

        Current behavior: diff_lockfiles keys purely by (name, version), so identical
        Decision is ALLOW with 0 packages scanned.
        """
        base_v3 = {
            "name": "demo-app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "demo-app", "version": "1.0.0", "dependencies": {"lodash": "4.17.20"}},
                "node_modules/lodash": {
                    "version": "4.17.20",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
                    "integrity": "sha512-PlhdFcillOINfeV7Ni6GEITXcmSEVDzsjWnMQCRGqm5aM2+QQHPOOs89eV10/0aaaqVWTY240689XYdlau9AXgk==",  # noqa: E501
                },
            },
        }
        head_v3 = {
            "name": "demo-app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "demo-app", "version": "1.0.0", "dependencies": {"lodash": "4.17.20"}},
                "node_modules/lodash": {
                    "version": "4.17.20",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
                    "integrity": "sha512-TAMPERED_DIFFERENT_INTEGRITY==",
                },
            },
        }
        report = scan_lockfile_diff(json.dumps(base_v3), json.dumps(head_v3))
        assert report.decision == Decision.ALLOW
        assert report.total_packages_scanned == 0
        assert len(report.package_results) == 0

    def test_tamper_same_version_different_resolved_url_currently_allow(self):
        """Case (b): Same name and version has different resolved URL on npmjs.org.

        Current behavior: diff_lockfiles keys purely by (name, version), so identical
        Decision is ALLOW with 0 packages scanned.
        """
        base_v3 = {
            "name": "demo-app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "demo-app", "version": "1.0.0", "dependencies": {"lodash": "4.17.20"}},
                "node_modules/lodash": {
                    "version": "4.17.20",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
                    "integrity": "sha512-PlhdFcillOINfeV7Ni6GEITXcmSEVDzsjWnMQCRGqm5aM2+QQHPOOs89eV10/0aaaqVWTY240689XYdlau9AXgk==",  # noqa: E501
                },
            },
        }
        head_v3 = {
            "name": "demo-app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "demo-app", "version": "1.0.0", "dependencies": {"lodash": "4.17.20"}},
                "node_modules/lodash": {
                    "version": "4.17.20",
                    "resolved": "https://registry.npmjs.org/lodash/-/tampered-lodash-4.17.20.tgz",
                    "integrity": "sha512-PlhdFcillOINfeV7Ni6GEITXcmSEVDzsjWnMQCRGqm5aM2+QQHPOOs89eV10/0aaaqVWTY240689XYdlau9AXgk==",  # noqa: E501
                },
            },
        }
        report = scan_lockfile_diff(json.dumps(base_v3), json.dumps(head_v3))
        assert report.decision == Decision.ALLOW
        assert report.total_packages_scanned == 0
        assert len(report.package_results) == 0

    def test_tamper_bumped_version_resolved_points_to_old_tarball_blocks(self):
        """Case (c): Bumped version whose resolved URL points to the old version's tarball.

        Detected by lockfile_resolved_mismatch rule: immediately produces Decision.BLOCK
        and evidence ['lockfile_resolved_mismatch'].
        """
        base_v3 = {
            "name": "demo-app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "demo-app", "version": "1.0.0", "dependencies": {"lodash": "4.17.20"}},
                "node_modules/lodash": {
                    "version": "4.17.20",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
                    "integrity": "sha512-PlhdFcillOINfeV7Ni6GEITXcmSEVDzsjWnMQCRGqm5aM2+QQHPOOs89eV10/0aaaqVWTY240689XYdlau9AXgk==",  # noqa: E501
                },
            },
        }
        head_v3 = {
            "name": "demo-app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "demo-app", "version": "1.0.0", "dependencies": {"lodash": "4.17.21"}},
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
                    "integrity": "sha512-PlhdFcillOINfeV7Ni6GEITXcmSEVDzsjWnMQCRGqm5aM2+QQHPOOs89eV10/0aaaqVWTY240689XYdlau9AXgk==",  # noqa: E501
                },
            },
        }
        report = scan_lockfile_diff(json.dumps(base_v3), json.dumps(head_v3))
        assert report.decision == Decision.BLOCK
        assert report.total_packages_scanned == 1
        assert len(report.package_results) == 1
        pkg_res = report.package_results[0]
        assert pkg_res["package"] == "lodash"
        assert pkg_res["old_version"] == "4.17.20"
        assert pkg_res["new_version"] == "4.17.21"
        assert pkg_res["decision"] == "BLOCK"
        assert pkg_res["evidence"] == ["lockfile_resolved_mismatch"]
        assert pkg_res["status"] == "lockfile_resolved_mismatch"
