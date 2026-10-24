"""Tests for Stage 7a Part 0 correctness fixes.

Covers:
- Part 0a: Lockfile duplicates (nested duplicate with malicious version; 1.10.0 vs 1.9.0).
- Part 0b: Baseline selection and maturity rule (backport diffed vs same major; decoy full-scanned).
- Part 0c: Max-packages cap risk prioritization (added first, hooks first; 50 skipped reported).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import MagicMock

from release_sentinel.dependency_resolver import select_baseline_for_added_package
from release_sentinel.extractor import ReleaseContents
from release_sentinel.lockfile import (
    DEFAULT_MAX_PACKAGES,
    LockfilePackage,
    PackageChange,
    _sort_changes_by_risk,
    diff_lockfiles,
    parse_lockfile_content,
    scan_lockfile_diff,
)
from release_sentinel.models import Decision

# ---------------------------------------------------------------------------
# Part 0a: Lockfile Duplicates & Semver Classification
# ---------------------------------------------------------------------------


class TestLockfileDuplicates:
    def test_nested_duplicate_where_malicious_version_is_nested(self):
        """When top-level is 1.0.0, but a nested dependency requires 1.0.1-malicious,

        the nested version must not be ignored and must be detected for scanning.
        """
        # Base lockfile: only has benign foo@1.0.0
        base_v3 = json.dumps({
            "name": "root-app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "root-app", "version": "1.0.0"},
                "node_modules/foo": {"version": "1.0.0"},
            },
        })

        # Head lockfile: retains top-level foo@1.0.0, but nested dependency adds foo@1.0.1-malicious
        head_v3 = json.dumps({
            "name": "root-app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "root-app", "version": "1.0.0"},
                "node_modules/foo": {"version": "1.0.0"},
                "node_modules/bar/node_modules/foo": {
                    "version": "1.0.1-malicious",
                    "resolved": "https://registry.npmjs.org/foo/-/foo-1.0.1-malicious.tgz",
                },
            },
        })

        old_pkgs = parse_lockfile_content(base_v3)
        new_pkgs = parse_lockfile_content(head_v3)

        # Both versions must be present in parsed head packages
        assert ("foo", "1.0.0") in new_pkgs
        assert ("foo", "1.0.1-malicious") in new_pkgs

        changes = diff_lockfiles(old_pkgs, new_pkgs)
        scannable = [c for c in changes if c.change_type != "removed"]

        # The nested malicious version MUST be detected as an added package to scan
        foo_changes = [c for c in scannable if c.name == "foo"]
        assert len(foo_changes) == 1
        assert foo_changes[0].new_version == "1.0.1-malicious"
        assert foo_changes[0].change_type == "added"

    def test_v1_nested_duplicate_detection(self):
        """npm v1 dependencies tree holding nested different version of a package."""
        base_v1 = json.dumps({
            "name": "root-app",
            "version": "1.0.0",
            "lockfileVersion": 1,
            "dependencies": {
                "foo": {"version": "1.0.0"},
            },
        })
        head_v1 = json.dumps({
            "name": "root-app",
            "version": "1.0.0",
            "lockfileVersion": 1,
            "dependencies": {
                "foo": {"version": "1.0.0"},
                "bar": {
                    "version": "2.0.0",
                    "dependencies": {
                        "foo": {"version": "1.0.1-malicious"},
                    },
                },
            },
        })

        old_pkgs = parse_lockfile_content(base_v1)
        new_pkgs = parse_lockfile_content(head_v1)

        assert ("foo", "1.0.0") in new_pkgs
        assert ("foo", "1.0.1-malicious") in new_pkgs

        changes = diff_lockfiles(old_pkgs, new_pkgs)
        added_foo = [c for c in changes if c.name == "foo" and c.new_version == "1.0.1-malicious"]
        assert len(added_foo) == 1
        assert added_foo[0].change_type == "added"

    def test_semver_comparison_1_10_0_vs_1_9_0(self):
        """Nodesemver classification: 1.10.0 > 1.9.0 must be classified as 'upgraded',

        not 'downgraded' (string comparison would treat '1.10.0' < '1.9.0').
        """
        old_pkgs = {("lib", "1.9.0"): LockfilePackage("lib", "1.9.0")}
        new_pkgs = {("lib", "1.10.0"): LockfilePackage("lib", "1.10.0")}

        changes = diff_lockfiles(old_pkgs, new_pkgs)
        assert len(changes) == 1
        assert changes[0].change_type == "upgraded"
        assert changes[0].old_version == "1.9.0"
        assert changes[0].new_version == "1.10.0"

        # Reverse transition: 1.10.0 -> 1.9.0 is a downgrade
        reverse_changes = diff_lockfiles(new_pkgs, old_pkgs)
        assert len(reverse_changes) == 1
        assert reverse_changes[0].change_type == "downgraded"
        assert reverse_changes[0].old_version == "1.10.0"
        assert reverse_changes[0].new_version == "1.9.0"


# ---------------------------------------------------------------------------
# Part 0b: Baseline Selection & Maturity Rule
# ---------------------------------------------------------------------------


class TestBaselineSelectionAndMaturity:
    def test_backport_release_diffed_against_same_major(self):
        """A backport release (e.g. 2.1.0 published in 2024 after 3.0.0 was published in 2022)

        must be diffed against previous 2.x (e.g. 2.0.5), not against 3.0.0.
        """
        meta = {
            "versions": {
                "1.0.0": {},
                "2.0.0": {},
                "2.0.5": {},
                "3.0.0": {},
                "3.1.0": {},
                "2.1.0": {},  # Target backport release
            },
            "time": {
                "created": "2020-01-01T00:00:00.000Z",
                "1.0.0": "2020-01-01T00:00:00.000Z",
                "2.0.0": "2021-01-01T00:00:00.000Z",
                "2.0.5": "2021-06-01T00:00:00.000Z",
                "3.0.0": "2022-01-01T00:00:00.000Z",
                "3.1.0": "2023-01-01T00:00:00.000Z",
                "2.1.0": "2024-01-01T00:00:00.000Z",  # Backport published after 3.1.0
            },
        }
        as_of = datetime(2025, 1, 1, tzinfo=UTC)

        baseline = select_baseline_for_added_package(
            name="example-pkg",
            new_version="2.1.0",
            metadata=meta,
            as_of=as_of,
        )
        # Must pick 2.0.5 (highest lower semver in major 2), NOT 3.1.0
        assert baseline == "2.0.5"

    def test_decoy_scenario_fails_maturity_rule_and_full_scans(self):
        """Decoy scenario: clean 4.2.0, then malicious 4.2.1 and 4.2.2 published within days.

        Total versions < 5 and package age < 90 days.
        Maturity rule fails -> returns None (full-scan mode).
        """
        meta = {
            "versions": {
                "4.2.0": {},
                "4.2.1": {},
                "4.2.2": {},
            },
            "time": {
                "created": "2026-03-01T00:00:00.000Z",
                "4.2.0": "2026-03-01T00:00:00.000Z",
                "4.2.1": "2026-03-03T00:00:00.000Z",
                "4.2.2": "2026-03-05T00:00:00.000Z",
            },
        }
        # Cut-off 10 days later (< 90 days old, only 3 versions)
        as_of = datetime(2026, 3, 11, tzinfo=UTC)

        baseline = select_baseline_for_added_package(
            name="decoy-pkg",
            new_version="4.2.2",
            metadata=meta,
            as_of=as_of,
        )
        # Must return None to trigger full-scan mode
        assert baseline is None


# ---------------------------------------------------------------------------
# Part 0c: Max-Packages Cap & Risk Prioritization
# ---------------------------------------------------------------------------


class TestMaxPackagesCap:
    def test_default_cap_is_300(self):
        assert DEFAULT_MAX_PACKAGES == 300

    def test_risk_prioritization_ordering(self):
        """Risk priority order:

        1. Added packages before upgraded
        2. Packages with preinstall/install/postinstall before ones without
        3. Newest-published packages before older ones
        """
        c1 = PackageChange("upgraded-no-hook", "1.0.0", "1.1.0", "upgraded")
        c2 = PackageChange(
            "upgraded-with-hook", "1.0.0", "1.1.0", "upgraded", has_install_script=True
        )
        c3 = PackageChange("added-no-hook", None, "1.0.0", "added")
        c4 = PackageChange("added-with-hook", None, "1.0.0", "added", has_install_script=True)

        changes = [c1, c2, c3, c4]
        sorted_changes = _sort_changes_by_risk(changes)

        # Expected order:
        # 1. added-with-hook (added=0, hook=0)
        # 2. added-no-hook (added=0, hook=1)
        # 3. upgraded-with-hook (added=1, hook=0)
        # 4. upgraded-no-hook (added=1, hook=1)
        assert [c.name for c in sorted_changes] == [
            "added-with-hook",
            "added-no-hook",
            "upgraded-with-hook",
            "upgraded-no-hook",
        ]

    def test_capped_run_reports_skipped_packages_and_warns(self, monkeypatch, tmp_path):
        """When lockfile changes exceed max_packages:

        - Scans top max_packages by risk priority
        - Skips remaining packages
        - Emits WARN with first 50 skipped packages named in limitations
        """
        # Create 350 package additions in head
        base_json = json.dumps({"lockfileVersion": 3, "packages": {}})
        head_packages = {}
        for i in range(350):
            # First 50 declare install script
            has_script = i < 50
            head_packages[f"node_modules/pkg-{i:03d}"] = {
                "version": "1.0.0",
                "hasInstallScript": has_script,
            }
        head_json = json.dumps({"lockfileVersion": 3, "packages": head_packages})

        dummy_tar = tmp_path / "dummy.tgz"
        dummy_tar.write_bytes(b"dummy")

        mock_client = MagicMock()
        mock_client.download_tarball.return_value = dummy_tar

        def mock_extract(tar_path, config=None):
            return ReleaseContents(files={"package.json": b'{"name": "pkg", "version": "1.0.0"}'})

        monkeypatch.setattr("release_sentinel.lockfile.extract_release_in_memory", mock_extract)

        report = scan_lockfile_diff(
            base_content=base_json,
            head_content=head_json,
            max_packages=300,
            registry_client=mock_client,
        )

        assert report.decision == Decision.WARN
        assert report.has_budget_exceeded is True
        assert report.total_packages_scanned == 300

        # Limitation must mention scanned 300, skipped 50, and list skipped package names
        lim_found = False
        for lim in report.limitations:
            if "Exceeded max-packages limit: scanned 300, skipped 50" in lim:
                lim_found = True
                assert "Skipped packages (first 50):" in lim
                assert "pkg-" in lim
        assert lim_found is True
