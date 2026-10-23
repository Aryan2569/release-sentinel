"""Tests for the release differ (differ.py).

All tests use synthetic tarballs built by conftest.py fixtures.
No network calls, no real packages.
"""

from __future__ import annotations

from pathlib import Path

from release_sentinel.differ import compare_releases
from release_sentinel.extractor import ReleaseContents, extract_release
from release_sentinel.models import Severity


def extract_pair(tmp_path: Path, old_tgz: Path, new_tgz: Path):
    """Helper: extract two tarballs and return their ExtractionResult objects."""
    old = extract_release(old_tgz, tmp_path / "old")
    new = extract_release(new_tgz, tmp_path / "new")
    return old, new


class TestInstallScripts:
    def test_postinstall_added_is_high(
        self,
        tmp_path: Path,
        old_tarball: Path,
        new_tarball_with_postinstall: Path,
    ):
        old, new = extract_pair(tmp_path, old_tarball, new_tarball_with_postinstall)
        evidence = compare_releases(old, new)
        ids = [e.id for e in evidence]
        assert "install_script_added" in ids
        ev = next(e for e in evidence if e.id == "install_script_added")
        assert ev.severity == Severity.HIGH

    def test_install_script_changed_is_medium(
        self,
        tmp_path: Path,
        old_tarball_with_postinstall: Path,
        new_tarball_changed_install_script: Path,
    ):
        old, new = extract_pair(
            tmp_path, old_tarball_with_postinstall, new_tarball_changed_install_script
        )
        evidence = compare_releases(old, new)
        ids = [e.id for e in evidence]
        assert "install_script_changed" in ids
        ev = next(e for e in evidence if e.id == "install_script_changed")
        assert ev.severity == Severity.MEDIUM

    def test_no_script_change_no_script_evidence(
        self,
        tmp_path: Path,
        old_tarball: Path,
        new_tarball_clean: Path,
    ):
        old, new = extract_pair(tmp_path, old_tarball, new_tarball_clean)
        evidence = compare_releases(old, new)
        script_ids = {
            "install_script_added",
            "install_script_changed",
        }
        found = {e.id for e in evidence} & script_ids
        assert not found, f"Unexpected script evidence: {found}"


class TestDependencies:
    def test_new_dep_detected(
        self,
        tmp_path: Path,
        old_tarball: Path,
        new_tarball_new_dep: Path,
    ):
        old, new = extract_pair(tmp_path, old_tarball, new_tarball_new_dep)
        evidence = compare_releases(old, new)
        ids = [e.id for e in evidence]
        assert "dependency_added" in ids
        ev = next(e for e in evidence if e.id == "dependency_added")
        assert ev.severity == Severity.LOW
        assert "axios" in ev.explanation

    def test_dep_version_bump_detected(
        self,
        tmp_path: Path,
        old_tarball: Path,
        new_tarball_clean: Path,
    ):
        # new_tarball_clean bumps lodash from 4.17.20 → 4.17.21
        old, new = extract_pair(tmp_path, old_tarball, new_tarball_clean)
        evidence = compare_releases(old, new)
        ids = [e.id for e in evidence]
        assert "dependency_version_changed" in ids

    def test_dev_and_peer_dependencies_emitted_as_info(self):
        old_rel = ReleaseContents(files={"package.json": b'{"name": "p", "version": "1.0.0"}'})
        new_rel = ReleaseContents(
            files={
                "package.json": (
                    b'{"name": "p", "version": "1.0.1", '
                    b'"devDependencies": {"typescript": "^5.0.0"}, '
                    b'"peerDependencies": {"react": "^18.0.0"}, '
                    b'"optionalDependencies": {"fsevents": "^2.3.0"}}'
                )
            }
        )
        evidence = compare_releases(old_rel, new_rel)
        by_id = {e.id: e for e in evidence}
        assert "dev_dependency_added" in by_id
        assert by_id["dev_dependency_added"].severity == Severity.INFO
        assert "peer_dependency_added" in by_id
        assert by_id["peer_dependency_added"].severity == Severity.INFO
        assert "dependency_added" in by_id
        assert by_id["dependency_added"].severity == Severity.LOW
        assert "fsevents" in by_id["dependency_added"].explanation


class TestBinEntries:
    def test_new_bin_detected(
        self,
        tmp_path: Path,
        old_tarball: Path,
        new_tarball_new_bin: Path,
    ):
        old, new = extract_pair(tmp_path, old_tarball, new_tarball_new_bin)
        evidence = compare_releases(old, new)
        ids = [e.id for e in evidence]
        assert "bin_entry_added" in ids
        ev = next(e for e in evidence if e.id == "bin_entry_added")
        assert ev.severity == Severity.MEDIUM


class TestNewFiles:
    def test_new_file_summary_emitted(
        self,
        tmp_path: Path,
        old_tarball: Path,
        new_tarball_with_postinstall: Path,
    ):
        """Stage 2: new files emit new_files_summary (aggregated), not per-file new_file_added."""
        old, new = extract_pair(tmp_path, old_tarball, new_tarball_with_postinstall)
        evidence = compare_releases(old, new)
        ids = [e.id for e in evidence]
        # Should NOT have the old per-file ID
        assert "new_file_added" not in ids
        # Should have the aggregated summary OR a notable_new_file for setup.js
        assert "new_files_summary" in ids or "notable_new_file" in ids

    def test_no_new_file_evidence_when_unchanged(
        self,
        tmp_path: Path,
        old_tarball: Path,
        new_tarball_clean: Path,
    ):
        old, new = extract_pair(tmp_path, old_tarball, new_tarball_clean)
        evidence = compare_releases(old, new)
        # new_tarball_clean has same files as old_tarball
        file_ev_ids = {"new_file_added", "new_files_summary", "notable_new_file"}
        assert not any(e.id in file_ev_ids for e in evidence)

    def test_new_install_script_target_flagged_notable(
        self,
        tmp_path: Path,
        old_tarball: Path,
        new_tarball_with_postinstall: Path,
    ):
        old, new = extract_pair(tmp_path, old_tarball, new_tarball_with_postinstall)
        evidence = compare_releases(old, new)
        notable = [e for e in evidence if e.id == "notable_new_file" and e.file == "setup.js"]
        assert len(notable) == 1
        assert notable[0].severity.value == "HIGH"


class TestSizeJump:
    def test_large_size_jump_detected(self, tmp_path: Path):
        from tests.conftest import make_tarball

        # Old: 100 bytes, New: 300 bytes  → ratio 3× > threshold 2×
        old_tgz = make_tarball(
            tmp_path / "old.tgz",
            {"package.json": '{"name":"x","version":"1.0.0"}', "a.js": "x" * 80},
        )
        new_tgz = make_tarball(
            tmp_path / "new.tgz",
            {"package.json": '{"name":"x","version":"1.0.1"}', "a.js": "x" * 300},
        )
        old, new = extract_pair(tmp_path, old_tgz, new_tgz)
        evidence = compare_releases(old, new)
        assert any(e.id == "large_size_jump" for e in evidence)

    def test_small_size_change_no_flag(self, tmp_path: Path):
        from tests.conftest import make_tarball

        old_tgz = make_tarball(
            tmp_path / "old.tgz",
            {"package.json": '{"name":"x","version":"1.0.0"}', "a.js": "x" * 100},
        )
        new_tgz = make_tarball(
            tmp_path / "new.tgz",
            {"package.json": '{"name":"x","version":"1.0.1"}', "a.js": "x" * 130},
        )
        old, new = extract_pair(tmp_path, old_tgz, new_tgz)
        evidence = compare_releases(old, new)
        assert not any(e.id == "large_size_jump" for e in evidence)


class TestEvidenceSortOrder:
    def test_highest_severity_first(
        self,
        tmp_path: Path,
        old_tarball: Path,
        new_tarball_with_postinstall: Path,
    ):
        old, new = extract_pair(tmp_path, old_tarball, new_tarball_with_postinstall)
        evidence = compare_releases(old, new)
        if len(evidence) > 1:
            sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            orders = [sev_order[e.severity.value] for e in evidence]
            assert orders == sorted(orders), "Evidence is not sorted by severity"


class TestMissingPackageJson:
    def test_inspection_failed_when_no_package_json(self, tmp_path: Path):
        from tests.conftest import make_tarball

        old_tgz = make_tarball(tmp_path / "old.tgz", {"package.json": '{"name":"x"}'})
        new_tgz = make_tarball(tmp_path / "new.tgz", {"index.js": "// no package.json"})
        old, new = extract_pair(tmp_path, old_tgz, new_tgz)
        evidence = compare_releases(old, new)
        assert any(e.id == "inspection_failed" for e in evidence)


class TestRegistryVsRootInstallScripts:
    def test_prepare_and_prepublish_ignored_for_registry_package(self):
        old_rel = ReleaseContents(files={"package.json": b'{"name": "p", "version": "1.0.0"}'})
        new_rel = ReleaseContents(
            files={
                "package.json": (
                    b'{"name": "p", "version": "1.0.1", "scripts": {'
                    b'"prepare": "husky install", "prepublish": "npm run build"}}'
                )
            }
        )
        evidence = compare_releases(old_rel, new_rel, is_registry_package=True)
        assert not any(e.id == "install_script_added" for e in evidence)

    def test_prepare_and_prepublish_included_for_git_or_root_package(self):
        old_rel = ReleaseContents(files={"package.json": b'{"name": "p", "version": "1.0.0"}'})
        new_rel = ReleaseContents(
            files={
                "package.json": (
                    b'{"name": "p", "version": "1.0.1", "scripts": {'
                    b'"prepare": "husky install", "prepublish": "npm run build"}}'
                )
            }
        )
        evidence = compare_releases(old_rel, new_rel, is_registry_package=False)
        added_scripts = [e for e in evidence if e.id == "install_script_added"]
        assert len(added_scripts) == 2

