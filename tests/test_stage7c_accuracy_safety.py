"""Tests for Stage 7c Part 2: Accuracy & Safety Fixes.

Covers:
- Mode-dependent limitations text (lockfile mode vs single-package mode)
- Policy overlay additivity by default and replace_block_requires override with warning
- Package context isolation for block_requires corroboration
- Lockfile mode bypass of child dependency following
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from release_sentinel.lockfile import scan_lockfile_diff
from release_sentinel.models import Decision, Evidence, Severity
from release_sentinel.policy import decide, load_policy


class TestModeDependentLimitations:
    def test_single_package_mode_has_depth1_limitation(self):
        ev = [
            Evidence(
                id="install_script_present",
                severity=Severity.LOW,
                file="package.json",
                explanation="preinstall",
                legitimate_use_note="build",
            )
        ]
        _, lims = decide(ev)
        assert any(
            "Transitive (indirect) dependencies beyond depth-1" in lim for lim in lims
        )

    def test_lockfile_mode_has_scanned_all_entries_limitation(self, tmp_path: Path):
        base_f = tmp_path / "base.json"
        head_f = tmp_path / "head.json"
        base_f.write_text(json.dumps({"lockfileVersion": 3, "packages": {}}), encoding="utf-8")
        head_f.write_text(json.dumps({"lockfileVersion": 3, "packages": {}}), encoding="utf-8")

        report = scan_lockfile_diff(
            base_content=base_f.read_text(encoding="utf-8"),
            head_content=head_f.read_text(encoding="utf-8"),
            base_source="base.json",
            head_source="head.json",
        )
        assert not any("Transitive (indirect) dependencies" in lim for lim in report.limitations)
        assert any(
            "Every changed lockfile entry (including transitive dependencies) is scanned." in lim
            for lim in report.limitations
        )


class TestPolicyOverlayAdditivity:
    def test_additive_by_default(self, tmp_path: Path):
        policy_toml = tmp_path / "custom.toml"
        policy_toml.write_text(
            """
            [decision]
            block_requires = [
                { signals = ["hardcoded_ip", "process_exec"], description = "custom ip exec" }
            ]
            """,
            encoding="utf-8",
        )
        pol = load_policy(policy_path=policy_toml, profile="default")
        assert pol.replace_block_requires is False
        # Profile default has 16 rules; custom adds 1 -> 17 rules
        assert len(pol.block_requires) > 1
        descriptions = [r.description for r in pol.block_requires]
        assert "custom ip exec" in descriptions

        # Verify no override warning
        _, lims = decide([], policy=pol)
        assert not any("Warning: Built-in multi-signal" in lim for lim in lims)

    def test_replace_block_requires_replaces_and_warns(self, tmp_path: Path):
        policy_toml = tmp_path / "custom_replace.toml"
        policy_toml.write_text(
            """
            [decision]
            replace_block_requires = true
            block_requires = [
                { signals = ["hardcoded_ip", "process_exec"], description = "only ip exec" }
            ]
            """,
            encoding="utf-8",
        )
        pol = load_policy(policy_path=policy_toml, profile="default")
        assert pol.replace_block_requires is True
        # Built-in rules should be completely replaced by the 1 custom rule
        assert len(pol.block_requires) == 1
        assert pol.block_requires[0].description == "only ip exec"

        # Verify limitation warning is emitted
        ev = [
            Evidence(
                id="hardcoded_ip",
                severity=Severity.HIGH,
                file="index.js",
                explanation="ip",
                legitimate_use_note="none",
            )
        ]
        _, lims = decide(ev, policy=pol)
        warn_text = (
            "Warning: Built-in multi-signal block_requires rules are overridden by custom policy."
        )
        assert any(warn_text in lim for lim in lims)


class TestPackageContextCorroboration:
    def test_signals_split_across_root_and_dependency_do_not_cross_corroborate(self):
        # install_script_added + network_access is a block_requires pair in default profile
        root_ev = Evidence(
            id="install_script_added",
            severity=Severity.HIGH,
            file="package.json",
            explanation="Added postinstall script",
            legitimate_use_note="build",
        )
        dep_ev = Evidence(
            id="network_access",
            severity=Severity.HIGH,
            file="node_modules/helper/index.js",
            explanation="[dep: helper@1.0.0] Found http.get",
            legitimate_use_note="telemetry",
        )
        # Passed together as whole-run evidence
        dec, _ = decide([root_ev, dep_ev])
        # Neither package context has BOTH signals -> cannot cross-corroborate to BLOCK
        assert dec == Decision.WARN

    def test_signals_within_same_package_context_corroborate_to_block(self):
        root_ev1 = Evidence(
            id="install_script_added",
            severity=Severity.HIGH,
            file="package.json",
            explanation="Added postinstall script",
            legitimate_use_note="build",
        )
        root_ev2 = Evidence(
            id="network_access",
            severity=Severity.HIGH,
            file="build.js",
            explanation="Found http.get",
            legitimate_use_note="telemetry",
        )
        dec, _ = decide([root_ev1, root_ev2])
        assert dec == Decision.BLOCK

    def test_signals_within_same_dependency_context_corroborate_to_block(self):
        dep_ev1 = Evidence(
            id="install_script_added",
            severity=Severity.HIGH,
            file="node_modules/helper/package.json",
            explanation="[dep: helper@1.0.0] Added postinstall script",
            legitimate_use_note="build",
        )
        dep_ev2 = Evidence(
            id="network_access",
            severity=Severity.HIGH,
            file="node_modules/helper/index.js",
            explanation="[dep: helper@1.0.0] Found http.get",
            legitimate_use_note="telemetry",
        )
        dec, _ = decide([dep_ev1, dep_ev2])
        assert dec == Decision.BLOCK


class TestLockfileModeDependencyBypass:
    @patch("release_sentinel.lockfile.analyze_release")
    def test_scan_lockfile_diff_passes_follow_dependencies_false(
        self, mock_analyze: MagicMock, tmp_path: Path
    ):
        base_f = tmp_path / "base.json"
        head_f = tmp_path / "head.json"
        base_f.write_text(json.dumps({"lockfileVersion": 3, "packages": {}}), encoding="utf-8")
        head_f.write_text(
            json.dumps({
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/foo": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz",
                        "integrity": "sha512-test",
                    }
                },
            }),
            encoding="utf-8",
        )
        mock_analyze.return_value = []
        client = MagicMock()
        client.cache_dir = tmp_path
        client.download_tarball.return_value = tmp_path / "dummy.tgz"

        with patch("release_sentinel.lockfile.extract_release_in_memory"):
            scan_lockfile_diff(
                base_content=base_f.read_text(encoding="utf-8"),
                head_content=head_f.read_text(encoding="utf-8"),
                base_source="base.json",
                head_source="head.json",
                registry_client=client,
            )

        assert mock_analyze.called
        assert mock_analyze.call_args.kwargs.get("follow_dependencies") is False
