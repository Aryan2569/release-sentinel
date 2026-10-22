"""Tests for the TOML policy engine (policy.py).

Covers: loading the default policy, single-signal cap, corroboration rules,
install_script_changed override, custom TOML merging.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from release_sentinel.models import Decision, Evidence, Severity
from release_sentinel.policy import (
    BlockRequires,
    Policy,
    decide,
    load_policy,
)


def _ev(ev_id: str, severity: Severity) -> Evidence:
    return Evidence(
        id=ev_id,
        severity=severity,
        file=None,
        explanation="test",
        legitimate_use_note="test",
    )


# ---------------------------------------------------------------------------
# Default policy loading
# ---------------------------------------------------------------------------


class TestLoadPolicy:
    def test_default_policy_loads(self):
        policy = load_policy()
        assert isinstance(policy, Policy)
        assert len(policy.block_requires) > 0

    def test_default_policy_has_install_script_override(self):
        policy = load_policy()
        assert "install_script_changed" in policy.severity_overrides

    def test_bundled_and_data_policy_are_identical(self):
        bundled = Path("src/release_sentinel/data/policy_default.toml")
        repo_data = Path("data/policy_default.toml")
        if repo_data.exists():
            assert bundled.read_bytes() == repo_data.read_bytes(), (
                "data/policy_default.toml and bundled "
                "src/release_sentinel/data/policy_default.toml must be byte-identical."
            )

    def test_custom_toml_file(self, tmp_path: Path):
        toml_content = """
[decision]
single_signal_cap = "WARN"

[[decision.block_requires]]
signals = ["sig_x", "sig_y"]
description = "test pair"

[severity_overrides]
my_signal = "HIGH"
"""
        p = tmp_path / "my_policy.toml"
        p.write_text(toml_content, encoding="utf-8")
        policy = load_policy(p)
        assert any(
            set(br.signals) == {"sig_x", "sig_y"}
            for br in policy.block_requires
        )
        assert policy.severity_overrides.get("my_signal") == Severity.HIGH

    def test_invalid_toml_raises(self, tmp_path: Path):
        bad = tmp_path / "bad.toml"
        bad.write_text("[[not valid toml }", encoding="utf-8")
        with pytest.raises(ValueError, match="Cannot load policy"):
            load_policy(bad)


# ---------------------------------------------------------------------------
# Single-signal cap
# ---------------------------------------------------------------------------


class TestSingleSignalCap:
    def test_single_high_signal_caps_at_warn(self):
        policy = Policy()
        evidence = [_ev("install_script_added", Severity.HIGH)]
        decision, _ = decide(evidence, policy=policy)
        assert decision == Decision.WARN

    def test_single_critical_caps_at_warn(self):
        policy = Policy()
        evidence = [_ev("anything", Severity.CRITICAL)]
        decision, _ = decide(evidence, policy=policy)
        assert decision == Decision.WARN

    def test_single_low_is_allow(self):
        policy = Policy()
        evidence = [_ev("dep_added", Severity.LOW)]
        decision, _ = decide(evidence, policy=policy)
        assert decision == Decision.ALLOW

    def test_empty_is_allow(self):
        decision, _ = decide([])
        assert decision == Decision.ALLOW


# ---------------------------------------------------------------------------
# Corroboration rules
# ---------------------------------------------------------------------------


class TestCorroboration:
    def test_pair_match_with_high_gives_block(self):
        policy = Policy(
            block_requires=[BlockRequires(signals=["install_script_added", "network_access"])]
        )
        evidence = [
            _ev("install_script_added", Severity.HIGH),
            _ev("network_access", Severity.MEDIUM),
        ]
        decision, _ = decide(evidence, policy=policy)
        assert decision == Decision.BLOCK

    def test_pair_match_but_all_low_gives_warn(self):
        """Pair matches but no HIGH/CRITICAL → WARN (not enough severity)."""
        policy = Policy(
            block_requires=[BlockRequires(signals=["sig_a", "sig_b"])]
        )
        evidence = [
            _ev("sig_a", Severity.LOW),
            _ev("sig_b", Severity.LOW),
        ]
        decision, _ = decide(evidence, policy=policy)
        assert decision == Decision.WARN

    def test_no_pair_match_gives_warn_despite_high(self):
        """HIGH evidence present but no corroboration pair matches → WARN."""
        policy = Policy(
            block_requires=[BlockRequires(signals=["a", "b"])]
        )
        evidence = [
            _ev("a", Severity.HIGH),
            _ev("c", Severity.MEDIUM),  # 'c' is not in the pair
        ]
        decision, _ = decide(evidence, policy=policy)
        assert decision == Decision.WARN

    def test_multiple_pairs_any_match_blocks(self):
        policy = Policy(
            block_requires=[
                BlockRequires(signals=["x", "y"]),
                BlockRequires(signals=["install_script_added", "dynamic_code"]),
            ]
        )
        evidence = [
            _ev("install_script_added", Severity.HIGH),
            _ev("dynamic_code", Severity.HIGH),
        ]
        decision, _ = decide(evidence, policy=policy)
        assert decision == Decision.BLOCK

    def test_default_policy_install_plus_network_blocks(self):
        """Regression test against the default policy file."""
        policy = load_policy()
        evidence = [
            _ev("install_script_added", Severity.HIGH),
            _ev("network_access", Severity.MEDIUM),
        ]
        decision, _ = decide(evidence, policy=policy)
        assert decision == Decision.BLOCK

    def test_default_policy_install_plus_dynamic_code_blocks(self):
        policy = load_policy()
        evidence = [
            _ev("install_script_added", Severity.HIGH),
            _ev("dynamic_code", Severity.HIGH),
        ]
        decision, _ = decide(evidence, policy=policy)
        assert decision == Decision.BLOCK


# ---------------------------------------------------------------------------
# Severity overrides
# ---------------------------------------------------------------------------


class TestSeverityOverrides:
    def test_override_downgrades_severity(self):
        """Policy override of install_script_changed → MEDIUM; alone → still WARN."""
        policy = load_policy()
        evidence = [_ev("install_script_changed", Severity.HIGH)]
        decision, _ = decide(evidence, policy=policy)
        # Override kicks severity down to MEDIUM; single signal → WARN
        assert decision == Decision.WARN

    def test_install_script_changed_alone_never_blocks(self):
        """install_script_changed is in default overrides as MEDIUM; cannot corroborate alone."""
        policy = load_policy()
        evidence = [_ev("install_script_changed", Severity.MEDIUM)]
        decision, _ = decide(evidence, policy=policy)
        assert decision != Decision.BLOCK


# ---------------------------------------------------------------------------
# Limitations
# ---------------------------------------------------------------------------


class TestLimitations:
    def test_limitations_always_present(self):
        for ev_list in [[], [_ev("x", Severity.LOW)], [_ev("x", Severity.HIGH)]]:
            _, lims = decide(ev_list)
            assert len(lims) > 0

    def test_limitations_mention_static(self):
        _, lims = decide([])
        assert any("static" in lim.lower() or "regex" in lim.lower() for lim in lims)
