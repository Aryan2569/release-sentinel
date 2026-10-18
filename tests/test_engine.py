"""Tests for the decision engine (engine.py) — Stage 2 policy-aware.

The Stage 2 engine uses corroboration rules:
- A SINGLE signal type → capped at WARN regardless of severity
- BLOCK requires at least TWO corroborating signal types, both present,
  including at least one HIGH/CRITICAL, matching a pair in the default policy
"""

from __future__ import annotations

from pathlib import Path

from release_sentinel.engine import decide
from release_sentinel.models import Decision, Evidence, Severity
from release_sentinel.policy import BlockRequires, Policy


def make_evidence(severity: Severity, ev_id: str = "test") -> Evidence:
    return Evidence(
        id=ev_id,
        severity=severity,
        file=None,
        explanation="test explanation",
        legitimate_use_note="test note",
    )


class TestDecide:
    def test_empty_evidence_returns_allow(self):
        decision, limitations = decide([])
        assert decision == Decision.ALLOW

    def test_low_only_returns_allow(self):
        evidence = [make_evidence(Severity.LOW)]
        decision, _ = decide(evidence)
        assert decision == Decision.ALLOW

    def test_medium_only_returns_warn(self):
        evidence = [make_evidence(Severity.MEDIUM)]
        decision, _ = decide(evidence)
        assert decision == Decision.WARN

    # Stage 2: a single HIGH signal type → WARN (single-signal cap)
    def test_single_high_signal_returns_warn(self):
        evidence = [make_evidence(Severity.HIGH)]
        decision, _ = decide(evidence)
        assert decision == Decision.WARN

    def test_single_critical_signal_returns_warn(self):
        evidence = [make_evidence(Severity.CRITICAL)]
        decision, _ = decide(evidence)
        assert decision == Decision.WARN

    def test_mixed_low_and_medium_returns_warn(self):
        evidence = [
            make_evidence(Severity.LOW, "a"),
            make_evidence(Severity.MEDIUM, "b"),
        ]
        decision, _ = decide(evidence)
        assert decision == Decision.WARN

    # Stage 2: multiple signals but no corroboration pair → WARN
    def test_multiple_signals_without_corroboration_returns_warn(self):
        evidence = [
            make_evidence(Severity.LOW, "a"),
            make_evidence(Severity.LOW, "b"),
            make_evidence(Severity.HIGH, "c"),
        ]
        decision, _ = decide(evidence)
        assert decision == Decision.WARN

    # Stage 2: corroborating pair present + HIGH/CRITICAL → BLOCK
    def test_corroborating_pair_triggers_block(self):
        """install_script_added + network_access → BLOCK per default policy."""
        evidence = [
            Evidence(
                id="install_script_added",
                severity=Severity.HIGH,
                file="package.json",
                explanation="new install hook",
                legitimate_use_note="native addons",
            ),
            Evidence(
                id="network_access",
                severity=Severity.MEDIUM,
                file="setup.js",
                explanation="http.request call",
                legitimate_use_note="API calls",
            ),
        ]
        decision, _ = decide(evidence)
        assert decision == Decision.BLOCK

    def test_corroboration_with_dynamic_code_triggers_block(self):
        """install_script_added + dynamic_code → BLOCK per default policy."""
        evidence = [
            Evidence(
                id="install_script_added",
                severity=Severity.HIGH,
                file="package.json",
                explanation="new install hook",
                legitimate_use_note="native addons",
            ),
            Evidence(
                id="dynamic_code",
                severity=Severity.HIGH,
                file="setup.js",
                explanation="eval call",
                legitimate_use_note="template engines",
            ),
        ]
        decision, _ = decide(evidence)
        assert decision == Decision.BLOCK

    # install_script_changed alone → WARN (not BLOCK), per policy override
    def test_install_script_changed_alone_is_warn(self):
        evidence = [
            Evidence(
                id="install_script_changed",
                severity=Severity.MEDIUM,
                file="package.json",
                explanation="hook changed",
                legitimate_use_note="refactor",
            )
        ]
        decision, _ = decide(evidence)
        assert decision == Decision.WARN

    def test_corroboration_requires_high_severity(self):
        """Two LOW signals matching a corroboration pair → still WARN (no HIGH/CRITICAL)."""
        policy = Policy(
            block_requires=[BlockRequires(signals=["sig_a", "sig_b"])],
        )
        evidence = [
            make_evidence(Severity.LOW, "sig_a"),
            make_evidence(Severity.LOW, "sig_b"),
        ]
        decision, _ = decide(evidence, policy=policy)
        assert decision == Decision.WARN

    def test_custom_policy_block(self):
        """Custom policy with a simple pair should BLOCK when signals are present + HIGH."""
        policy = Policy(
            block_requires=[BlockRequires(signals=["foo", "bar"])],
        )
        evidence = [
            make_evidence(Severity.HIGH, "foo"),
            make_evidence(Severity.MEDIUM, "bar"),
        ]
        decision, _ = decide(evidence, policy=policy)
        assert decision == Decision.BLOCK

    def test_limitations_always_non_empty(self):
        for evidence_list in [
            [],
            [make_evidence(Severity.LOW)],
            [make_evidence(Severity.HIGH)],
        ]:
            _, limitations = decide(evidence_list)
            assert isinstance(limitations, list)
            assert len(limitations) > 0, "Limitations should always be present"

    def test_limitations_mention_static_analysis(self):
        _, limitations = decide([])
        combined = " ".join(limitations).lower()
        assert "static" in combined or "js" in combined or "javascript" in combined

    def test_decide_with_policy_path(self, tmp_path: Path):
        policy_file = tmp_path / "custom.toml"
        policy_file.write_text(
            """
[decision]
single_signal_cap = "WARN"

[[decision.block_requires]]
signals = ["custom_sig_1", "custom_sig_2"]
description = "custom block pair"
""",
            encoding="utf-8",
        )
        evidence = [
            make_evidence(Severity.HIGH, "custom_sig_1"),
            make_evidence(Severity.MEDIUM, "custom_sig_2"),
        ]
        decision, _ = decide(evidence, policy_path=policy_file)
        assert decision == Decision.BLOCK
