"""Tests for Pydantic data models."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from release_sentinel.models import (
    Decision,
    Evidence,
    ReleaseRef,
    Report,
    Severity,
)


class TestReleaseRef:
    def test_valid(self):
        ref = ReleaseRef(
            name="lodash",
            version="4.17.21",
            published_at=datetime(2021, 2, 20, tzinfo=UTC),
        )
        assert ref.name == "lodash"
        assert ref.version == "4.17.21"

    def test_missing_fields_raises(self):
        with pytest.raises(ValidationError):
            ReleaseRef(name="pkg")  # type: ignore[call-arg]


class TestEvidence:
    def test_valid_with_file(self):
        ev = Evidence(
            id="install_script_added",
            severity=Severity.HIGH,
            file="package.json",
            explanation="A postinstall script was added.",
            legitimate_use_note="May be used for native compilation.",
        )
        assert ev.severity == Severity.HIGH
        assert ev.file == "package.json"

    def test_valid_no_file(self):
        ev = Evidence(
            id="large_size_jump",
            severity=Severity.MEDIUM,
            file=None,
            explanation="Size grew 3x.",
            legitimate_use_note="May bundle dependencies.",
        )
        assert ev.file is None

    def test_severity_enum_values(self):
        for sev in Severity:
            assert isinstance(sev.value, str)

    def test_missing_required_field_raises(self):
        with pytest.raises(ValidationError):
            Evidence(  # type: ignore[call-arg]
                id="x",
                severity=Severity.LOW,
                explanation="test",
                # missing legitimate_use_note
            )


class TestDecision:
    def test_all_values(self):
        assert set(Decision) == {Decision.ALLOW, Decision.WARN, Decision.BLOCK}


class TestReport:
    def _make_ref(self, version: str) -> ReleaseRef:
        return ReleaseRef(
            name="pkg",
            version=version,
            published_at=datetime(2024, 1, 1, tzinfo=UTC),
        )

    def test_empty_evidence_is_allow(self):
        report = Report(
            old_release=self._make_ref("1.0.0"),
            new_release=self._make_ref("1.0.1"),
            decision=Decision.ALLOW,
            evidence=[],
            limitations=["Static only."],
            as_of=datetime(2024, 6, 1, tzinfo=UTC),
            generated_at=datetime(2024, 6, 2, tzinfo=UTC),
        )
        assert report.decision == Decision.ALLOW
        assert report.evidence == []

    def test_json_roundtrip(self):
        ev = Evidence(
            id="install_script_added",
            severity=Severity.HIGH,
            file="package.json",
            explanation="A postinstall was added.",
            legitimate_use_note="May compile native code.",
        )
        report = Report(
            old_release=self._make_ref("1.0.0"),
            new_release=self._make_ref("1.0.1"),
            decision=Decision.BLOCK,
            evidence=[ev],
            limitations=["JS not parsed."],
            as_of=datetime(2024, 6, 1, tzinfo=UTC),
            generated_at=datetime(2024, 6, 2, tzinfo=UTC),
        )
        json_str = report.model_dump_json()
        reloaded = Report.model_validate_json(json_str)
        assert reloaded.decision == Decision.BLOCK
        assert reloaded.evidence[0].id == "install_script_added"
