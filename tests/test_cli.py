"""Tests for the Release Sentinel CLI (cli.py).

Tests CLI options: --format (text, json, markdown), --quiet, --min-severity,
--policy, --max-files, --max-size, --as-of, and exit codes.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from release_sentinel.cli import (
    _generate_one_line_summary,
    _group_evidence,
    _render_markdown,
    app,
)
from release_sentinel.models import Decision, Evidence, ReleaseRef, Report, Severity

runner = CliRunner()


def _make_report(
    evidence: list[Evidence],
    decision: Decision = Decision.WARN,
) -> Report:
    return Report(
        old_release=ReleaseRef(
            name="demo-pkg",
            version="1.0.0",
            published_at=datetime(2024, 1, 1, tzinfo=UTC),
        ),
        new_release=ReleaseRef(
            name="demo-pkg",
            version="1.0.1",
            published_at=datetime(2024, 1, 2, tzinfo=UTC),
        ),
        decision=decision,
        evidence=evidence,
        limitations=["Static analysis only."],
        as_of=datetime(2024, 6, 1, tzinfo=UTC),
        generated_at=datetime(2024, 6, 2, tzinfo=UTC),
    )


class TestFormattingHelpers:
    def test_one_line_summary(self):
        ev = [
            Evidence(
                id="install_script_added",
                severity=Severity.HIGH,
                file="package.json",
                explanation="added script",
                legitimate_use_note="native addon",
            ),
            Evidence(
                id="network_access",
                severity=Severity.MEDIUM,
                file="setup.js",
                explanation="http request",
                legitimate_use_note="api call",
            ),
        ]
        report = _make_report(ev, Decision.BLOCK)
        summary = _generate_one_line_summary(report, ev)
        assert "BLOCK" in summary
        assert "demo-pkg" in summary
        assert "1.0.0 -> 1.0.1" in summary
        assert "2 evidence item(s)" in summary
        assert "1 high" in summary
        assert "1 medium" in summary

    def test_group_evidence(self):
        ev = [
            Evidence(
                id="install_script_added",
                severity=Severity.HIGH,
                file="package.json",
                explanation="x",
                legitimate_use_note="y",
            ),
            Evidence(
                id="dynamic_code",
                severity=Severity.HIGH,
                file="setup.js",
                explanation="x",
                legitimate_use_note="y",
            ),
            Evidence(
                id="dependency_added",
                severity=Severity.LOW,
                file="package.json",
                explanation="x",
                legitimate_use_note="y",
            ),
            Evidence(
                id="custom_unknown_id",
                severity=Severity.LOW,
                file=None,
                explanation="x",
                legitimate_use_note="y",
            ),
        ]
        grouped = _group_evidence(ev)
        assert "Lifecycle & Install Scripts" in grouped
        assert "Suspicious Code & Obfuscation" in grouped
        assert "Dependencies & Binaries Config" in grouped
        assert "Other Findings" in grouped

    def test_markdown_rendering(self):
        ev = [
            Evidence(
                id="install_script_added",
                severity=Severity.HIGH,
                file="package.json",
                explanation="new hook",
                legitimate_use_note="setup",
            )
        ]
        report = _make_report(ev, Decision.WARN)
        md = _render_markdown(report, ev)
        assert "## ⚠️ Release Sentinel: WARN" in md
        assert "> **Summary**:" in md
        assert "| **Package** | `demo-pkg` |" in md
        assert "### Lifecycle & Install Scripts" in md
        assert "`install_script_added`" in md
        assert "<details>" in md
        assert "Static analysis only." in md


class TestCliExecution:
    def test_version_flag(self):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "sentinel" in result.stdout

    def test_invalid_format_exits_with_error(self):
        result = runner.invoke(app, ["diff", "pkg", "1.0.0", "1.0.1", "--format", "yaml"])
        assert result.exit_code == 1
        assert "Invalid --format" in result.stderr

    def test_invalid_min_severity_exits_with_error(self):
        result = runner.invoke(app, ["diff", "pkg", "1.0.0", "1.0.1", "--min-severity", "SUPER"])
        assert result.exit_code == 1
        assert "Invalid --min-severity" in result.stderr

    @patch("release_sentinel.cli._run_analysis")
    def test_cli_diff_json_format(self, mock_run: patch):
        ev = [
            Evidence(
                id="install_script_added",
                severity=Severity.HIGH,
                file="package.json",
                explanation="postinstall added",
                legitimate_use_note="build",
            )
        ]
        mock_run.return_value = _make_report(ev, Decision.WARN)

        result = runner.invoke(app, ["diff", "pkg", "1.0.0", "1.0.1", "--format", "json"])
        assert result.exit_code == 1  # WARN exit code is 1
        data = json.loads(result.stdout)
        assert data["decision"] == "WARN"
        assert len(data["evidence"]) == 1

    @patch("release_sentinel.cli._run_analysis")
    def test_cli_diff_markdown_format(self, mock_run: patch):
        mock_run.return_value = _make_report([], Decision.ALLOW)

        result = runner.invoke(
            app, ["diff", "pkg", "1.0.0", "1.0.1", "--format", "markdown", "--quiet"]
        )
        assert result.exit_code == 0  # ALLOW exit code is 0
        assert "## ✅ Release Sentinel: ALLOW" in result.stdout
        assert "No suspicious evidence detected" in result.stdout

    @patch("release_sentinel.cli._run_analysis")
    def test_cli_min_severity_filtering(self, mock_run: patch):
        ev = [
            Evidence(
                id="dep_added",
                severity=Severity.LOW,
                file="package.json",
                explanation="dep",
                legitimate_use_note="routine",
            ),
            Evidence(
                id="install_script_added",
                severity=Severity.HIGH,
                file="package.json",
                explanation="hook",
                legitimate_use_note="native",
            ),
        ]
        mock_run.return_value = _make_report(ev, Decision.WARN)

        result = runner.invoke(
            app,
            [
                "diff",
                "pkg",
                "1.0.0",
                "1.0.1",
                "--format",
                "json",
                "--min-severity",
                "HIGH",
            ],
        )
        assert result.exit_code == 1
        data = json.loads(result.stdout)
        assert len(data["evidence"]) == 1
        assert data["evidence"][0]["severity"] == "HIGH"

    @patch("release_sentinel.cli._run_analysis")
    def test_cli_policy_flag_passed(self, mock_run: patch, tmp_path: Path):
        policy_file = tmp_path / "custom.toml"
        policy_file.write_text("[decision]\nsingle_signal_cap = 'WARN'\n", encoding="utf-8")
        mock_run.return_value = _make_report([], Decision.ALLOW)

        result = runner.invoke(
            app,
            [
                "diff",
                "pkg",
                "1.0.0",
                "1.0.1",
                "--policy",
                str(policy_file),
                "--quiet",
            ],
        )
        assert result.exit_code == 0
        mock_run.assert_called_once()
        assert mock_run.call_args.kwargs["policy_path"] == policy_file
