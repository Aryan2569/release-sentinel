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
        assert "Invalid --format" in result.output

    def test_invalid_min_severity_exits_with_error(self):
        result = runner.invoke(app, ["diff", "pkg", "1.0.0", "1.0.1", "--min-severity", "SUPER"])
        assert result.exit_code == 1
        assert "Invalid --min-severity" in result.output

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

    @patch("release_sentinel.cli._run_analysis")
    def test_cli_diff_default_as_of_is_current_time(self, mock_run: patch):
        mock_run.return_value = _make_report([], Decision.ALLOW)
        before = datetime.now(tz=UTC)
        result = runner.invoke(app, ["diff", "pkg", "1.0.0", "1.0.1", "--quiet"])
        after = datetime.now(tz=UTC)
        assert result.exit_code == 0
        mock_run.assert_called_once()
        as_of_arg = mock_run.call_args.kwargs["as_of"]
        assert isinstance(as_of_arg, datetime)
        assert before <= as_of_arg <= after

    @patch("release_sentinel.cli.analyze_release")
    @patch("release_sentinel.cli.extract_release")
    @patch("release_sentinel.cli.NpmRegistryClient")
    def test_run_analysis_passes_as_of_and_client_to_analyze_release(
        self, mock_client_cls: patch, mock_extract: patch, mock_analyze: patch, tmp_path: Path
    ):
        mock_client = mock_client_cls.return_value.__enter__.return_value
        mock_client.get_release_ref.side_effect = lambda pkg, ver, as_of: ReleaseRef(
            name=pkg, version=ver, published_at=datetime.now(tz=UTC)
        )
        mock_client.download_tarball.side_effect = lambda pkg, ver, as_of, dest: dest
        mock_extract.side_effect = lambda tgz, dest, config: None
        mock_analyze.return_value = []

        now_dt = datetime.now(tz=UTC)
        from release_sentinel.cli import _run_analysis

        report = _run_analysis(
            package="foo",
            old_version="1.0.0",
            new_version="1.0.1",
            as_of=now_dt,
            cache_dir=tmp_path / "cache",
            quiet=True,
        )
        assert report.decision == Decision.ALLOW
        mock_analyze.assert_called_once()
        kwargs = mock_analyze.call_args.kwargs
        assert kwargs["as_of"] == now_dt
        assert kwargs["registry_client"] == mock_client


class TestCliCheck:
    def test_check_missing_base_and_base_ref_exits_2(self):
        result = runner.invoke(app, ["check"])
        assert result.exit_code == 2
        assert "Either --base" in result.output
        assert "Internal error" not in result.output

    def test_check_invalid_fail_on_exits_2(self):
        result = runner.invoke(app, ["check", "--base", "package-lock.json", "--fail-on", "bad"])
        assert result.exit_code == 2
        assert "Invalid --fail-on" in result.output

    def test_check_unsupported_yarn_lock_exits_2(self):
        result = runner.invoke(app, ["check", "--base", "yarn.lock"])
        assert result.exit_code == 2
        assert "Yarn lockfile" in result.output

    def test_check_markdown_output_format(self, tmp_path: Path):
        base_f = tmp_path / "base.json"
        head_f = tmp_path / "head.json"
        base_f.write_text(json.dumps({"lockfileVersion": 3, "packages": {}}), encoding="utf-8")
        head_f.write_text(json.dumps({"lockfileVersion": 3, "packages": {}}), encoding="utf-8")

        result = runner.invoke(app, [
            "check",
            "--base", str(base_f),
            "--head", str(head_f),
            "--format", "markdown",
        ])
        assert result.exit_code == 0
        assert "<!-- release-sentinel-pr-comment -->" in result.output
        assert "Verdict:" in result.output
        assert "ALLOW" in result.output

    @patch("release_sentinel.cli.scan_lockfile_diff")
    def test_check_fail_on_block_and_warn(self, mock_scan: patch, tmp_path: Path):
        from release_sentinel.lockfile import LockfileDiffReport

        base_f = tmp_path / "base.json"
        head_f = tmp_path / "head.json"
        base_f.write_text("{}", encoding="utf-8")
        head_f.write_text("{}", encoding="utf-8")

        # Decision = WARN
        mock_scan.return_value = LockfileDiffReport(
            base_source="base",
            head_source="head",
            total_packages_scanned=1,
            decision=Decision.WARN,
            package_results=[{
                "package": "test-pkg",
                "old_version": "1.0.0",
                "new_version": "1.0.1",
                "change_type": "upgraded",
                "decision": "WARN",
                "evidence": ["install_script_changed"],
                "evidence_details": [{
                    "id": "install_script_changed",
                    "severity": "MEDIUM",
                    "file": "package.json",
                    "explanation": "Script changed",
                    "legitimate_use_note": "Rebuilt assets",
                }],
                "limitations": [],
                "status": "ok",
            }],
            limitations=[],
        )

        # --fail-on block with WARN -> passes (0)
        res_block = runner.invoke(app, [
            "check", "--base", str(base_f), "--head", str(head_f), "--fail-on", "block"
        ])
        assert res_block.exit_code == 0

        # --fail-on warn with WARN -> fails gate (1)
        res_warn = runner.invoke(app, [
            "check", "--base", str(base_f), "--head", str(head_f), "--fail-on", "warn"
        ])
        assert res_warn.exit_code == 1

        # --fail-on never with WARN -> passes (0)
        res_never = runner.invoke(app, [
            "check", "--base", str(base_f), "--head", str(head_f), "--fail-on", "never"
        ])
        assert res_never.exit_code == 0


class TestCliDemo:
    def test_demo_axios_screen_recording_support(self):
        result = runner.invoke(app, ["demo", "--pair", "axios", "1.14.0", "1.14.1"])
        assert result.exit_code == 0
        assert "axios" in result.output
        assert "1.14.0" in result.output
        assert "1.14.1" in result.output
        assert "plain-crypto-js" in result.output
