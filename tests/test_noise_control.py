"""Tests for noise control, notable criteria, and PR comment gating."""

import json
from pathlib import Path

from typer.testing import CliRunner

from release_sentinel.cli import app
from release_sentinel.lockfile import (
    LockfileDiffReport,
    is_report_notable,
    should_post_comment,
)
from release_sentinel.models import Decision


def test_is_report_notable_block():
    report = LockfileDiffReport(
        base_source="base",
        head_source="head",
        total_packages_scanned=1,
        decision=Decision.BLOCK,
        package_results=[],
        limitations=[],
    )
    assert is_report_notable(report) is True


def test_is_report_notable_high_evidence():
    report = {
        "decision": "WARN",
        "package_results": [
            {
                "package": "pkg-a",
                "evidence_details": [
                    {"id": "dynamic_code", "severity": "HIGH"},
                ],
            }
        ],
    }
    assert is_report_notable(report) is True


def test_is_report_notable_install_hook_change():
    report = {
        "decision": "WARN",
        "package_results": [
            {
                "package": "pkg-a",
                "evidence": ["install_script_changed"],
                "evidence_details": [
                    {"id": "install_script_changed", "severity": "MEDIUM"},
                ],
            }
        ],
    }
    assert is_report_notable(report) is True


def test_is_report_notable_two_medium_evidence():
    report = {
        "decision": "WARN",
        "package_results": [
            {
                "package": "pkg-a",
                "evidence_details": [
                    {"id": "process_exec", "severity": "MEDIUM"},
                    {"id": "network_access", "severity": "MEDIUM"},
                ],
            }
        ],
    }
    assert is_report_notable(report) is True


def test_is_not_notable_single_medium():
    report = {
        "decision": "WARN",
        "package_results": [
            {
                "package": "pkg-a",
                "evidence_details": [
                    {"id": "notable_new_file", "severity": "MEDIUM"},
                ],
            }
        ],
    }
    assert is_report_notable(report) is False


def test_is_not_notable_low_and_single_medium():
    report = {
        "decision": "WARN",
        "package_results": [
            {
                "package": "pkg-a",
                "evidence_details": [
                    {"id": "dependency_added", "severity": "LOW"},
                    {"id": "high_entropy_string", "severity": "MEDIUM"},
                ],
            }
        ],
    }
    assert is_report_notable(report) is False


def test_is_not_notable_allow_package_with_evidence():
    report = {
        "decision": "WARN",
        "package_results": [
            {
                "package": "clean-pkg",
                "decision": "ALLOW",
                "evidence_details": [
                    {"id": "dynamic_code", "severity": "HIGH", "effective_severity": "HIGH"},
                ],
            }
        ],
    }
    # An ALLOW package should never drive report notability
    assert is_report_notable(report) is False


def test_is_report_notable_uses_effective_severity():
    # Raw severity is HIGH, but effective severity was overridden to LOW
    demoted_report = {
        "decision": "WARN",
        "package_results": [
            {
                "package": "pkg-a",
                "decision": "WARN",
                "evidence_details": [
                    {"id": "some_sig", "severity": "HIGH", "effective_severity": "LOW"},
                ],
            }
        ],
    }
    assert is_report_notable(demoted_report) is False

    # Raw severity is LOW, but effective severity was overridden to HIGH
    promoted_report = {
        "decision": "WARN",
        "package_results": [
            {
                "package": "pkg-a",
                "decision": "WARN",
                "evidence_details": [
                    {"id": "some_sig", "severity": "LOW", "effective_severity": "HIGH"},
                ],
            }
        ],
    }
    assert is_report_notable(promoted_report) is True


def test_should_post_comment_matrix():
    notable_report = {
        "decision": "WARN",
        "package_results": [
            {"evidence_details": [{"id": "dynamic_code", "severity": "HIGH"}]}
        ],
    }
    quiet_report = {
        "decision": "WARN",
        "package_results": [
            {"evidence_details": [{"id": "notable_new_file", "severity": "MEDIUM"}]}
        ],
    }
    block_report = {"decision": "BLOCK", "package_results": []}
    allow_report = {"decision": "ALLOW", "package_results": []}

    # 'always'
    assert should_post_comment(block_report, "always") is True
    assert should_post_comment(notable_report, "always") is True
    assert should_post_comment(quiet_report, "always") is True
    assert should_post_comment(allow_report, "always") is True

    # 'warn'
    assert should_post_comment(block_report, "warn") is True
    assert should_post_comment(notable_report, "warn") is True
    assert should_post_comment(quiet_report, "warn") is True
    assert should_post_comment(allow_report, "warn") is False

    # 'notable' (default)
    assert should_post_comment(block_report, "notable") is True
    assert should_post_comment(notable_report, "notable") is True
    assert should_post_comment(quiet_report, "notable") is False
    assert should_post_comment(allow_report, "notable") is False

    # 'block'
    assert should_post_comment(block_report, "block") is True
    assert should_post_comment(notable_report, "block") is False
    assert should_post_comment(quiet_report, "block") is False
    assert should_post_comment(allow_report, "block") is False

    # invalid comment_on
    assert should_post_comment(block_report, "invalid") is False
    assert should_post_comment(allow_report, "invalid") is False

    # LockfileDiffReport object instance
    typed_block = LockfileDiffReport("base", "head", 1, Decision.BLOCK, [], [])
    typed_allow = LockfileDiffReport("base", "head", 1, Decision.ALLOW, [], [])
    assert should_post_comment(typed_block, "block") is True
    assert should_post_comment(typed_allow, "block") is False
    assert should_post_comment(typed_allow, "always") is True


def test_cli_check_json_output_file(tmp_path: Path):
    runner = CliRunner()
    base_lock = tmp_path / "base.json"
    head_lock = tmp_path / "head.json"
    json_out = tmp_path / "report.json"

    lock_content = json.dumps({
        "name": "test-repo",
        "version": "1.0.0",
        "lockfileVersion": 2,
        "packages": {"": {"name": "test-repo", "version": "1.0.0"}},
    })
    base_lock.write_text(lock_content, encoding="utf-8")
    head_lock.write_text(lock_content, encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "check",
            "--base",
            str(base_lock),
            "--head",
            str(head_lock),
            "--json-output-file",
            str(json_out),
        ],
    )
    assert result.exit_code == 0
    assert json_out.exists()
    data = json.loads(json_out.read_text(encoding="utf-8"))
    assert data["decision"] == "ALLOW"
    assert data["total_packages_scanned"] == 0
