"""Tests for escaping untrusted strings in Rich terminal output."""

from __future__ import annotations

import io
from datetime import UTC, datetime

from rich.console import Console

import release_sentinel.cli as cli
from release_sentinel.cli import _print_report_text, print_lockfile_text
from release_sentinel.lockfile import LockfileDiffReport
from release_sentinel.models import Decision, Evidence, ReleaseRef, Report, Severity


def test_print_lockfile_text_with_hostile_markup():
    buf = io.StringIO()
    test_console = Console(file=buf, force_terminal=True, color_system="standard", width=200)

    report = LockfileDiffReport(
        base_source="package-lock.json",
        head_source="package-lock.json",
        total_packages_scanned=1,
        decision=Decision.WARN,
        package_results=[
            {
                "package": "[bold red]hostile-pkg[/]",
                "old_version": "[1.0.0]",
                "new_version": "[2.0.0]",
                "change_type": "upgrade",
                "decision": "WARN",
                "evidence": ["[/x]", "[bold red]x[/]"],
                "evidence_details": [
                    {
                        "id": "[/x]",
                        "severity": Severity.HIGH.name,
                        "file": "path/to/[foo]/bar.js",
                        "explanation": "Hostile explanation with [/x] and [bold red]x[/]",
                        "legitimate_use_note": "Legit note [tag]",
                    }
                ],
                "limitations": ["Limitation with [/dim] and [bold]x[/]"],
                "status": "ok",
            }
        ],
        limitations=["Top limitation with [/dim] and [red]x[/red]"],
    )

    orig_console = cli.console
    try:
        cli.console = test_console
        print_lockfile_text(report)
    finally:
        cli.console = orig_console

    output = buf.getvalue()
    assert "[bold red]hostile-pkg[/]" in output
    assert "[/x]" in output


def test_print_report_text_with_hostile_markup():
    buf = io.StringIO()
    test_console = Console(file=buf, force_terminal=True, color_system="standard", width=200)

    ev = [
        Evidence(
            id="[/x]",
            severity=Severity.HIGH,
            file="path/to/[brackets]/file.js",
            explanation="Explanation containing [/x] and [bold red]x[/] markup",
            legitimate_use_note="Note with [brackets]",
        )
    ]
    report = Report(
        old_release=ReleaseRef(
            name="[old-pkg]", version="[1.0.0]", published_at=datetime.now(UTC)
        ),
        new_release=ReleaseRef(
            name="[new-pkg]", version="[2.0.0]", published_at=datetime.now(UTC)
        ),
        decision=Decision.WARN,
        evidence=ev,
        as_of=datetime.now(UTC),
        generated_at=datetime.now(UTC),
        limitations=["Limitation with [/dim] and [red]tag[/]"],
    )

    orig_console = cli.console
    try:
        cli.console = test_console
        _print_report_text(report, ev)
    finally:
        cli.console = orig_console

    output = buf.getvalue()
    assert "[old-pkg]" in output
    assert "path/to/[brackets]/file.js" in output
    assert "[/x]" in output
