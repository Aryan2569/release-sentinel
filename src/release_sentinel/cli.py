"""CLI for Release Sentinel.

Usage
-----
    sentinel diff <package> <old_version> <new_version> [OPTIONS]

Options
-------
    --as-of ISO_DATETIME   Treat this as the current time for registry queries.
                           Defaults to now (UTC).  Accepts ISO 8601 strings.
    --json                 Output the report as JSON to stdout.
    --cache-dir PATH       Override the default cache directory
                           (~/.cache/release_sentinel).

Examples
--------
    sentinel diff lodash 4.17.20 4.17.21
    sentinel diff express 4.18.2 4.18.3 --as-of 2024-01-15T00:00:00Z
    sentinel diff chalk 5.3.0 5.4.0 --json
"""

from __future__ import annotations

import json
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from release_sentinel import __version__
from release_sentinel.differ import analyze_release
from release_sentinel.engine import decide
from release_sentinel.eval import get_samples_root
from release_sentinel.extractor import ExtractionConfig, extract_release
from release_sentinel.lockfile import (
    DEFAULT_MAX_PACKAGES,
    LockfileDiffReport,
    LockfileError,
    LockfileParseError,
    UnsupportedLockfileError,
    get_git_repo_root,
    read_lockfile_from_git,
    read_lockfile_from_path,
    scan_lockfile_diff,
)
from release_sentinel.models import Decision, Evidence, ReleaseRef, Report, Severity
from release_sentinel.policy import load_policy
from release_sentinel.registry import NpmRegistryClient, RegistryError
from release_sentinel.sanitizer import (
    MAX_FIELD_CHARS,
    cap_comment_size,
    defang_gha_commands,
    render_code_span,
    sanitize_untrusted_text,
)

app = typer.Typer(
    name="sentinel",
    help="Release Sentinel — time-aware static security gate for npm dependency updates.",
    add_completion=False,
)

console = Console(stderr=True)  # rich output goes to stderr; JSON/Markdown goes to stdout

_DEFAULT_CACHE_DIR = Path.home() / ".cache" / "release_sentinel"

# Decision → colour mapping for terminal output
_DECISION_STYLE: dict[Decision, str] = {
    Decision.ALLOW: "bold green",
    Decision.WARN: "bold yellow",
    Decision.BLOCK: "bold red",
}

_SEVERITY_STYLE: dict[str, str] = {
    "INFO": "dim cyan",
    "LOW": "dim",
    "MEDIUM": "yellow",
    "HIGH": "red",
    "CRITICAL": "bold red",
}

_SEV_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

_EVIDENCE_GROUPS: list[tuple[str, set[str]]] = [
    (
        "Lifecycle & Install Scripts",
        {"install_script_added", "install_script_changed"},
    ),
    (
        "Suspicious Code & Obfuscation",
        {
            "process_exec",
            "dynamic_code",
            "network_access",
            "hardcoded_url",
            "hardcoded_ip",
            "credential_file_read",
            "registry_token",
            "long_encoded_blob",
            "high_entropy_string",
            "env_enumeration",
            "ci_write",
            "shell_profile_write",
            "git_hook_write",
        },
    ),
    (
        "Files & Binaries",
        {
            "notable_new_file",
            "native_binary_present",
            "new_files_summary",
            "large_size_jump",
            "large_file_count_jump",
        },
    ),
    (
        "Dependencies & Binaries Config",
        {
            "dependency_added",
            "dependency_removed",
            "dependency_version_changed",
            "bin_entry_added",
            "bin_entry_changed",
        },
    ),
    (
        "Inspection Limitations & Warnings",
        {"inspection_failed"},
    ),
]


def _version_callback(value: bool) -> None:  # noqa: FBT001
    if value:
        typer.echo(f"sentinel {__version__}")
        raise typer.Exit


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version"),
    ] = None,
) -> None:
    """Release Sentinel CLI."""


@app.command()
def diff(
    package: Annotated[str, typer.Argument(help="npm package name")],
    old_version: Annotated[str, typer.Argument(help="Version to compare from")],
    new_version: Annotated[str, typer.Argument(help="Version to compare to")],
    as_of: Annotated[
        str | None,
        typer.Option(
            "--as-of",
            help="ISO 8601 datetime for the registry cut-off (default: now).",
        ),
    ] = None,
    format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output format: text | json | markdown.",
        ),
    ] = "text",
    output_json: Annotated[
        bool,
        typer.Option("--json", help="Output report as JSON to stdout (alias for --format json)."),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Suppress non-essential progress output."),
    ] = False,
    min_severity: Annotated[
        str,
        typer.Option(
            "--min-severity",
            help="Minimum severity to display: LOW | MEDIUM | HIGH | CRITICAL.",
        ),
    ] = "LOW",
    policy: Annotated[
        Path | None,
        typer.Option(
            "--policy",
            help="Path to a custom TOML policy file to overlay.",
        ),
    ] = None,
    profile: Annotated[
        str,
        typer.Option(
            "--profile",
            help="Policy profile: 'default' (low-noise) or 'strict' (frozen v1.4 research policy).",
        ),
    ] = "default",
    max_files: Annotated[
        int,
        typer.Option("--max-files", help="Soft cap for maximum extracted files (default: 5000)."),
    ] = 5000,
    max_size: Annotated[
        int,
        typer.Option("--max-size", help="Soft cap for size in MB (default: 200)."),
    ] = 200,
    cache_dir: Annotated[
        Path | None,
        typer.Option("--cache-dir", help="Cache directory (default: ~/.cache/release_sentinel)."),
    ] = None,
    experimental_hollow: Annotated[
        bool,
        typer.Option(
            "--experimental-hollow",
            help="Enable experimental hollow+lookalike release warnings.",
        ),
    ] = False,
    samples_root: Annotated[
        Path | None,
        typer.Option(
            "--samples-root",
            help="Path to malware samples directory (env: RS_SAMPLES_ROOT).",
            envvar="RS_SAMPLES_ROOT",
        ),
    ] = None,
) -> None:
    """Compare two versions of an npm package and return a security gate decision.

    Exit codes:
      0: ALLOW (all checks passed)
      1: WARN (suspicious signals detected, or argument usage error)
      2: BLOCK (severe security violation detected, or registry error)
      3: Unexpected internal error
    """
    # --- Resolve as_of ---
    if as_of is not None:
        try:
            as_of_dt = _parse_as_of(as_of)
        except ValueError as exc:
            console.print(f"[red]Invalid --as-of value: {escape(str(exc))}[/red]")
            raise typer.Exit(code=1) from exc
    else:
        as_of_dt = datetime.now(tz=UTC)

    effective_cache = cache_dir or _DEFAULT_CACHE_DIR

    # Format resolution
    selected_format = "json" if output_json else format.strip().lower()
    if selected_format not in {"text", "json", "markdown"}:
        console.print(f"[red]Invalid --format {format!r}. Choose text, json, or markdown.[/red]")
        raise typer.Exit(code=1)

    # Severity resolution
    try:
        min_sev_enum = Severity(min_severity.strip().upper())
    except ValueError:
        console.print(
            f"[red]Invalid --min-severity {min_severity!r}. "
            "Choose LOW, MEDIUM, HIGH, or CRITICAL.[/red]"
        )
        raise typer.Exit(code=1) from None

    if not quiet and selected_format == "text":
        console.print(
            f"\n[bold]Release Sentinel[/bold]  "
            f"[dim]v{__version__}[/dim]\n"
            f"  Package : [cyan]{escape(package)}[/cyan]\n"
            f"  Old     : [cyan]{escape(old_version)}[/cyan]\n"
            f"  New     : [cyan]{escape(new_version)}[/cyan]\n"
            f"  As-of   : [cyan]{as_of_dt.isoformat()}[/cyan]\n"
        )

    try:
        report = _run_analysis(
            package=package,
            old_version=old_version,
            new_version=new_version,
            as_of=as_of_dt,
            cache_dir=effective_cache,
            policy_path=policy,
            profile=profile,
            max_files=max_files,
            max_size=max_size,
            quiet=quiet,
            experimental_hollow=experimental_hollow,
            samples_root=samples_root,
        )
    except RegistryError as exc:
        console.print(f"[red]Registry error: {escape(str(exc))}[/red]")
        raise typer.Exit(code=2) from exc
    except typer.Exit:
        raise
    except Exception as exc:
        console.print(f"[red]Unexpected error: {escape(str(exc))}[/red]")
        raise typer.Exit(code=3) from exc

    _render_output(report, selected_format, min_sev_enum)

    # Exit code mirrors decision severity
    exit_codes = {Decision.ALLOW: 0, Decision.WARN: 1, Decision.BLOCK: 2}
    raise typer.Exit(code=exit_codes[report.decision])


# ------------------------------------------------------------------
# Analysis orchestration
# ------------------------------------------------------------------


def _run_analysis(
    package: str,
    old_version: str,
    new_version: str,
    as_of: datetime,
    cache_dir: Path,
    policy_path: Path | None = None,
    profile: str = "default",
    max_files: int = 5000,
    max_size: int = 200,
    quiet: bool = False,
    experimental_hollow: bool = False,
    samples_root: Path | None = None,
) -> Report:
    """Download, extract, compare, and decide."""
    with NpmRegistryClient(cache_dir=cache_dir) as client:
        # --- Resolve release refs ---
        if not quiet:
            console.print("[dim]Fetching registry metadata…[/dim]")
        old_ref = client.get_release_ref(package, old_version, as_of)
        new_ref = client.get_release_ref(package, new_version, as_of)

        with tempfile.TemporaryDirectory(prefix="sentinel-") as tmp:
            tmp_path = Path(tmp)

            # --- Download tarballs ---
            if not quiet:
                console.print(f"[dim]Downloading {package}@{old_version}…[/dim]")
            old_tgz = client.download_tarball(package, old_version, as_of, tmp_path / "old")
            if not quiet:
                console.print(f"[dim]Downloading {package}@{new_version}…[/dim]")
            new_tgz = client.download_tarball(package, new_version, as_of, tmp_path / "new")

            # --- Extract ---
            if not quiet:
                console.print("[dim]Extracting tarballs…[/dim]")
            ext_cfg = ExtractionConfig(
                max_files=max_files,
                max_total_size=max_size * 1024 * 1024,
            )
            old_result = extract_release(old_tgz, tmp_path / "old_extracted", config=ext_cfg)
            new_result = extract_release(new_tgz, tmp_path / "new_extracted", config=ext_cfg)

            # --- Diff & Analyze ---
            if not quiet:
                console.print("[dim]Comparing releases…[/dim]")
            policy = load_policy(
                policy_path, profile=profile, experimental_hollow=experimental_hollow
            )
            evidence = analyze_release(
                new=new_result,
                baseline=old_result,
                policy=policy,
                config=ext_cfg,
                as_of=as_of,
                registry_client=client,
                samples_root=samples_root,
                experimental_hollow=experimental_hollow,
            )

        # --- Decide ---
        decision, limitations = decide(
            evidence,
            policy=policy,
            experimental_hollow=experimental_hollow,
        )

        return Report(
            old_release=old_ref,
            new_release=new_ref,
            decision=decision,
            evidence=evidence,
            limitations=limitations,
            as_of=as_of,
            generated_at=datetime.now(tz=UTC),
        )


# ------------------------------------------------------------------
# Report formatting and output
# ------------------------------------------------------------------


def _group_evidence(evidence: list[Evidence]) -> dict[str, list[Evidence]]:
    """Group evidence items by functional category."""
    grouped: dict[str, list[Evidence]] = {}
    assigned: set[str] = set()

    for group_name, ids in _EVIDENCE_GROUPS:
        matching = [e for e in evidence if e.id in ids]
        if matching:
            grouped[group_name] = matching
            assigned.update(ids)

    other = [e for e in evidence if e.id not in assigned]
    if other:
        grouped["Other Findings"] = other

    return grouped


def _generate_one_line_summary(report: Report, evidence: list[Evidence]) -> str:
    """Generate a high-level summary string."""
    pkg = report.new_release.name
    v_old = report.old_release.version
    v_new = report.new_release.version

    counts: dict[str, int] = {}
    for ev in evidence:
        counts[ev.severity.value] = counts.get(ev.severity.value, 0) + 1

    parts: list[str] = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if sev in counts:
            parts.append(f"{counts[sev]} {sev.lower()}")

    counts_str = f" ({', '.join(parts)})" if parts else ""
    return (
        f"{report.decision.value}: {len(evidence)} evidence item(s){counts_str} "
        f"for {pkg} ({v_old} -> {v_new})"
    )


def _safe_print(text: str) -> None:
    """Safely print text to stdout defanging GitHub Actions commands and handling encoding."""
    defanged = defang_gha_commands(text)
    try:
        print(defanged)
    except UnicodeEncodeError:
        sys.stdout.buffer.write(defanged.encode("utf-8", errors="replace"))
        sys.stdout.buffer.write(b"\n")
        sys.stdout.buffer.flush()


def _render_output(report: Report, fmt: str, min_sev: Severity) -> None:
    """Render the report according to selected format and minimum severity."""
    min_rank = _SEV_ORDER[min_sev]
    filtered_evidence = [e for e in report.evidence if _SEV_ORDER[e.severity] >= min_rank]

    if fmt == "json":
        report_display = report.model_copy(update={"evidence": filtered_evidence})
        _safe_print(report_display.model_dump_json(indent=2))
    elif fmt == "markdown":
        md = _render_markdown(report, filtered_evidence)
        _safe_print(md)
    else:
        _print_report_text(report, filtered_evidence)


def _print_report_text(report: Report, evidence: list[Evidence]) -> None:
    """Render a rich terminal report grouped by type with top summary."""
    summary = _generate_one_line_summary(report, evidence)
    style = _DECISION_STYLE[report.decision]

    console.print(f"[bold]Summary:[/bold] [{style}]{escape(summary)}[/{style}]\n")

    decision_text = f"[{style}]{report.decision.value}[/{style}]"
    console.print(
        Panel(
            f"Decision: {decision_text}\n"
            f"Total evidence items: {len(report.evidence)} "
            f"(showing {len(evidence)})\n"
            f"Old: {escape(report.old_release.name)}@{escape(report.old_release.version)} "
            f"(published {report.old_release.published_at.strftime('%Y-%m-%d')})\n"
            f"New: {escape(report.new_release.name)}@{escape(report.new_release.version)} "
            f"(published {report.new_release.published_at.strftime('%Y-%m-%d')})",
            title="[bold]Release Sentinel Report[/bold]",
            border_style=style,
        )
    )

    if evidence:
        grouped = _group_evidence(evidence)
        for group_name, items in grouped.items():
            console.print(f"\n[bold cyan]● {escape(group_name)}[/bold cyan]")
            table = Table(
                "Severity",
                "ID",
                "File",
                "Explanation",
                box=box.SIMPLE_HEAD,
                show_header=True,
                header_style="bold",
            )
            for ev in items:
                sev_style = _SEVERITY_STYLE.get(ev.severity.value, "")
                table.add_row(
                    f"[{sev_style}]{ev.severity.value}[/{sev_style}]",
                    escape(ev.id),
                    escape(ev.file or "—"),
                    escape(ev.explanation[:120] + ("…" if len(ev.explanation) > 120 else "")),
                )
            console.print(table)
    else:
        console.print("[green]No suspicious evidence detected at this severity level.[/green]\n")

    # Limitations
    console.print("\n[bold dim]Limitations[/bold dim]")
    for lim in report.limitations:
        console.print(f"  [dim]• {escape(lim)}[/dim]")
    console.print()


def _render_markdown(report: Report, evidence: list[Evidence]) -> str:
    """Format report as GitHub Flavored Markdown suitable for a PR comment."""
    decision_icons = {
        Decision.ALLOW: "✅",
        Decision.WARN: "⚠️",
        Decision.BLOCK: "🚫",
    }
    icon = decision_icons.get(report.decision, "ℹ️")
    summary = sanitize_untrusted_text(
        _generate_one_line_summary(report, evidence),
        max_length=MAX_FIELD_CHARS,
    )
    pkg_name = render_code_span(report.new_release.name)
    old_ver = render_code_span(report.old_release.version)
    new_ver = render_code_span(report.new_release.version)

    lines: list[str] = [
        f"## {icon} Release Sentinel: {report.decision.value}",
        "",
        f"> **Summary**: {summary}",
        "",
        "| Detail | Value |",
        "|---|---|",
        f"| **Package** | {pkg_name} |",
        (
            f"| **Old Version** | {old_ver} "
            f"({report.old_release.published_at.strftime('%Y-%m-%d')}) |"
        ),
        (
            f"| **New Version** | {new_ver} "
            f"({report.new_release.published_at.strftime('%Y-%m-%d')}) |"
        ),
        f"| **Decision** | **{report.decision.value}** |",
        f"| **As-Of** | `{report.as_of.isoformat()}` |",
        "",
    ]

    if evidence:
        grouped = _group_evidence(evidence)
        for group_name, items in grouped.items():
            lines.append(f"### {group_name}")
            lines.append("| Severity | ID | File | Explanation |")
            lines.append("|---|---|---|---|")
            for ev in items:
                file_str = render_code_span(ev.file) if ev.file else "—"
                id_str = render_code_span(ev.id)
                clean_exp = sanitize_untrusted_text(ev.explanation, max_length=MAX_FIELD_CHARS)
                lines.append(f"| **{ev.severity.value}** | {id_str} | {file_str} | {clean_exp} |")
            lines.append("")
    else:
        lines.append("*No suspicious evidence detected at this severity level.*")
        lines.append("")

    lines.append("<details>")
    lines.append("<summary><strong>Limitations & Scope</strong></summary>")
    lines.append("")
    for lim in report.limitations:
        clean_lim = sanitize_untrusted_text(
            lim, max_length=MAX_FIELD_CHARS, collapse_newlines=True
        )
        lines.append(f"- {clean_lim}")
    lines.append("</details>")

    return cap_comment_size("\n".join(lines))


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _parse_as_of(s: str) -> datetime:
    """Parse an ISO 8601 string, defaulting to UTC if no timezone given."""
    s = s.replace("Z", "+00:00")
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)



def format_lockfile_markdown(report: LockfileDiffReport) -> str:
    """Format a LockfileDiffReport as a GitHub PR markdown comment."""
    lines = [
        "<!-- release-sentinel-pr-comment -->",
        "## Release Sentinel Security Gate",
        "",
    ]
    if report.decision == Decision.BLOCK:
        icon = "🛑"
        verdict = "**BLOCK**"
    elif report.decision == Decision.WARN:
        icon = "⚠️"
        verdict = "**WARN**"
    else:
        icon = "✅"
        verdict = "**ALLOW**"

    flagged = [p for p in report.package_results if p["decision"] in ("BLOCK", "WARN")]
    clean = [p for p in report.package_results if p["decision"] == "ALLOW"]

    if report.has_budget_exceeded:
        summary = f"{icon} {verdict} — Analysis exceeded safety budget; gate failed closed."
    elif report.decision == Decision.BLOCK:
        summary = (
            f"{icon} {verdict} — {len(flagged)} package(s) blocked out of "
            f"{report.total_packages_scanned} scanned."
        )
    elif report.decision == Decision.WARN:
        summary = (
            f"{icon} {verdict} — {len(flagged)} package(s) flagged with warnings out of "
            f"{report.total_packages_scanned} scanned."
        )
    else:
        summary = (
            f"{icon} {verdict} — All {report.total_packages_scanned} changed package(s) "
            f"passed security checks."
        )

    lines.append(f"**Verdict:** {summary}")
    lines.append("")

    if flagged:
        lines.append("### Flagged Packages")
        lines.append("")
        lines.append(
            "| Package | Version Change | Decision | Top Evidence | Why It Matters | Legitimate Explanation |"  # noqa: E501
        )
        lines.append("| :--- | :--- | :---: | :--- | :--- | :--- |")
        for pkg in flagged:
            p_name = render_code_span(pkg["package"])
            old_v = pkg["old_version"] or "(new)"
            new_v = pkg["new_version"] or "(none)"
            v_change = f"{render_code_span(old_v)} → {render_code_span(new_v)}"
            dec_str = "🛑 BLOCK" if pkg["decision"] == "BLOCK" else "⚠️ WARN"
            top_ev_raw = pkg["evidence"][0] if pkg["evidence"] else "inspection_failed"
            top_ev = render_code_span(top_ev_raw)
            details = pkg.get("evidence_details", [])
            why_raw = details[0]["explanation"] if details else "Suspicious behavior detected."
            why = sanitize_untrusted_text(why_raw, max_length=MAX_FIELD_CHARS)
            legit_raw = (
                details[0].get("legitimate_use_note", "No legitimate explanation registered.")
                if details
                else "No legitimate explanation registered."
            )
            legit = sanitize_untrusted_text(legit_raw, max_length=MAX_FIELD_CHARS)
            lines.append(
                f"| {p_name} | {v_change} | {dec_str} | {top_ev} | {why} | {legit} |"
            )
        lines.append("")

    if clean:
        lines.append("<details>")
        lines.append(f"<summary><b>Inspected Packages (ALLOW) ({len(clean)})</b></summary>")
        lines.append("")
        lines.append("| Package | Version Change | Decision | Notes |")
        lines.append("| :--- | :--- | :---: | :--- |")
        for pkg in clean:
            p_name = render_code_span(pkg["package"])
            old_v = pkg["old_version"] or "(new)"
            new_v = pkg["new_version"] or "(none)"
            v_change = f"{render_code_span(old_v)} → {render_code_span(new_v)}"
            notes = (
                ", ".join(render_code_span(e) for e in pkg["evidence"])
                if pkg["evidence"]
                else "Clean"
            )
            lines.append(f"| {p_name} | {v_change} | ✅ ALLOW | {notes} |")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    lines.append("### Limitations & Scope")
    lines.append("")
    if report.limitations:
        for lim in report.limitations:
            clean_lim = sanitize_untrusted_text(
                lim, max_length=MAX_FIELD_CHARS, collapse_newlines=True
            )
            lines.append(f"- {clean_lim}")
    else:
        lines.append(
            "- JavaScript/TypeScript source scanned with static heuristics; dynamic evasion is possible."  # noqa: E501
        )
        lines.append(
            "- Every changed lockfile entry (including transitive dependencies) is scanned."
        )
    lines.append("")
    return cap_comment_size("\n".join(lines))


def print_lockfile_text(report: LockfileDiffReport, quiet: bool = False) -> None:
    """Format and print LockfileDiffReport to terminal using rich."""
    if quiet:
        summary = f"{report.decision.name}: {report.total_packages_scanned} packages scanned"
        if report.has_budget_exceeded:
            summary += " (budget exceeded)"
        console.print(summary)
        return

    table = Table(
        title=f"Release Sentinel Lockfile Diff Report ({escape(report.base_source)} → {escape(report.head_source)})",  # noqa: E501
        box=box.ROUNDED,
    )
    table.add_column("Package", style="bold")
    table.add_column("Old Version")
    table.add_column("New Version")
    table.add_column("Decision")
    table.add_column("Evidence")

    for pkg in report.package_results:
        dec = Decision[pkg["decision"]]
        style = _DECISION_STYLE.get(dec, "white")
        ev_str = ", ".join(pkg["evidence"]) if pkg["evidence"] else "—"
        table.add_row(
            escape(str(pkg["package"])),
            escape(str(pkg["old_version"] or "(new)")),
            escape(str(pkg["new_version"] or "(none)")),
            f"[{style}]{dec.name}[/{style}]",
            escape(ev_str),
        )

    console.print(table)
    if report.limitations:
        console.print("[dim]Limitations:[/dim]")
        for lim in report.limitations:
            console.print(f"  [dim]- {escape(lim)}[/dim]")

    verdict_style = _DECISION_STYLE.get(report.decision, "white")
    console.print(
        Panel(
            f"Verdict: [{verdict_style}]{report.decision.name}[/{verdict_style}] "
            f"({report.total_packages_scanned} packages analyzed)",
            expand=False,
        )
    )


@app.command()
def check(
    base: Annotated[
        Path | None,
        typer.Option("--base", help="Path to base (old) package-lock.json or repo dir."),
    ] = None,
    head: Annotated[
        Path | None,
        typer.Option(
            "--head",
            help="Path to head (new) package-lock.json or repo dir (default: current dir).",
        ),
    ] = None,
    base_ref: Annotated[
        str | None,
        typer.Option(
            "--base-ref",
            help="Git ref to read base package-lock.json from (e.g. origin/main, HEAD~1).",
        ),
    ] = None,
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: text | json | markdown."),
    ] = "text",
    fail_on: Annotated[
        str,
        typer.Option("--fail-on", help="Gate failure condition: block | warn | never (default: block)."),  # noqa: E501
    ] = "block",
    policy: Annotated[
        Path | None,
        typer.Option("--policy", help="Path to custom policy TOML file."),
    ] = None,
    profile: Annotated[
        str,
        typer.Option(
            "--profile",
            help="Policy profile: 'default' (low-noise) or 'strict' (frozen v1.4 research policy).",
        ),
    ] = "default",
    experimental_hollow: Annotated[
        bool,
        typer.Option("--experimental-hollow", help="Enable experimental hollow release detection."),
    ] = False,
    max_packages: Annotated[
        int,
        typer.Option("--max-packages", help="Maximum packages to scan before capping (default: 200)."),  # noqa: E501
    ] = DEFAULT_MAX_PACKAGES,
    as_of: Annotated[
        str | None,
        typer.Option("--as-of", help="Cut-off timestamp in ISO 8601 format (default: now)."),
    ] = None,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Suppress non-essential progress output."),
    ] = False,
    cache_dir: Annotated[
        Path | None,
        typer.Option("--cache-dir", help="Cache directory (default: ~/.cache/release_sentinel)."),
    ] = None,
    json_output_file: Annotated[
        Path | None,
        typer.Option("--json-output-file", help="Path to write complete JSON report to."),
    ] = None,
) -> None:
    """Audit dependency changes in an npm package-lock.json diff against security policy.

    Exit codes:
      0: Pass (policy gate satisfied)
      1: Gate failed (BLOCK, or WARN when --fail-on warn)
      2: Usage, input, or internal error
    """
    fail_on_clean = fail_on.strip().lower()
    if fail_on_clean not in ("block", "warn", "never"):
        console.print(
            f"[bold red]Error:[/] Invalid --fail-on option '{escape(fail_on)}'. Choose from: block, warn, never."  # noqa: E501
        )
        raise typer.Exit(code=2)

    format_clean = format.strip().lower()
    if format_clean not in ("text", "json", "markdown"):
        console.print(
            f"[bold red]Error:[/] Invalid --format option '{escape(format)}'. Choose from: text, json, markdown."  # noqa: E501
        )
        raise typer.Exit(code=2)

    as_of_dt = _parse_as_of(as_of) if as_of else datetime.now(UTC)
    effective_cache = cache_dir or _DEFAULT_CACHE_DIR
    pol = load_policy(policy, profile=profile)

    try:
        if not base and not base_ref:
            console.print(
                "[bold red]Error:[/] Either --base <path> or --base-ref <ref> must be specified."
            )
            raise typer.Exit(code=2)

        if base:
            base_content, base_source = read_lockfile_from_path(base)

        target_head = head or Path("package-lock.json")
        head_content, head_source = read_lockfile_from_path(target_head)

        if base_ref:
            try:
                repo_root = get_git_repo_root()
            except LockfileError as exc:
                console.print(f"[bold red]Error:[/] {exc}")
                raise typer.Exit(code=2) from exc

            resolved_head = target_head.resolve()
            if resolved_head.is_dir():
                resolved_head = resolved_head / "package-lock.json"

            try:
                rel_lockfile_path = resolved_head.relative_to(repo_root).as_posix()
            except ValueError as err:
                console.print(
                    f"[bold red]Error:[/] Head lockfile '{target_head}' is outside git repo."
                )
                raise typer.Exit(code=2) from err

            base_content = read_lockfile_from_git(
                base_ref,
                lockfile_rel_path=rel_lockfile_path,
                repo_dir=repo_root,
            )
            base_source = f"git:{base_ref}:{rel_lockfile_path}"

        with NpmRegistryClient(cache_dir=effective_cache) as client:
            report = scan_lockfile_diff(
                base_content=base_content,
                head_content=head_content,
                base_source=base_source,
                head_source=head_source,
                policy=pol,
                max_packages=max_packages,
                registry_client=client,
                experimental_hollow=experimental_hollow,
                as_of=as_of_dt,
            )

    except UnsupportedLockfileError as exc:
        console.print(f"[bold red]Error:[/] {escape(str(exc))}")
        raise typer.Exit(code=2) from exc
    except LockfileParseError as exc:
        console.print(f"[bold red]Error:[/] {escape(str(exc))}")
        raise typer.Exit(code=2) from exc
    except LockfileError as exc:
        console.print(f"[bold red]Error:[/] {escape(str(exc))}")
        raise typer.Exit(code=2) from exc
    except FileNotFoundError as exc:
        console.print(f"[bold red]Error:[/] {escape(str(exc))}")
        raise typer.Exit(code=2) from exc
    except typer.Exit:
        raise
    except Exception as exc:
        console.print(f"[bold red]Internal error:[/] {escape(str(exc))}")
        raise typer.Exit(code=2) from exc

    # Write optional json report file
    if json_output_file is not None:
        import dataclasses
        json_output_file.write_text(
            json.dumps(dataclasses.asdict(report), indent=2, default=str),
            encoding="utf-8",
        )

    # Render output
    if format_clean == "json":
        import dataclasses
        _safe_print(json.dumps(dataclasses.asdict(report), indent=2, default=str))
    elif format_clean == "markdown":
        md = format_lockfile_markdown(report)
        _safe_print(md)
    else:
        print_lockfile_text(report, quiet=quiet)

    # Exit code per fail_on
    gate_failed = False
    if fail_on_clean == "block":
        gate_failed = (report.decision == Decision.BLOCK)
    elif fail_on_clean == "warn":
        gate_failed = (report.decision in (Decision.BLOCK, Decision.WARN))
    elif fail_on_clean == "never":
        gate_failed = False

    if gate_failed:
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


@app.command()
def demo(
    package: Annotated[str | None, typer.Argument(help="Package name (default: axios)")] = None,
    old_version: Annotated[str | None, typer.Argument(help="Baseline version (default: 1.14.0)")] = None,  # noqa: E501
    new_version: Annotated[str | None, typer.Argument(help="New version (default: 1.14.1)")] = None,  # noqa: E501
    pair: Annotated[
        tuple[str, str, str] | None,
        typer.Option(
            "--pair",
            help="Package, old, new version triplet (e.g. --pair axios 1.14.0 1.14.1)",
        ),
    ] = None,
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: markdown | text | json"),
    ] = "markdown",
    samples_root: Annotated[
        Path | None,
        typer.Option("--samples-root", help="Datadog samples root (defaults to RS_SAMPLES_ROOT)"),
    ] = None,
    policy: Annotated[Path | None, typer.Option("--policy", help="Custom policy TOML")] = None,
    profile: Annotated[
        str,
        typer.Option(
            "--profile",
            help="Policy profile: 'default' (low-noise) or 'strict' (frozen v1.4 research policy).",
        ),
    ] = "default",
    cache_dir: Annotated[Path | None, typer.Option("--cache-dir", help="Cache directory")] = None,
) -> None:
    """Run an in-memory evaluation demo on an encrypted dataset sample (never executes code)."""
    from release_sentinel.extractor import extract_release_in_memory
    from release_sentinel.zip_loader import load_zip_release

    if pair:
        if len(pair) != 3:
            console.print(
                "[bold red]Error:[/] --pair requires 3 arguments: <pkg> <old_version> <new_version>"  # noqa: E501
            )
            raise typer.Exit(code=2)
        p_name, old_v, new_v = pair[0], pair[1], pair[2]
    elif package and old_version and new_version:
        p_name, old_v, new_v = package, old_version, new_version
    else:
        p_name, old_v, new_v = "axios", "1.14.0", "1.14.1"

    eff_samples_root = get_samples_root(samples_root)
    if not eff_samples_root.exists():
        console.print(
            f"[bold red]Error:[/] Samples root directory not found: {eff_samples_root}. "
            "Please set the RS_SAMPLES_ROOT environment variable pointing to the Datadog dataset. "
            "See docs/REPRODUCING.md."
        )
        raise typer.Exit(code=2)

    eff_cache = cache_dir or _DEFAULT_CACHE_DIR
    pol = load_policy(policy, profile=profile)

    try:
        # Locate encrypted sample zip under eff_samples_root
        candidates = list(eff_samples_root.glob(f"**/{p_name}/**/{new_v}/*.zip"))
        if not candidates:
            unscoped = p_name.split("/")[-1]
            candidates = list(eff_samples_root.glob(f"**/{unscoped}/**/{new_v}/*.zip"))
        if not candidates:
            candidates = list(eff_samples_root.glob(f"**/*{p_name}*{new_v}*.zip"))
        if not candidates:
            console.print(
                f"[bold red]Error:[/] Encrypted sample not found for {p_name}@{new_v} in {eff_samples_root}"  # noqa: E501
            )
            raise typer.Exit(code=2)
        zip_path = candidates[0]

        # Load new release in-memory from encrypted sample (Rule 1, 2, 7)
        rc_new = load_zip_release(zip_path, password=b"infected")

        # Baseline: try from sample, else download from cache/registry
        rc_old = None
        with NpmRegistryClient(cache_dir=eff_cache) as client:
            try:
                old_tar = client.download_tarball(name=p_name, version=old_v)
                rc_old = extract_release_in_memory(old_tar)
            except Exception:
                # Try finding old version in samples root
                old_candidates = list(eff_samples_root.glob(f"**/{p_name}/**/{old_v}/*.zip"))
                if old_candidates:
                    rc_old = load_zip_release(old_candidates[0], password=b"infected")

            cfg = ExtractionConfig()
            evidence = analyze_release(
                new=rc_new,
                baseline=rc_old,
                policy=pol,
                config=cfg,
                registry_client=client,
                samples_root=eff_samples_root,
                as_of=datetime.now(UTC),
            )
            decision, lims = decide(evidence, policy=pol, is_full_scan=rc_old is None)

        rep = Report(
            old_release=ReleaseRef(name=p_name, version=old_v, published_at=datetime.now(UTC)),
            new_release=ReleaseRef(name=p_name, version=new_v, published_at=datetime.now(UTC)),
            decision=decision,
            evidence=evidence,
            as_of=datetime.now(UTC),
            generated_at=datetime.now(UTC),
            limitations=lims,
        )
        _render_output(rep, format, Severity.LOW)
    except typer.Exit:
        raise
    except Exception as exc:
        console.print(f"[bold red]Demo error:[/] {escape(str(exc))}")
        raise typer.Exit(code=2) from exc


if __name__ == "__main__":
    app()

