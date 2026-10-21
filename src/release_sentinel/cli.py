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

import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from release_sentinel import __version__
from release_sentinel.differ import compare_releases
from release_sentinel.engine import decide
from release_sentinel.extractor import ExtractionConfig, extract_release
from release_sentinel.models import Decision, Evidence, Report, Severity
from release_sentinel.registry import NpmRegistryClient, RegistryError

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
    """Compare two versions of an npm package and return a security gate decision."""
    # --- Resolve as_of ---
    if as_of is not None:
        try:
            as_of_dt = _parse_as_of(as_of)
        except ValueError as exc:
            console.print(f"[red]Invalid --as-of value: {exc}[/red]")
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
            f"  Package : [cyan]{package}[/cyan]\n"
            f"  Old     : [cyan]{old_version}[/cyan]\n"
            f"  New     : [cyan]{new_version}[/cyan]\n"
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
            max_files=max_files,
            max_size=max_size,
            quiet=quiet,
            experimental_hollow=experimental_hollow,
            samples_root=samples_root,
        )
    except RegistryError as exc:
        console.print(f"[red]Registry error: {exc}[/red]")
        raise typer.Exit(code=2) from exc
    except Exception as exc:
        console.print(f"[red]Unexpected error: {exc}[/red]")
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

            # --- Diff ---
            if not quiet:
                console.print("[dim]Comparing releases…[/dim]")
            evidence = compare_releases(
                old_result, new_result, experimental_hollow=experimental_hollow
            )

        # --- Decide ---
        decision, limitations = decide(
            evidence,
            policy_path=policy_path,
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


def _render_output(report: Report, fmt: str, min_sev: Severity) -> None:
    """Render the report according to selected format and minimum severity."""
    min_rank = _SEV_ORDER[min_sev]
    filtered_evidence = [e for e in report.evidence if _SEV_ORDER[e.severity] >= min_rank]

    if fmt == "json":
        report_display = report.model_copy(update={"evidence": filtered_evidence})
        print(report_display.model_dump_json(indent=2))
    elif fmt == "markdown":
        md = _render_markdown(report, filtered_evidence)
        print(md)
    else:
        _print_report_text(report, filtered_evidence)


def _print_report_text(report: Report, evidence: list[Evidence]) -> None:
    """Render a rich terminal report grouped by type with top summary."""
    summary = _generate_one_line_summary(report, evidence)
    style = _DECISION_STYLE[report.decision]

    console.print(f"[bold]Summary:[/bold] [{style}]{summary}[/{style}]\n")

    decision_text = f"[{style}]{report.decision.value}[/{style}]"
    console.print(
        Panel(
            f"Decision: {decision_text}\n"
            f"Total evidence items: {len(report.evidence)} "
            f"(showing {len(evidence)})\n"
            f"Old: {report.old_release.name}@{report.old_release.version} "
            f"(published {report.old_release.published_at.strftime('%Y-%m-%d')})\n"
            f"New: {report.new_release.name}@{report.new_release.version} "
            f"(published {report.new_release.published_at.strftime('%Y-%m-%d')})",
            title="[bold]Release Sentinel Report[/bold]",
            border_style=style,
        )
    )

    if evidence:
        grouped = _group_evidence(evidence)
        for group_name, items in grouped.items():
            console.print(f"\n[bold cyan]● {group_name}[/bold cyan]")
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
                    ev.id,
                    ev.file or "—",
                    ev.explanation[:120] + ("…" if len(ev.explanation) > 120 else ""),
                )
            console.print(table)
    else:
        console.print("[green]No suspicious evidence detected at this severity level.[/green]\n")

    # Limitations
    console.print("\n[bold dim]Limitations[/bold dim]")
    for lim in report.limitations:
        console.print(f"  [dim]• {lim}[/dim]")
    console.print()


def _render_markdown(report: Report, evidence: list[Evidence]) -> str:
    """Format report as GitHub Flavored Markdown suitable for a PR comment."""
    decision_icons = {
        Decision.ALLOW: "✅",
        Decision.WARN: "⚠️",
        Decision.BLOCK: "🚫",
    }
    icon = decision_icons.get(report.decision, "ℹ️")
    summary = _generate_one_line_summary(report, evidence)

    lines: list[str] = [
        f"## {icon} Release Sentinel: {report.decision.value}",
        "",
        f"> **Summary**: {summary}",
        "",
        "| Detail | Value |",
        "|---|---|",
        f"| **Package** | `{report.new_release.name}` |",
        (
            f"| **Old Version** | `{report.old_release.version}` "
            f"({report.old_release.published_at.strftime('%Y-%m-%d')}) |"
        ),
        (
            f"| **New Version** | `{report.new_release.version}` "
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
                file_str = f"`{ev.file}`" if ev.file else "—"
                clean_exp = ev.explanation.replace("\n", " ").replace("|", "\\|")
                lines.append(f"| **{ev.severity.value}** | `{ev.id}` | {file_str} | {clean_exp} |")
            lines.append("")
    else:
        lines.append("*No suspicious evidence detected at this severity level.*")
        lines.append("")

    lines.append("<details>")
    lines.append("<summary><strong>Limitations & Scope</strong></summary>")
    lines.append("")
    for lim in report.limitations:
        lines.append(f"- {lim}")
    lines.append("</details>")

    return "\n".join(lines)


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


if __name__ == "__main__":
    app()

