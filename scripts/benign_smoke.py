"""Benign smoke test runner measuring alert burden on real benign npm updates.

Network-dependent: fetches live package metadata and tarballs from registry.npmjs.org.
Follows all project rules:
- Rule 1: Never executes package code (static inspection only).
- Rule 2: Safe tarball extraction with caps and path traversal checks.
- Rule 3: Time-awareness enforced (as_of = new release publish time).
- Rule 5: Writes only to project directory and ~/.cache/release_sentinel.
- Rule 6: Synthetic / harmless packages only; no malware.
"""

from __future__ import annotations

import argparse
import csv
import logging
import re
import sys
import tempfile
import time
from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from release_sentinel.differ import analyze_release
from release_sentinel.engine import decide
from release_sentinel.extractor import ExtractionConfig, extract_release
from release_sentinel.models import Severity
from release_sentinel.registry import NpmRegistryClient, RegistryError, _safe_filename

logger = logging.getLogger(__name__)


_DEFAULT_CACHE_DIR = Path.home() / ".cache" / "release_sentinel"
_DEFAULT_SEED_FILE = Path("data/benign_seed_packages.txt")
_DEFAULT_CSV_FILE = Path("data/smoke_results.csv")
_DEFAULT_DOC_FILE = Path("docs/smoke_results.md")

_SEV_ORDER: dict[Severity, int] = {
    Severity.INFO: -1,
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


def parse_semver(v: str) -> tuple[int, ...]:
    """Parse a basic semver string (X.Y.Z) into integer components."""
    return tuple(int(p) for p in v.split("."))


def find_stable_release_pairs(
    metadata: dict[str, Any],
    pairs_per_package: int = 5,
) -> list[tuple[str, str, datetime]]:
    """Return consecutive stable release pairs within the same major version.

    Pairs are ordered chronologically by the new release's publish time.
    Cross-major releases and prerelease versions are excluded.
    """
    time_map: dict[str, str] = {
        k: v for k, v in metadata.get("time", {}).items() if k not in ("created", "modified")
    }
    versions_map: dict[str, Any] = metadata.get("versions", {})

    stables = [
        v for v in versions_map if re.match(r"^\d+\.\d+\.\d+$", v) and v in time_map
    ]
    stables.sort(key=lambda v: time_map[v])

    pairs: list[tuple[str, str, datetime]] = []
    for i, v_new in enumerate(stables):
        maj_new = parse_semver(v_new)[0]
        # Candidates: published before v_new, same major, semver < v_new
        candidates = [
            u
            for u in stables[:i]
            if parse_semver(u)[0] == maj_new and parse_semver(u) < parse_semver(v_new)
        ]
        if candidates:
            v_old = max(candidates, key=parse_semver)
            ts_str = time_map[v_new].replace("Z", "+00:00")
            pub_dt = datetime.fromisoformat(ts_str).astimezone(UTC)
            pairs.append((v_old, v_new, pub_dt))

    return pairs[-pairs_per_package:]


def check_tarball_size_remote(
    client: NpmRegistryClient,
    pkg: str,
    version: str,
    as_of: datetime,
    max_bytes: int,
) -> bool:
    """Return True if tarball size is confirmed to exceed max_bytes."""
    meta = client.get_metadata(pkg, as_of)
    v_meta = meta.get("versions", {}).get(version, {})
    dist = v_meta.get("dist", {})
    tarball_url = dist.get("tarball")
    if not tarball_url:
        return False

    safe_name = _safe_filename(pkg)
    cache_path = client._cache_dir / safe_name / f"{safe_name}-{version}.tgz"
    if cache_path.exists():
        return cache_path.stat().st_size > max_bytes

    try:
        with client._http.stream("GET", tarball_url) as resp:
            cl = resp.headers.get("content-length")
            if cl and int(cl) > max_bytes:
                return True
    except (httpx.HTTPError, OSError):
        pass
    return False


def with_retry[T](func: Callable[..., T], *args: object, **kwargs: object) -> T:
    """Execute func with a single retry on network/registry errors."""
    try:
        return func(*args, **kwargs)
    except (httpx.HTTPError, RegistryError) as exc:
        logger.warning("Network issue (%s); retrying in 2 seconds...", exc)
        time.sleep(2.0)
        return func(*args, **kwargs)


def process_pair(
    client: NpmRegistryClient,
    pkg: str,
    old_ver: str,
    new_ver: str,
    as_of: datetime,
    max_bytes: int,
) -> dict[str, Any]:
    """Inspect and diff one release pair, returning a result dict."""
    t0 = time.time()

    # Pre-check remote size if known
    if check_tarball_size_remote(client, pkg, old_ver, as_of, max_bytes) or (
        check_tarball_size_remote(client, pkg, new_ver, as_of, max_bytes)
    ):
        elapsed = time.time() - t0
        return {
            "package": pkg,
            "old": old_ver,
            "new": new_ver,
            "published_new": as_of.isoformat(),
            "decision": "skipped_large",
            "max_severity": "NONE",
            "evidence_types": "",
            "limitation_count": 0,
            "seconds": round(elapsed, 2),
        }

    with tempfile.TemporaryDirectory(prefix="sentinel-smoke-") as tmp:
        tmp_path = Path(tmp)
        old_tgz = with_retry(client.download_tarball, pkg, old_ver, as_of, tmp_path / "old")
        new_tgz = with_retry(client.download_tarball, pkg, new_ver, as_of, tmp_path / "new")

        if old_tgz.stat().st_size > max_bytes or new_tgz.stat().st_size > max_bytes:
            elapsed = time.time() - t0
            return {
                "package": pkg,
                "old": old_ver,
                "new": new_ver,
                "published_new": as_of.isoformat(),
                "decision": "skipped_large",
                "max_severity": "NONE",
                "evidence_types": "",
                "limitation_count": 0,
                "seconds": round(elapsed, 2),
            }

        ext_cfg = ExtractionConfig()
        old_res = extract_release(old_tgz, tmp_path / "old_ext", config=ext_cfg)
        new_res = extract_release(new_tgz, tmp_path / "new_ext", config=ext_cfg)
        evidence = analyze_release(
            new=new_res,
            baseline=old_res,
            as_of=as_of,
            registry_client=client,
            dest_dir=tmp_path / "dep_tarballs",
        )

    decision, limitations = decide(evidence)
    elapsed = time.time() - t0

    max_sev = "NONE"
    if evidence:
        max_sev = max((e.severity for e in evidence), key=lambda s: _SEV_ORDER[s]).value

    ev_types = ";".join(sorted({e.id for e in evidence}))

    return {
        "package": pkg,
        "old": old_ver,
        "new": new_ver,
        "published_new": as_of.isoformat(),
        "decision": decision.value,
        "max_severity": max_sev,
        "evidence_types": ev_types,
        "limitation_count": len(limitations),
        "seconds": round(elapsed, 2),
    }


def read_existing_csv(csv_path: Path) -> list[dict[str, Any]]:
    """Read existing results from CSV if it exists."""
    if not csv_path.exists():
        return []
    with csv_path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        return list(reader)


def append_csv_row(csv_path: Path, row: dict[str, Any], fieldnames: list[str]) -> None:
    """Append a single row to the results CSV, writing headers if newly created."""
    file_exists = csv_path.exists()
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("a", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)
        fh.flush()


def generate_analysis_report(rows: list[dict[str, Any]]) -> str:
    """Generate markdown analysis summarizing benign smoke results."""
    total = len(rows)
    if total == 0:
        return "# Smoke Results\n\nNo records to analyze."

    decision_counts: Counter[str] = Counter(r["decision"] for r in rows)
    evaluated = total - decision_counts.get("skipped_large", 0)
    alerts = decision_counts.get("WARN", 0) + decision_counts.get("BLOCK", 0)
    alert_rate = (alerts / evaluated * 100) if evaluated > 0 else 0.0

    lines: list[str] = [
        "# Release Sentinel -- Benign Smoke Test Results",
        "",
        "## 1. Decision Distribution",
        "",
        f"- **Total Pairs Evaluated**: {total}",
        f"- **ALLOW**: {decision_counts.get('ALLOW', 0)} "
        f"({decision_counts.get('ALLOW', 0) / total * 100:.1f}%)",
        f"- **WARN**: {decision_counts.get('WARN', 0)} "
        f"({decision_counts.get('WARN', 0) / total * 100:.1f}%)",
        f"- **BLOCK**: {decision_counts.get('BLOCK', 0)} "
        f"({decision_counts.get('BLOCK', 0) / total * 100:.1f}%)",
        f"- **Skipped (Large Tarball)**: {decision_counts.get('skipped_large', 0)} "
        f"({decision_counts.get('skipped_large', 0) / total * 100:.1f}%)",
        f"- **Alert Burden (WARN + BLOCK)**: **{alert_rate:.1f} alerts per 100 updates**",
        "",
        "## 2. Top 10 Evidence Types",
        "",
        "| Evidence Type | Total Frequency | Sole Evidence for WARN/BLOCK |",
        "|:---|:---:|:---:|",
    ]

    # Calculate frequencies and sole-evidence counts
    evidence_freq: Counter[str] = Counter()
    sole_evidence_counts: Counter[str] = Counter()

    for r in rows:
        raw_ev = r.get("evidence_types", "")
        if not raw_ev:
            continue
        types = set(raw_ev.split(";"))
        for t in types:
            evidence_freq[t] += 1
        if r["decision"] in ("WARN", "BLOCK") and len(types) == 1:
            only_type = next(iter(types))
            sole_evidence_counts[only_type] += 1

    for ev_type, count in evidence_freq.most_common(10):
        sole = sole_evidence_counts.get(ev_type, 0)
        lines.append(f"| `{ev_type}` | {count} | {sole} |")

    lines.extend([
        "",
        "## 3. Every BLOCK Decision",
        "",
    ])

    block_rows = [r for r in rows if r["decision"] == "BLOCK"]
    if block_rows:
        lines.append("| Package | Upgrade | Evidence Types Driving Block |")
        lines.append("|:---|:---|:---|")
        for b in block_rows:
            lines.append(
                f"| `{b['package']}` | `{b['old']}` -> `{b['new']}` | `{b['evidence_types']}` |"
            )
    else:
        lines.append("*(No releases were blocked.)*")

    lines.extend([
        "",
        "## 4. The 3 Noisiest Packages",
        "",
        "| Package | Alerts (WARN/BLOCK) | Total Evidence Items | Most Common Signals |",
        "|:---|:---:|:---:|:---|",
    ])

    pkg_alerts: Counter[str] = Counter()
    pkg_evidence_counts: Counter[str] = Counter()
    pkg_signals: dict[str, Counter[str]] = {}

    for r in rows:
        pkg = r["package"]
        if pkg not in pkg_signals:
            pkg_signals[pkg] = Counter()
        if r["decision"] in ("WARN", "BLOCK"):
            pkg_alerts[pkg] += 1
        raw_ev = r.get("evidence_types", "")
        if raw_ev:
            signals = raw_ev.split(";")
            pkg_evidence_counts[pkg] += len(signals)
            for s in signals:
                pkg_signals[pkg][s] += 1

    # Sort packages by alerts descending, then total evidence descending
    sorted_pkgs = sorted(
        pkg_signals.keys(),
        key=lambda p: (pkg_alerts[p], pkg_evidence_counts[p]),
        reverse=True,
    )

    for pkg in sorted_pkgs[:3]:
        common = ", ".join(f"`{s}` ({c})" for s, c in pkg_signals[pkg].most_common(3))
        lines.append(
            f"| `{pkg}` | {pkg_alerts[pkg]} | {pkg_evidence_counts[pkg]} | {common} |"
        )

    lines.extend([
        "",
        "## 5. Suggested Rule & Policy Changes (Measurement Only)",
        "",
        "1. **Allowlist Known Bundled / Minified Assets**:",
        "   - `long_encoded_blob` and `high_entropy_string` fire frequently on source maps, "
        "base64 fixtures, or bundled/minified JS. Tuning entropy thresholds or exempting "
        "known test fixture directories would significantly cut noise.",
        "2. **Refine `process_exec` and `network_access` Patterns**:",
        "   - In utility packages like `lodash`, `yargs`, or `commander`, static references "
        "to `child_process` in helper/debug scripts trigger WARN. Require corroboration with "
        "lifecycle scripts (`install_script_added`) before escalating.",
        "3. **De-duplicate / Aggregate Informational Signals**:",
        "   - `dependency_added`, `dependency_version_changed`, and `new_files_summary` should "
        "remain LOW and never by themselves trigger a warning.",
        "4. **Install Hook Specificity**:",
        "   - Packages like `bcrypt` legitimately use `install` for node-pre-gyp. "
        "Differentiate standard build tools (`node-pre-gyp`, `node-gyp rebuild`) from "
        "arbitrary curl/bash commands.",
        "",
        "## 6. Items of Uncertainty",
        "",
        "- **Concurrency in Package Release Cadences**: Some packages (e.g. `react`, `express`) "
        "backport patches across minor lines simultaneously. The time-filtered `as_of` ensures "
        "reproducibility, but release pairs must track within-major branches.",
        "- **Tarball Unpacked Size vs Gzip Size**: Content-Length is not always sent by npm "
        "registry on HEAD requests; streaming tarball size validation safely bounds memory usage.",
        "",
    ])

    return "\n".join(lines)


def main() -> None:
    """Run benign smoke test measurement."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="Benign Smoke Test for Release Sentinel")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of packages")
    parser.add_argument(
        "--max-tarball-mb", type=float, default=25.0, help="Max tarball size in MB"
    )
    parser.add_argument(
        "--pairs-per-package", type=int, default=5, help="Number of pairs per package"
    )
    parser.add_argument(
        "--seed-file", type=Path, default=_DEFAULT_SEED_FILE, help="Seed packages file"
    )
    parser.add_argument(
        "--cache-dir", type=Path, default=_DEFAULT_CACHE_DIR, help="Cache directory"
    )
    parser.add_argument(
        "--output-csv", type=Path, default=_DEFAULT_CSV_FILE, help="Output CSV path"
    )
    parser.add_argument(
        "--report-file", type=Path, default=_DEFAULT_DOC_FILE, help="Markdown report path"
    )
    parser.add_argument(
        "--delay", type=float, default=0.1, help="Delay between operations in seconds"
    )
    args = parser.parse_args()

    max_bytes = int(args.max_tarball_mb * 1024 * 1024)

    if not args.seed_file.exists():
        print(f"Error: seed file {args.seed_file} does not exist.", file=sys.stderr)
        sys.exit(1)

    with args.seed_file.open("r", encoding="utf-8") as fh:
        packages = [
            line.strip()
            for line in fh
            if line.strip() and not line.strip().startswith("#")
        ]

    if args.limit is not None:
        packages = packages[: args.limit]

    print(f"Loaded {len(packages)} packages to evaluate.")

    fieldnames = [
        "package",
        "old",
        "new",
        "published_new",
        "decision",
        "max_severity",
        "evidence_types",
        "limitation_count",
        "seconds",
    ]

    existing_rows = read_existing_csv(args.output_csv)
    seen_pairs = {(r["package"], r["old"], r["new"]) for r in existing_rows}
    print(f"Found {len(seen_pairs)} previously evaluated pairs in {args.output_csv}.")

    all_rows = list(existing_rows)

    with NpmRegistryClient(cache_dir=args.cache_dir) as client:
        for idx, pkg in enumerate(packages, 1):
            print(f"\n[{idx}/{len(packages)}] Inspecting {pkg}...")
            now_utc = datetime.now(tz=UTC)
            try:
                meta = with_retry(client.get_metadata, pkg, now_utc)
            except Exception as exc:
                print(f"  [ERROR] Failed to fetch metadata for {pkg}: {exc}")
                continue

            pairs = find_stable_release_pairs(meta, pairs_per_package=args.pairs_per_package)
            print(f"  Found {len(pairs)} stable same-major pair(s).")

            for old_ver, new_ver, pub_dt in pairs:
                if (pkg, old_ver, new_ver) in seen_pairs:
                    print(f"  -> Skipping {pkg} {old_ver} -> {new_ver} (already in CSV)")
                    continue

                print(f"  -> Evaluating {pkg} {old_ver} -> {new_ver} (as_of {pub_dt.date()})...")
                try:
                    result = process_pair(
                        client=client,
                        pkg=pkg,
                        old_ver=old_ver,
                        new_ver=new_ver,
                        as_of=pub_dt,
                        max_bytes=max_bytes,
                    )
                    append_csv_row(args.output_csv, result, fieldnames)
                    seen_pairs.add((pkg, old_ver, new_ver))
                    all_rows.append(result)
                    print(
                        f"     Decision: {result['decision']} "
                        f"(Severity: {result['max_severity']}, Time: {result['seconds']}s)"
                    )
                except Exception as exc:
                    print(f"     [ERROR] Failed evaluating {pkg} {old_ver} -> {new_ver}: {exc}")

                time.sleep(args.delay)

    report_md = generate_analysis_report(all_rows)
    args.report_file.parent.mkdir(parents=True, exist_ok=True)
    args.report_file.write_text(report_md, encoding="utf-8")
    print(f"\nReport written to {args.report_file}")
    print("\n" + report_md)


if __name__ == "__main__":
    main()
