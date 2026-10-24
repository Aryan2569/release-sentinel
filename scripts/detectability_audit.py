"""Release Sentinel — Stage 5c Part 2: Detectability Audit.

Audits all 1,349 evaluation pairs on data alone (archive vs baseline) without
depending on detector outputs:
- Content changed vs metadata only vs empty diff
- Native binary / wasm only changes
- Minified / bundled only changes
- Over size budget (>500KB) only changes
- Non-JS text only changes
- Adds direct dependency
- Adds or changes lifecycle script
- Adds new files vs modifies existing only
- Archive size and file count distributions
- Inspectable vs non-inspectable classification
- Attack style mix over time (2024, 2025, early 2026, mid 2026, late 2026)
- Conditional recall on TEST-B (inspectable vs non-inspectable)
"""

from __future__ import annotations

import csv
import json
import logging
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from release_sentinel.eval import get_samples_root, parse_discovery_date_as_of
from release_sentinel.extractor import extract_release_in_memory
from release_sentinel.file_classifier import FileCategory, classify
from release_sentinel.registry import NpmRegistryClient, _safe_filename
from release_sentinel.zip_loader import load_zip_release

logging.basicConfig(level=logging.WARNING)

CACHE_DIR = Path.home() / ".cache" / "release_sentinel"

SAMPLES_ROOT = get_samples_root()
EVAL_PAIRS_CSV = Path("data/eval_pairs.csv")
EVAL_RESULTS_V5 = Path("data/eval_results_v5.jsonl")
CLUSTERS_V5 = Path("data/eval_clusters_v5.json")
OUTPUT_JSON = Path("data/detectability_audit.json")

MAX_FILE_SIZE_DIFF_BYTES = 500 * 1024  # 500 KB

LIFECYCLE_HOOKS = {
    "preinstall",
    "install",
    "postinstall",
    "prepublish",
    "prepublishOnly",
    "prepare",
    "prepack",
    "postpack",
}


def _is_binary(path: str, data: bytes, cat: FileCategory) -> bool:
    if cat == FileCategory.NATIVE_BINARY:
        return True
    lower = path.lower()
    if lower.endswith((".node", ".so", ".dll", ".wasm", ".dylib", ".exe")):
        return True
    if (
        data.startswith(b"\x7fELF")
        or data.startswith(b"MZ")
        or data.startswith(b"\xfe\xed\xfa")
        or data.startswith(b"\xce\xfa\xed\xfe")
        or data.startswith(b"\x00asm")
    ):
        return True
    return False


def _is_non_js_text(path: str, cat: FileCategory) -> bool:
    if cat == FileCategory.DOCUMENT:
        return True
    name = Path(path).name.upper()
    if name.startswith((
        "README",
        "LICENSE",
        "LICENCE",
        "CHANGELOG",
        "AUTHORS",
        "NOTICE",
        "CONTRIBUTING",
        "SECURITY",
    )):
        return True
    lower = path.lower()
    return lower.endswith((
        ".md",
        ".markdown",
        ".txt",
        ".rst",
        ".html",
        ".css",
        ".json",
        ".yml",
        ".yaml",
        ".xml",
    ))


def _is_minified_or_map(path: str, cat: FileCategory) -> bool:
    if cat in (FileCategory.MINIFIED, FileCategory.SOURCE_MAP):
        return True
    lower = path.lower()
    return lower.endswith((".min.js", ".bundle.js", ".map"))


def audit_pair(
    pair: dict[str, str],
    client: NpmRegistryClient,
    dest_temp: Path,
) -> dict[str, Any]:
    pkg = pair["package"]
    old_ver = pair["old_version"]
    new_ver = pair["new_version"]
    disc_date = pair["discovery_date"]
    zip_path = SAMPLES_ROOT / pair["zip_path"]

    # 1. Load new release
    new_rc = load_zip_release(zip_path, password=b"infected")
    new_files = new_rc.files
    new_archive_bytes = sum(len(b) for b in new_files.values())
    new_file_count = len(new_files)

    # 2. Load baseline release
    safe_name = _safe_filename(pkg)
    tgz_cache = client._cache_dir / safe_name / f"{safe_name}-{old_ver}.tgz"
    alt_cache = dest_temp / f"{safe_name}-{old_ver}.tgz"
    if tgz_cache.exists():
        old_rc = extract_release_in_memory(tgz_cache)
    elif alt_cache.exists():
        old_rc = extract_release_in_memory(alt_cache)
    else:
        as_of = parse_discovery_date_as_of(disc_date)
        tgz = client.download_tarball(pkg, old_ver, as_of=as_of, dest_dir=dest_temp)
        old_rc = extract_release_in_memory(tgz)

    old_files = old_rc.files
    old_archive_bytes = sum(len(b) for b in old_files.values())
    old_file_count = len(old_files)

    # 3. Diff analysis
    added_paths = set(new_files) - set(old_files)
    modified_paths = {k for k in (set(new_files) & set(old_files)) if new_files[k] != old_files[k]}
    removed_paths = set(old_files) - set(new_files)
    all_changed_paths = added_paths | modified_paths | removed_paths

    empty_diff = len(all_changed_paths) == 0
    metadata_only = all_changed_paths == {"package.json"}
    content_changed = len(all_changed_paths - {"package.json"}) > 0

    adds_new_files = len(added_paths) > 0
    modifies_existing_only = len(added_paths) == 0 and len(modified_paths) > 0

    # Package.json inspection
    old_pj = old_rc.package_json() or {}
    new_pj = new_rc.package_json() or {}

    old_deps = set(old_pj.get("dependencies", {}).keys()) if isinstance(old_pj, dict) else set()
    new_deps = set(new_pj.get("dependencies", {}).keys()) if isinstance(new_pj, dict) else set()
    added_deps = sorted(new_deps - old_deps)
    adds_direct_dependency = len(added_deps) > 0

    old_scripts = (
        old_pj.get("scripts", {})
        if isinstance(old_pj, dict) and isinstance(old_pj.get("scripts"), dict)
        else {}
    )
    new_scripts = (
        new_pj.get("scripts", {})
        if isinstance(new_pj, dict) and isinstance(new_pj.get("scripts"), dict)
        else {}
    )
    changed_hooks = [
        h
        for h in LIFECYCLE_HOOKS
        if new_scripts.get(h) != old_scripts.get(h) and new_scripts.get(h) is not None
    ]
    adds_or_changes_lifecycle_script = len(changed_hooks) > 0

    # Non-package.json added or modified files analysis
    content_chg_paths = (added_paths | modified_paths) - {"package.json"}

    file_classifications: dict[str, dict[str, Any]] = {}
    for p in content_chg_paths:
        data = new_files[p]
        cat = classify(data, p)
        file_classifications[p] = {
            "size": len(data),
            "category": cat.value,
            "is_binary": _is_binary(p, data, cat),
            "is_non_js_text": _is_non_js_text(p, cat),
            "is_minified_or_map": _is_minified_or_map(p, cat),
            "is_over_budget": len(data) > MAX_FILE_SIZE_DIFF_BYTES,
        }

    n_content_files = len(content_chg_paths)
    if n_content_files > 0:
        changes_only_binary = all(fc["is_binary"] for fc in file_classifications.values())
        changes_only_minified = all(
            fc["is_minified_or_map"] for fc in file_classifications.values()
        )
        changes_only_over_budget = all(fc["is_over_budget"] for fc in file_classifications.values())
        changes_only_non_js_text = all(fc["is_non_js_text"] for fc in file_classifications.values())

        # Inspectable code file: not binary, not over budget, not non-JS text, not minified-only
        has_inspectable_code_file = any(
            (not fc["is_binary"])
            and (not fc["is_over_budget"])
            and (not fc["is_non_js_text"])
            and (not fc["is_minified_or_map"])
            for fc in file_classifications.values()
        )
    else:
        changes_only_binary = False
        changes_only_minified = False
        changes_only_over_budget = False
        changes_only_non_js_text = False
        has_inspectable_code_file = False

    # Define inspectable change:
    # At least one changed file or script that the scanner can actually read:
    # (has_inspectable_code_file OR adds_or_changes_lifecycle_script)
    is_inspectable = bool(has_inspectable_code_file or adds_or_changes_lifecycle_script)

    return {
        "package": pkg,
        "old_version": old_ver,
        "new_version": new_ver,
        "discovery_date": disc_date,
        "new_archive_bytes": new_archive_bytes,
        "new_file_count": new_file_count,
        "old_archive_bytes": old_archive_bytes,
        "old_file_count": old_file_count,
        "empty_diff": empty_diff,
        "metadata_only": metadata_only,
        "content_changed": content_changed,
        "adds_new_files": adds_new_files,
        "modifies_existing_only": modifies_existing_only,
        "adds_direct_dependency": adds_direct_dependency,
        "added_deps_count": len(added_deps),
        "adds_or_changes_lifecycle_script": adds_or_changes_lifecycle_script,
        "changed_lifecycle_hooks": changed_hooks,
        "changes_only_in_binary_native_wasm": changes_only_binary,
        "changes_only_in_minified_or_bundled": changes_only_minified,
        "changes_only_in_files_over_size_budget": changes_only_over_budget,
        "changes_only_in_non_js_text": changes_only_non_js_text,
        "is_inspectable": is_inspectable,
    }


def _worker_wrapper(p: dict[str, str]) -> tuple[str, dict[str, Any]]:
    client = NpmRegistryClient(cache_dir=CACHE_DIR)
    dest_temp = CACHE_DIR / "tarballs" / "eval_tmp"
    k = f"{p['package']}@{p['old_version']}@{p['new_version']}"
    r = audit_pair(p, client, dest_temp)
    return k, r


def main() -> None:
    print("Starting Detectability Audit on all pairs in data/eval_pairs.csv...")
    dest_temp = CACHE_DIR / "tarballs" / "eval_tmp"
    dest_temp.mkdir(parents=True, exist_ok=True)

    pairs = [
        p for p in csv.DictReader(open(EVAL_PAIRS_CSV, encoding="utf-8")) if p.get("status") == "ok"
    ]
    total = len(pairs)
    print(f"Loaded {total} eval pairs.")

    # Check for existing cached audit results
    audit_results: dict[str, dict[str, Any]] = {}
    if OUTPUT_JSON.exists():
        try:
            raw = json.loads(OUTPUT_JSON.read_text(encoding="utf-8"))
            audit_results = {
                f"{r['package']}@{r['old_version']}@{r['new_version']}": r for r in raw
            }
            print(f"Loaded {len(audit_results)} pre-computed pairs from {OUTPUT_JSON}.")
        except Exception:
            audit_results = {}

    to_process = [
        p
        for p in pairs
        if f"{p['package']}@{p['old_version']}@{p['new_version']}" not in audit_results
    ]
    print(f"Remaining pairs to audit: {len(to_process)}", flush=True)

    count = len(audit_results)

    if to_process:
        with ProcessPoolExecutor(max_workers=8) as executor:
            futures = {executor.submit(_worker_wrapper, p): p for p in to_process}
            for fut in as_completed(futures):
                k, r = fut.result()
                audit_results[k] = r
                count += 1
                if count % 100 == 0 or count == total:
                    print(
                        f"Progress: {count}/{total} pairs audited ({count / total * 100:.1f}%)",
                        flush=True,
                    )
                    OUTPUT_JSON.write_text(
                        json.dumps(list(audit_results.values()), indent=2),
                        encoding="utf-8",
                    )

    OUTPUT_JSON.write_text(
        json.dumps(list(audit_results.values()), indent=2), encoding="utf-8"
    )
    print("Audit data saved to", OUTPUT_JSON, flush=True)

    # 4. Integrate with eval results and cluster definitions
    eval_results = [json.loads(line) for line in open(EVAL_RESULTS_V5, encoding="utf-8")]
    eval_by_key = {f"{e['package']}@{e['old']}@{e['new']}": e for e in eval_results}

    clusters = json.load(open(CLUSTERS_V5, encoding="utf-8"))
    test_cids = sorted(
        {e["cluster_id"] for e in eval_results if e["split"] == "TEST"},
        key=lambda cid: (clusters[cid]["earliest_discovery"], clusters[cid]["rank"], cid),
    )
    test_a_cids = set(test_cids[:98])

    for e in eval_results:
        if e["split"] == "TEST":
            e["split"] = "TEST-A" if e["cluster_id"] in test_a_cids else "TEST-B"

    # Merge audit with eval
    merged = []
    for r in audit_results.values():
        k = f"{r['package']}@{r['old_version']}@{r['new_version']}"
        ev = eval_by_key.get(k, {})
        merged.append({**r, **ev})

    print(f"\nMerged {len(merged)} audited pairs with detector results.")

    # Time period assignment
    def get_period(m: dict[str, Any]) -> str:
        s = m["split"]
        d = m["discovery_date"]
        year = d[:4]
        if s == "DEV":
            return f"DEV ({year})"
        elif s == "VAL":
            return "VAL (Early 2026)"
        elif s == "TEST-A":
            return "TEST-A (Mid 2026)"
        elif s == "TEST-B":
            return "TEST-B (Late 2026)"
        return "UNKNOWN"

    for m in merged:
        m["period"] = get_period(m)

    # Group by period
    periods = [
        "DEV (2024)",
        "DEV (2025)",
        "VAL (Early 2026)",
        "TEST-A (Mid 2026)",
        "TEST-B (Late 2026)",
    ]
    period_groups = defaultdict(list)
    for m in merged:
        period_groups[m["period"]].append(m)

    print("\n" + "=" * 80)
    print("TABLE 1: ATTACK STYLE MIX OVER TIME (Percentages within each period)")
    print("=" * 80)
    print(
        f"{'Period':<20} | {'Pairs':<6} | {'Inspectable':<12} | {'Content Chg':<12} | "
        f"{'Metadata Only':<13} | {'Empty Diff':<10} | {'Direct Dep':<12} | "
        f"{'Lifecycle Hook':<14} | {'Binary Only':<11} | {'Minified Only':<13}"
    )
    print("-" * 140)

    for per in periods:
        group = period_groups[per]
        n = len(group)
        if n == 0:
            continue
        insp = sum(1 for x in group if x["is_inspectable"])
        c_chg = sum(1 for x in group if x["content_changed"])
        m_only = sum(1 for x in group if x["metadata_only"])
        e_diff = sum(1 for x in group if x["empty_diff"])
        dep_add = sum(1 for x in group if x["adds_direct_dependency"])
        lc_scr = sum(1 for x in group if x["adds_or_changes_lifecycle_script"])
        bin_only = sum(1 for x in group if x["changes_only_in_binary_native_wasm"])
        min_only = sum(1 for x in group if x["changes_only_in_minified_or_bundled"])

        print(
            f"{per:<20} | {n:<6} | {insp}/{n} ({insp/n*100:4.1f}%) | "
            f"{c_chg}/{n} ({c_chg/n*100:4.1f}%) | {m_only}/{n} ({m_only/n*100:4.1f}%) | "
            f"{e_diff}/{n} ({e_diff/n*100:4.1f}%) | {dep_add}/{n} ({dep_add/n*100:4.1f}%) | "
            f"{lc_scr}/{n} ({lc_scr/n*100:4.1f}%) | {bin_only}/{n} ({bin_only/n*100:4.1f}%) | "
            f"{min_only}/{n} ({min_only/n*100:4.1f}%)"
        )

    print("\n" + "=" * 80)
    print("TABLE 2: TEST-B CONDITIONAL RECALL (v1.0 Frozen Baseline)")
    print("=" * 80)
    test_b_pairs = [m for m in merged if m["split"] == "TEST-B"]
    insp_b = [m for m in test_b_pairs if m["is_inspectable"]]
    non_insp_b = [m for m in test_b_pairs if not m["is_inspectable"]]

    def summarize_recall(name: str, subset: list[dict[str, Any]]) -> None:
        n = len(subset)
        if n == 0:
            print(f"{name:<25}: 0 pairs")
            return
        w_fc = sum(1 for x in subset if x["decision"] in ("WARN", "BLOCK"))
        w_eo = sum(1 for x in subset if x["evidence_only_decision"] in ("WARN", "BLOCK"))
        b_fc = sum(1 for x in subset if x["decision"] == "BLOCK")
        print(
            f"{name:<25}: n={n:3d} | >=WARN (FC): {w_fc:2d}/{n:2d} ({w_fc/n*100:5.1f}%) | "
            f">=WARN (EO): {w_eo:2d}/{n:2d} ({w_eo/n*100:5.1f}%) | "
            f"BLOCK: {b_fc:2d}/{n:2d} ({b_fc/n*100:5.1f}%)"
        )

    summarize_recall("TEST-B Total", test_b_pairs)
    summarize_recall("TEST-B Inspectable", insp_b)
    summarize_recall("TEST-B Not Inspectable", non_insp_b)

    print("\n" + "=" * 80)
    print("TABLE 3: ARCHIVE SIZE AND FILE COUNT DISTRIBUTIONS ACROSS COHORTS")
    print("=" * 80)
    print(
        f"{'Cohort':<20} | {'Pairs':<6} | {'Median Size (KB)':<17} | {'Mean Size (KB)':<15} | "
        f"{'Median Files':<13} | {'Mean Files':<11}"
    )
    print("-" * 90)

    for per in periods:
        group = period_groups[per]
        n = len(group)
        if n == 0:
            continue
        sizes_kb = sorted(x["new_archive_bytes"] / 1024 for x in group)
        files = sorted(x["new_file_count"] for x in group)
        med_size = sizes_kb[n // 2]
        mean_size = sum(sizes_kb) / n
        med_files = files[n // 2]
        mean_files = sum(files) / n
        print(
            f"{per:<20} | {n:<6} | {med_size:<17.1f} | {mean_size:<15.1f} | "
            f"{med_files:<13d} | {mean_files:<11.1f}"
        )


if __name__ == "__main__":
    main()
