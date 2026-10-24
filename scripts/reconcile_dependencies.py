"""Reconcile added dependencies across all 1,349 eval pairs.

Under Part 0c:
- Use ONE definition of "added dependency" (state fields).
- Report per split (DEV, VAL, TEST-A, TEST-B; counts only):
  * pairs adding a dependency
  * distinct added dependency names
  * how those dependencies resolve today (real package / registry security placeholder / 404 / unsupported spec).
"""

from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import httpx

from release_sentinel.eval import get_samples_root, parse_discovery_date_as_of
from release_sentinel.extractor import extract_release_in_memory
from release_sentinel.registry import NpmRegistryClient
from release_sentinel.zip_loader import load_zip_release

SAMPLES_ROOT = get_samples_root()
CACHE_DIR = Path.home() / ".cache" / "release_sentinel"
EVAL_PAIRS_CSV = Path("data/eval_pairs.csv")
EVAL_RESULTS_V6 = Path("data/eval_results_v6.jsonl")
CLUSTERS_V6 = Path("data/eval_clusters_v6.json")

# Map pairs to split
results = [json.loads(line) for line in open(EVAL_RESULTS_V6, encoding="utf-8")]
clusters = json.load(open(CLUSTERS_V6, encoding="utf-8"))
test_cids = sorted(
    {e["cluster_id"] for e in results if e["split"] == "TEST"},
    key=lambda cid: (clusters[cid]["earliest_discovery"], clusters[cid]["rank"], cid),
)
test_a_cids = set(test_cids[:98])
key_to_split: dict[tuple[str, str, str], str] = {}
for e in results:
    s = e["split"]
    if s == "TEST":
        s = "TEST-A" if e["cluster_id"] in test_a_cids else "TEST-B"
    key_to_split[(e["package"], e["old"], e["new"])] = s

# Load pairs
pairs = [p for p in csv.DictReader(open(EVAL_PAIRS_CSV, encoding="utf-8")) if p.get("status") == "ok"]
client = NpmRegistryClient(cache_dir=CACHE_DIR)
dest_temp = CACHE_DIR / "tarballs" / "eval_tmp"
dest_temp.mkdir(parents=True, exist_ok=True)

split_pairs_adding_direct: dict[str, list[dict[str, Any]]] = defaultdict(list)
split_distinct_direct_deps: dict[str, set[str]] = defaultdict(set)
all_added_deps_with_specs: dict[str, set[str]] = defaultdict(set)  # dep_name -> specs

print(f"Analyzing {len(pairs)} pairs for added direct runtime dependencies...")

for i, p in enumerate(pairs, 1):
    pkg = p["package"]
    old_ver = p["old_version"]
    new_ver = p["new_version"]
    split = key_to_split.get((pkg, old_ver, new_ver), "DEV")

    # Load new release package.json from encrypted zip
    zip_path = SAMPLES_ROOT / p["zip_path"]
    try:
        new_rc = load_zip_release(zip_path, password=b"infected")
        new_pj = new_rc.package_json() or {}
    except Exception as exc:
        print(f"Error reading zip for {pkg}@{new_ver}: {exc}")
        new_pj = {}

    # Load old release package.json from cached baseline tarball
    old_pj = {}
    try:
        as_of = parse_discovery_date_as_of(p["discovery_date"])
        tarball_path = client.download_tarball(pkg, old_ver, as_of=as_of, dest_dir=dest_temp)
        old_rc = extract_release_in_memory(tarball_path)
        old_pj = old_rc.package_json() or {}
    except Exception:
        pass

    old_deps = old_pj.get("dependencies") or {}
    new_deps = new_pj.get("dependencies") or {}

    old_keys = set(old_deps.keys()) if isinstance(old_deps, dict) else set()
    new_keys = set(new_deps.keys()) if isinstance(new_deps, dict) else set()

    added = new_keys - old_keys
    if added:
        split_pairs_adding_direct[split].append({
            "package": pkg,
            "old": old_ver,
            "new": new_ver,
            "added_deps": sorted(added),
        })
        for dep in added:
            split_distinct_direct_deps[split].add(dep)
            spec = str(new_deps.get(dep, ""))
            all_added_deps_with_specs[dep].add(spec)

    if i % 200 == 0 or i == len(pairs):
        print(f"  [{i}/{len(pairs)}] pairs processed...")

print("\n--- Added Direct Runtime Dependencies Counts ---")
total_pairs_adding = 0
all_distinct_deps: set[str] = set()
for s in ["DEV", "VAL", "TEST-A", "TEST-B"]:
    n_p = len(split_pairs_adding_direct[s])
    total_pairs_adding += n_p
    n_deps = len(split_distinct_direct_deps[s])
    all_distinct_deps.update(split_distinct_direct_deps[s])
    print(f"{s}: {n_p} pairs add direct dependencies | {n_deps} distinct dependency names")
print(
    f"TOTAL: {total_pairs_adding} pairs add direct dependencies | "
    f"{len(all_distinct_deps)} distinct dependency names total"
)

# Check resolution of all distinct added dependency names today
print(f"\nChecking resolution of {len(all_distinct_deps)} distinct dependency names against public npm registry...")
resolution_status: dict[str, str] = {}
# Categories: "real", "placeholder", "404", "unsupported_spec"

with httpx.Client(timeout=10.0) as http:
    for dep in sorted(all_distinct_deps):
        specs = all_added_deps_with_specs[dep]
        # Check if spec is unsupported
        has_unsupported = any(s.startswith(("workspace:", "file:", "git:", "link:")) for s in specs)
        if has_unsupported:
            resolution_status[dep] = "unsupported_spec"
            continue

        url = f"https://registry.npmjs.org/{dep}"
        try:
            resp = http.get(url)
            if resp.status_code == 404:
                resolution_status[dep] = "404"
            elif resp.status_code == 200:
                data = resp.json()
                readme = str(data.get("readme", "")).lower()
                desc = str(data.get("description", "")).lower()
                name = str(data.get("name", ""))
                # Detect security holding package
                if (
                    "security holding package" in readme
                    or "security holding package" in desc
                    or "placeholder" in desc
                    or "non-functional placeholder" in readme
                ):
                    resolution_status[dep] = "placeholder"
                else:
                    resolution_status[dep] = "real"
            else:
                resolution_status[dep] = f"http_{resp.status_code}"
        except Exception as exc:
            resolution_status[dep] = f"error_{exc}"

print("\nOverall Resolution Breakdown of Distinct Dependency Names:")
overall_counts = Counter(resolution_status.values())
for cat, count in overall_counts.most_common():
    print(f"  {cat}: {count} ({count/len(all_distinct_deps)*100:.1f}%)")

print("\nPer-Split Resolution Breakdown (Distinct Dependency Names):")
for s in ["DEV", "VAL", "TEST-A", "TEST-B"]:
    s_deps = split_distinct_direct_deps[s]
    counts = Counter(resolution_status.get(d, "unknown") for d in s_deps)
    print(f"  {s} ({len(s_deps)} distinct): {dict(counts)}")

out_data = {
    "counts_per_split": {
        s: {
            "pairs_adding_dependency": len(split_pairs_adding_direct[s]),
            "distinct_dependency_names": len(split_distinct_direct_deps[s]),
            "resolution": dict(Counter(resolution_status.get(d, "unknown") for d in split_distinct_direct_deps[s])),
        }
        for s in ["DEV", "VAL", "TEST-A", "TEST-B"]
    },
    "distinct_dependencies": {
        dep: {
            "status": resolution_status.get(dep, "unknown"),
            "specs": sorted(all_added_deps_with_specs[dep]),
        }
        for dep in sorted(all_distinct_deps)
    },
}
with open("data/dependency_reconciliation.json", "w", encoding="utf-8") as f:
    json.dump(out_data, f, indent=2)
print("\nSaved output to data/dependency_reconciliation.json")
