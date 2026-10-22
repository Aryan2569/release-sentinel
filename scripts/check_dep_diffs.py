import csv
import json
from datetime import UTC, datetime
from pathlib import Path

from release_sentinel.eval import analyze_eval_pair
from release_sentinel.policy import load_policy
from release_sentinel.registry import NpmRegistryClient

CACHE_DIR = Path.home() / ".cache" / "release_sentinel"
SAMPLES_ROOT = Path(r"C:\rs-data\datadog")

client = NpmRegistryClient(cache_dir=CACHE_DIR)
policy = load_policy()

v10_rows = [json.loads(line) for line in open("data/eval_results_v10.jsonl", encoding="utf-8")]
eval_pairs = [p for p in csv.DictReader(open("data/eval_pairs.csv", encoding="utf-8")) if p.get("status") == "ok"]
pair_csv_map = {(p["package"], p.get("old_version", ""), p["new_version"]): p for p in eval_pairs}

dep_rows = [r for r in v10_rows if "dependency_added" in r.get("evidence_types", [])]
print(f"Checking {len(dep_rows)} pairs with dependency_added...")

changed = []
for _i, r in enumerate(dep_rows):
    pkg = r["package"]
    old = r.get("old", "")
    new = r["new"]
    p = pair_csv_map.get((pkg, old, new))
    if not p:
        continue

    res = analyze_eval_pair(
        package=pkg,
        old_version=old,
        new_version=new,
        zip_path=SAMPLES_ROOT / p["zip_path"],
        discovery_date=datetime.fromisoformat(p["discovery_date"]).astimezone(UTC),
        registry_client=client,
        samples_root=SAMPLES_ROOT,
    )
    if res.decision.name != r["decision"]:
        changed.append((pkg, old, new, r["decision"], res.decision.name))

client.close()
print(f"Done. Changed decisions: {len(changed)}")
for c in changed:
    print(" ", c)
