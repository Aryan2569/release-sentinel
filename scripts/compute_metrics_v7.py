"""Compute complete comparative evaluation across v1.0, v1.1, and v1.2."""

import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

sys.path.insert(0, ".")
from scripts.build_campaigns import evaluate_version_on_campaigns, get_split_mapping

EVAL_RESULTS_V4 = Path("data/eval_results_v4.jsonl")  # v1.0
EVAL_RESULTS_V6 = Path("data/eval_results_v6.jsonl")  # v1.1
EVAL_RESULTS_V7 = Path("data/eval_results_v7.jsonl")  # v1.2
CAMPAIGNS_JSON = Path("data/eval_campaigns.json")

campaigns_dict = json.load(open(CAMPAIGNS_JSON, encoding="utf-8"))
key_to_split = get_split_mapping()
pair_to_campaign: dict[str, str] = {}
for cid, c in campaigns_dict.items():
    for m in c["members"]:
        pair_to_campaign[m] = cid


def compute_sample_metrics(results_path: Path) -> dict[str, Any]:
    rows = [json.loads(line) for line in open(results_path, encoding="utf-8")]
    split_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        pair_key = (r["package"], r["old"], r["new"])
        s = key_to_split.get(pair_key, r.get("split", "DEV"))
        r["eval_split"] = s
        split_rows[s].append(r)
        split_rows["ALL"].append(r)

    stats: dict[str, Any] = {}
    for s in ["ALL", "DEV", "VAL", "TEST-A", "TEST-B"]:
        r_list = split_rows[s]
        n = len(r_list)
        fc_warn = sum(1 for r in r_list if r.get("decision") in ("WARN", "BLOCK"))
        fc_block = sum(1 for r in r_list if r.get("decision") == "BLOCK")
        eo_warn = sum(1 for r in r_list if r.get("evidence_only_decision") in ("WARN", "BLOCK"))
        eo_block = sum(1 for r in r_list if r.get("evidence_only_decision") == "BLOCK")
        incomp = sum(1 for r in r_list if r.get("limitation_count", 0) > 0 or r.get("status") != "ok")

        stats[s] = {
            "pairs": n,
            "fc_warn": fc_warn,
            "fc_warn_pct": fc_warn / n * 100,
            "fc_block": fc_block,
            "fc_block_pct": fc_block / n * 100,
            "eo_warn": eo_warn,
            "eo_warn_pct": eo_warn / n * 100,
            "eo_block": eo_block,
            "eo_block_pct": eo_block / n * 100,
            "incomp": incomp,
            "incomp_pct": incomp / n * 100,
        }
    return stats


sample_v10 = compute_sample_metrics(EVAL_RESULTS_V4)
sample_v11 = compute_sample_metrics(EVAL_RESULTS_V6)
sample_v12 = compute_sample_metrics(EVAL_RESULTS_V7)

camp_v10 = evaluate_version_on_campaigns(EVAL_RESULTS_V4, campaigns_dict, pair_to_campaign, key_to_split)
camp_v11 = evaluate_version_on_campaigns(EVAL_RESULTS_V6, campaigns_dict, pair_to_campaign, key_to_split)
camp_v12 = evaluate_version_on_campaigns(EVAL_RESULTS_V7, campaigns_dict, pair_to_campaign, key_to_split)

out = {
    "sample": {
        "v1.0": sample_v10,
        "v1.1": sample_v11,
        "v1.2": sample_v12,
    },
    "campaign": {
        "v1.0": camp_v10,
        "v1.1": camp_v11,
        "v1.2": camp_v12,
    },
}

with open("data/metrics_v7_summary.json", "w", encoding="utf-8") as f:
    json.dump(out, f, indent=2)

print("Saved data/metrics_v7_summary.json")
print("\n=== SAMPLE RECALL SUMMARY ===")
for s in ["ALL", "DEV", "VAL", "TEST-A", "TEST-B"]:
    print(f"\n[{s}]")
    print(f"  v1.0: EO-BLOCK={sample_v10[s]['eo_block']} ({sample_v10[s]['eo_block_pct']:.2f}%) | EO-WARN={sample_v10[s]['eo_warn']} ({sample_v10[s]['eo_warn_pct']:.2f}%)")
    print(f"  v1.1: EO-BLOCK={sample_v11[s]['eo_block']} ({sample_v11[s]['eo_block_pct']:.2f}%) | EO-WARN={sample_v11[s]['eo_warn']} ({sample_v11[s]['eo_warn_pct']:.2f}%)")
    print(f"  v1.2: EO-BLOCK={sample_v12[s]['eo_block']} ({sample_v12[s]['eo_block_pct']:.2f}%) | EO-WARN={sample_v12[s]['eo_warn']} ({sample_v12[s]['eo_warn_pct']:.2f}%)")

print("\n=== CAMPAIGN RECALL SUMMARY ===")
for s in ["ALL", "DEV", "VAL", "TEST-A", "TEST-B"]:
    print(f"\n[{s}]")
    print(f"  v1.0: Lenient-BLOCK={camp_v10[s]['lenient_eo_block']}/{camp_v10[s]['campaigns']} ({camp_v10[s]['lenient_eo_block_pct']:.2f}%) | Macro-BLOCK={camp_v10[s]['macro_eo_block_pct']:.2f}%")
    print(f"  v1.1: Lenient-BLOCK={camp_v11[s]['lenient_eo_block']}/{camp_v11[s]['campaigns']} ({camp_v11[s]['lenient_eo_block_pct']:.2f}%) | Macro-BLOCK={camp_v11[s]['macro_eo_block_pct']:.2f}%")
    print(f"  v1.2: Lenient-BLOCK={camp_v12[s]['lenient_eo_block']}/{camp_v12[s]['campaigns']} ({camp_v12[s]['lenient_eo_block_pct']:.2f}%) | Macro-BLOCK={camp_v12[s]['macro_eo_block_pct']:.2f}%")
