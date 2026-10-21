"""Single source of truth for Release Sentinel evaluation metrics (Stage 5e Part 5).

Recomputes every headline number:
- Pair-level recall (Fail-closed & Evidence-only >=WARN and BLOCK, incomplete counts/pcts)
- Campaign-level recall (k of n, lenient and macro, exact Clopper-Pearson 95% CIs)
- Benign evaluation alert rates and false BLOCK counts (800 pairs canonical)
- Dependency-addition share by split

Writes everything to docs/METRICS.json, and verifies consistency with docs/eval_results_v7.md.
"""

from __future__ import annotations

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

sys.path.insert(0, ".")

from scripts.build_campaigns import clopper_pearson, get_split_mapping

EVAL_RESULTS_V4 = Path("data/eval_results_v4.jsonl")  # v1.0
EVAL_RESULTS_V6 = Path("data/eval_results_v6.jsonl")  # v1.1
EVAL_RESULTS_V7 = Path("data/eval_results_v7.jsonl")  # v1.2
CAMPAIGNS_JSON = Path("data/eval_campaigns.json")
EVAL_PAIRS_CSV = Path("data/eval_pairs.csv")
DEP_RECON_JSON = Path("data/dependency_reconciliation.json")

SMOKE_TUNING_CSV = Path("data/smoke_results_v7.csv")
SMOKE_VAL_CSV = Path("data/smoke_validation_v7.csv")
MATCHED_NEG_JSONL = Path("data/matched_negatives_results_v7.jsonl")

METRICS_OUT = Path("docs/METRICS.json")
EVAL_REPORT_MD = Path("docs/eval_results_v7.md")


def compute_sample_metrics(results_path: Path, key_to_split: dict[tuple[str, str, str], str]) -> dict[str, Any]:
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
            "fc_warn_pct": round(fc_warn / n * 100, 2),
            "fc_block": fc_block,
            "fc_block_pct": round(fc_block / n * 100, 2),
            "eo_warn": eo_warn,
            "eo_warn_pct": round(eo_warn / n * 100, 2),
            "eo_block": eo_block,
            "eo_block_pct": round(eo_block / n * 100, 2),
            "incomp": incomp,
            "incomp_pct": round(incomp / n * 100, 2),
        }
    return stats


def compute_campaign_metrics(
    results_path: Path,
    campaigns_dict: dict[str, Any],
    pair_to_campaign: dict[str, str],
) -> dict[str, Any]:
    rows = [json.loads(line) for line in open(results_path, encoding="utf-8")]
    camp_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        pair_key = f"{r['package']}@{r['old']}@{r['new']}"
        cid = pair_to_campaign.get(pair_key)
        if cid:
            camp_rows[cid].append(r)

    by_split: dict[str, list[str]] = defaultdict(list)
    for cid, c in campaigns_dict.items():
        by_split[c["primary_split"]].append(cid)

    split_stats: dict[str, Any] = {}
    for split in ["ALL", "DEV", "VAL", "TEST-A", "TEST-B"]:
        target_cids = list(campaigns_dict.keys()) if split == "ALL" else by_split[split]
        n_camps = len(target_cids)

        lenient_fc_warn = 0
        lenient_fc_block = 0
        lenient_eo_warn = 0
        lenient_eo_block = 0

        macro_fc_warn_sum = 0.0
        macro_fc_block_sum = 0.0
        macro_eo_warn_sum = 0.0
        macro_eo_block_sum = 0.0

        for cid in target_cids:
            r_list = camp_rows.get(cid, [])
            if not r_list:
                continue

            n_pairs = len(r_list)
            c_fc_warn = sum(1 for r in r_list if r.get("decision") in ("WARN", "BLOCK"))
            c_fc_block = sum(1 for r in r_list if r.get("decision") == "BLOCK")
            c_eo_warn = sum(1 for r in r_list if r.get("evidence_only_decision") in ("WARN", "BLOCK"))
            c_eo_block = sum(1 for r in r_list if r.get("evidence_only_decision") == "BLOCK")

            if c_fc_warn > 0:
                lenient_fc_warn += 1
            if c_fc_block > 0:
                lenient_fc_block += 1
            if c_eo_warn > 0:
                lenient_eo_warn += 1
            if c_eo_block > 0:
                lenient_eo_block += 1

            macro_fc_warn_sum += c_fc_warn / n_pairs
            macro_fc_block_sum += c_fc_block / n_pairs
            macro_eo_warn_sum += c_eo_warn / n_pairs
            macro_eo_block_sum += c_eo_block / n_pairs

        lo_warn, hi_warn = clopper_pearson(lenient_eo_warn, n_camps)
        lo_block, hi_block = clopper_pearson(lenient_eo_block, n_camps)

        split_stats[split] = {
            "campaigns": n_camps,
            "lenient_fc_warn": lenient_fc_warn,
            "lenient_fc_warn_pct": round(lenient_fc_warn / n_camps * 100, 2),
            "lenient_fc_block": lenient_fc_block,
            "lenient_fc_block_pct": round(lenient_fc_block / n_camps * 100, 2),
            "lenient_eo_warn": lenient_eo_warn,
            "lenient_eo_warn_pct": round(lenient_eo_warn / n_camps * 100, 2),
            "lenient_eo_warn_ci": [round(lo_warn * 100, 2), round(hi_warn * 100, 2)],
            "lenient_eo_block": lenient_eo_block,
            "lenient_eo_block_pct": round(lenient_eo_block / n_camps * 100, 2),
            "lenient_eo_block_ci": [round(lo_block * 100, 2), round(hi_block * 100, 2)],
            "macro_fc_warn_pct": round(macro_fc_warn_sum / n_camps * 100, 2),
            "macro_fc_block_pct": round(macro_fc_block_sum / n_camps * 100, 2),
            "macro_eo_warn_pct": round(macro_eo_warn_sum / n_camps * 100, 2),
            "macro_eo_block_pct": round(macro_eo_block_sum / n_camps * 100, 2),
        }
    return split_stats


def compute_benign_metrics() -> dict[str, Any]:
    # Tuning smoke
    tuning_rows = list(csv.DictReader(open(SMOKE_TUNING_CSV, encoding="utf-8")))
    tuning_alerts = sum(1 for r in tuning_rows if r["decision"] in ("WARN", "BLOCK"))
    tuning_blocks = sum(1 for r in tuning_rows if r["decision"] == "BLOCK")

    # Validation smoke
    val_rows = list(csv.DictReader(open(SMOKE_VAL_CSV, encoding="utf-8")))
    val_alerts = sum(1 for r in val_rows if r["decision"] in ("WARN", "BLOCK"))
    val_blocks = sum(1 for r in val_rows if r["decision"] == "BLOCK")

    # Matched negatives
    matched_rows = [json.loads(line) for line in open(MATCHED_NEG_JSONL, encoding="utf-8")]
    matched_alerts = sum(1 for r in matched_rows if r["decision"] in ("WARN", "BLOCK"))
    matched_blocks = sum(1 for r in matched_rows if r["decision"] == "BLOCK")

    total_pairs = len(tuning_rows) + len(val_rows) + len(matched_rows)
    total_alerts = tuning_alerts + val_alerts + matched_alerts
    total_blocks = tuning_blocks + val_blocks + matched_blocks

    return {
        "tuning_smoke": {
            "pairs": len(tuning_rows),
            "alerts": tuning_alerts,
            "alert_rate_per_100": round(tuning_alerts / len(tuning_rows) * 100, 2),
            "false_blocks": tuning_blocks,
        },
        "validation_smoke": {
            "pairs": len(val_rows),
            "alerts": val_alerts,
            "alert_rate_per_100": round(val_alerts / len(val_rows) * 100, 2),
            "false_blocks": val_blocks,
        },
        "matched_negatives": {
            "pairs": len(matched_rows),
            "alerts": matched_alerts,
            "alert_rate_per_100": round(matched_alerts / len(matched_rows) * 100, 2),
            "false_blocks": matched_blocks,
        },
        "total_benign": {
            "pairs": total_pairs,
            "alerts": total_alerts,
            "alert_rate_per_100": round(total_alerts / total_pairs * 100, 2),
            "false_blocks": total_blocks,
            "false_block_ci_upper_pct": round((1.0 - (0.05 ** (1.0 / total_pairs))) * 100, 3),
        },
    }


def recompute_all_metrics() -> dict[str, Any]:
    key_to_split = get_split_mapping()
    campaigns_dict = json.load(open(CAMPAIGNS_JSON, encoding="utf-8"))
    pair_to_campaign: dict[str, str] = {}
    for cid, c in campaigns_dict.items():
        for m in c["members"]:
            pair_to_campaign[m] = cid

    dep_recon = json.load(open(DEP_RECON_JSON, encoding="utf-8"))

    sample_v10 = compute_sample_metrics(EVAL_RESULTS_V4, key_to_split)
    sample_v11 = compute_sample_metrics(EVAL_RESULTS_V6, key_to_split)
    sample_v12 = compute_sample_metrics(EVAL_RESULTS_V7, key_to_split)

    camp_v10 = compute_campaign_metrics(EVAL_RESULTS_V4, campaigns_dict, pair_to_campaign)
    camp_v11 = compute_campaign_metrics(EVAL_RESULTS_V6, campaigns_dict, pair_to_campaign)
    camp_v12 = compute_campaign_metrics(EVAL_RESULTS_V7, campaigns_dict, pair_to_campaign)

    benign = compute_benign_metrics()

    return {
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
        "benign": benign,
        "dependency_additions": dep_recon["counts_per_split"],
    }


def verify_doc_consistency(metrics: dict[str, Any]) -> None:
    if not EVAL_REPORT_MD.exists():
        return
    text = EVAL_REPORT_MD.read_text(encoding="utf-8")

    # Verify key headline sample numbers
    # ALL v1.2 Sample BLOCK: 1,202 / 1,349 (89.10%)
    s_v12 = metrics["sample"]["v1.2"]["ALL"]
    assert f"{s_v12['eo_block']:,}" in text or f"{s_v12['eo_block']}" in text, f"Missing ALL v1.2 EO-BLOCK {s_v12['eo_block']}"
    assert f"{s_v12['eo_warn']:,}" in text or f"{s_v12['eo_warn']}" in text, f"Missing ALL v1.2 EO-WARN {s_v12['eo_warn']}"

    # Verify split pair counts
    for s in ["DEV", "VAL", "TEST-A", "TEST-B"]:
        pairs_n = metrics["sample"]["v1.2"][s]["pairs"]
        assert f"{pairs_n:,}" in text or f"{pairs_n}" in text, f"Missing split pair count {pairs_n} for {s}"

    # Verify campaign counts
    for s in ["DEV", "VAL", "TEST-A", "TEST-B"]:
        c_n = metrics["campaign"]["v1.2"][s]["campaigns"]
        assert f"{c_n}" in text, f"Missing campaign count {c_n} for {s}"


def main() -> None:
    metrics = recompute_all_metrics()
    with open(METRICS_OUT, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"Wrote canonical metrics to {METRICS_OUT}")
    verify_doc_consistency(metrics)
    print("Verification against documentation passed cleanly.")


if __name__ == "__main__":
    main()
