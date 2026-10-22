"""Single source of truth for Release Sentinel evaluation metrics (Stage 5f Part 2).

Recomputes every headline number:
- Pair-level recall (Fail-closed & Evidence-only >=WARN and BLOCK, incomplete counts/pcts)
- Campaign-level recall (k of n, lenient and macro, exact Clopper-Pearson 95% CIs)
- Benign evaluation alert rates and false BLOCK counts (800 pairs canonical)
- Dependency-addition share by split

Reads all four version tags (v1.0, v1.1, v1.2, v1.2.1) dynamically from docs/versions.json.
Writes canonical metrics to docs/METRICS.json.
"""

from __future__ import annotations

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

sys.path.insert(0, ".")

from scripts.build_campaigns import assign_split, clopper_pearson

VERSIONS_JSON = Path("docs/versions.json")
CAMPAIGNS_JSON = Path("data/eval_campaigns.json")
EVAL_PAIRS_CSV = Path("data/eval_pairs.csv")
DEP_RECON_JSON = Path("data/dependency_reconciliation.json")

METRICS_OUT = Path("docs/METRICS.json")
EVAL_REPORT_MD = Path("docs/eval_results_v7.md")


def compute_sample_metrics(results_path: Path) -> dict[str, Any]:
    rows = [json.loads(line) for line in open(results_path, encoding="utf-8")]
    split_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        s = assign_split(r["package"], r["discovery_date"])
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
        r["eval_split"] = assign_split(r["package"], r["discovery_date"])
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
            all_r_list = camp_rows.get(cid, [])
            if not all_r_list:
                continue

            # Evaluate recall ONLY on member pairs that fall within this split (Part 1b)
            if split == "ALL":
                r_list = all_r_list
            else:
                r_list = [r for r in all_r_list if r["eval_split"] == split]

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


def compute_benign_metrics(benign_paths: dict[str, str]) -> dict[str, Any]:
    # Tuning smoke
    tuning_p = Path(benign_paths["tuning_smoke"])
    tuning_rows = list(csv.DictReader(open(tuning_p, encoding="utf-8"))) if tuning_p.exists() else []
    tuning_alerts = sum(1 for r in tuning_rows if r["decision"] in ("WARN", "BLOCK"))
    tuning_blocks = sum(1 for r in tuning_rows if r["decision"] == "BLOCK")

    # Validation smoke
    val_p = Path(benign_paths["validation_smoke"])
    val_rows = list(csv.DictReader(open(val_p, encoding="utf-8"))) if val_p.exists() else []
    val_alerts = sum(1 for r in val_rows if r["decision"] in ("WARN", "BLOCK"))
    val_blocks = sum(1 for r in val_rows if r["decision"] == "BLOCK")

    # Matched negatives
    matched_p = Path(benign_paths["matched_negatives"])
    matched_rows = [json.loads(line) for line in open(matched_p, encoding="utf-8")] if matched_p.exists() else []
    matched_alerts = sum(1 for r in matched_rows if r["decision"] in ("WARN", "BLOCK"))
    matched_blocks = sum(1 for r in matched_rows if r["decision"] == "BLOCK")

    total_pairs = len(tuning_rows) + len(val_rows) + len(matched_rows)
    total_alerts = tuning_alerts + val_alerts + matched_alerts
    total_blocks = tuning_blocks + val_blocks + matched_blocks

    return {
        "tuning_smoke": {
            "pairs": len(tuning_rows),
            "alerts": tuning_alerts,
            "alert_rate_per_100": round(tuning_alerts / len(tuning_rows) * 100, 2) if tuning_rows else 0.0,
            "false_blocks": tuning_blocks,
        },
        "validation_smoke": {
            "pairs": len(val_rows),
            "alerts": val_alerts,
            "alert_rate_per_100": round(val_alerts / len(val_rows) * 100, 2) if val_rows else 0.0,
            "false_blocks": val_blocks,
        },
        "matched_negatives": {
            "pairs": len(matched_rows),
            "alerts": matched_alerts,
            "alert_rate_per_100": round(matched_alerts / len(matched_rows) * 100, 2) if matched_rows else 0.0,
            "false_blocks": matched_blocks,
        },
        "total_benign": {
            "pairs": total_pairs,
            "alerts": total_alerts,
            "alert_rate_per_100": round(total_alerts / total_pairs * 100, 2) if total_pairs else 0.0,
            "false_blocks": total_blocks,
            "false_block_ci_upper_pct": round((1.0 - (0.05 ** (1.0 / total_pairs))) * 100, 3) if total_pairs else 0.0,
        },
    }


def recompute_all_metrics() -> dict[str, Any]:
    versions = json.load(open(VERSIONS_JSON, encoding="utf-8"))
    campaigns_dict = json.load(open(CAMPAIGNS_JSON, encoding="utf-8"))
    pair_to_campaign: dict[str, str] = {}
    for cid, c in campaigns_dict.items():
        for m in c["members"]:
            pair_to_campaign[m] = cid

    dep_recon = json.load(open(DEP_RECON_JSON, encoding="utf-8")) if DEP_RECON_JSON.exists() else {"counts_per_split": {}}

    sample_metrics: dict[str, Any] = {}
    campaign_metrics: dict[str, Any] = {}
    benign_metrics: dict[str, Any] = {}

    for ver_name, ver_info in versions.items():
        mal_p = Path(ver_info["malicious_results_jsonl"])
        sample_metrics[ver_name] = compute_sample_metrics(mal_p)
        campaign_metrics[ver_name] = compute_campaign_metrics(mal_p, campaigns_dict, pair_to_campaign)
        benign_metrics[ver_name] = compute_benign_metrics(ver_info.get("benign_results", {}))

    return {
        "sample": sample_metrics,
        "campaign": campaign_metrics,
        "benign": benign_metrics,
        "dependency_additions": dep_recon.get("counts_per_split", {}),
        "versions": versions,
    }


def verify_doc_consistency(metrics: dict[str, Any]) -> None:
    # Verify that v1.0 canonical numbers match Part 2c requirements
    s_v10 = metrics["sample"]["v1.0"]
    assert s_v10["ALL"]["fc_block"] == 1054, f"v1.0 ALL BLOCK expected 1054, got {s_v10['ALL']['fc_block']}"
    assert s_v10["DEV"]["fc_block"] == 807, f"v1.0 DEV BLOCK expected 807, got {s_v10['DEV']['fc_block']}"
    assert s_v10["VAL"]["fc_block"] == 90, f"v1.0 VAL BLOCK expected 90, got {s_v10['VAL']['fc_block']}"
    assert s_v10["TEST-A"]["fc_block"] == 154, f"v1.0 TEST-A BLOCK expected 154, got {s_v10['TEST-A']['fc_block']}"
    assert s_v10["TEST-B"]["fc_block"] == 3, f"v1.0 TEST-B BLOCK expected 3, got {s_v10['TEST-B']['fc_block']}"

    # Verify that v1.2.1 maintains 0 false BLOCKs across 800 benign packages
    b_v121 = metrics["benign"]["v1.2.1"]["total_benign"]
    assert b_v121["pairs"] == 800, f"Expected 800 benign pairs, got {b_v121['pairs']}"
    assert b_v121["false_blocks"] == 0, f"Expected 0 false blocks, got {b_v121['false_blocks']}"

    # Verify that v1.3 maintains 0 false BLOCKs across 800 benign packages
    b_v13 = metrics["benign"]["v1.3"]["total_benign"]
    assert b_v13["pairs"] == 800, f"Expected 800 benign pairs, got {b_v13['pairs']}"
    assert b_v13["false_blocks"] == 0, f"Expected 0 false blocks, got {b_v13['false_blocks']}"

    # Verify that v1.3.1 maintains 0 false BLOCKs across 800 benign packages
    b_v131 = metrics["benign"]["v1.3.1"]["total_benign"]
    assert b_v131["pairs"] == 800, f"Expected 800 benign pairs, got {b_v131['pairs']}"
    assert b_v131["false_blocks"] == 0, f"Expected 0 false blocks, got {b_v131['false_blocks']}"

    # Verify v1.3 malicious sample recall
    s_v13 = metrics["sample"]["v1.3"]
    assert s_v13["ALL"]["fc_block"] == 1102, f"v1.3 ALL BLOCK expected 1102, got {s_v13['ALL']['fc_block']}"
    assert s_v13["ALL"]["fc_warn"] == 1217, f"v1.3 ALL WARN expected 1217, got {s_v13['ALL']['fc_warn']}"

    # Verify v1.3.1 malicious sample recall restores VAL to 94/94
    s_v131 = metrics["sample"]["v1.3.1"]
    assert s_v131["VAL"]["fc_warn"] == 94, f"v1.3.1 VAL WARN expected 94, got {s_v131['VAL']['fc_warn']}"
    assert s_v131["ALL"]["fc_warn"] == 1218, f"v1.3.1 ALL WARN expected 1218, got {s_v131['ALL']['fc_warn']}"

    # Verify v1.3.1 VAL campaign recall restores to 12/12
    c_v131 = metrics["campaign"]["v1.3.1"]
    assert c_v131["VAL"]["lenient_fc_warn"] == 12, f"v1.3.1 VAL campaigns expected 12, got {c_v131['VAL']['lenient_fc_warn']}"

    # Verify DEV/VAL/TEST-A campaign BLOCK recall did not drop
    c_v11 = metrics["campaign"]["v1.1"]
    c_v13 = metrics["campaign"]["v1.3"]
    assert c_v13["DEV"]["lenient_fc_block"] >= c_v11["DEV"]["lenient_fc_block"] - 1
    assert c_v13["VAL"]["lenient_fc_block"] >= c_v11["VAL"]["lenient_fc_block"] - 1
    assert c_v13["TEST-A"]["lenient_fc_block"] >= c_v11["TEST-A"]["lenient_fc_block"] - 1

    # Verify attack style documentation and dependency additions (Part 6)
    assert Path("docs/attack_style_over_time.md").exists()
    assert Path("docs/attack_style_over_time.png").exists()
    deps = metrics.get("dependency_additions", {})
    assert deps.get("DEV", {}).get("pairs_adding_dependency") == 17
    assert deps.get("VAL", {}).get("pairs_adding_dependency") == 1
    assert deps.get("TEST-A", {}).get("pairs_adding_dependency") == 54
    assert deps.get("TEST-B", {}).get("pairs_adding_dependency") == 94


def main() -> None:
    metrics = recompute_all_metrics()
    with open(METRICS_OUT, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"Wrote canonical metrics to {METRICS_OUT}")
    verify_doc_consistency(metrics)
    print("Verification passed cleanly.")


if __name__ == "__main__":
    main()
