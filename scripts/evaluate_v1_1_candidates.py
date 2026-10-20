"""Evaluate v1.1 Policy Candidates under strict Stage 5c guardrails.

Guardrails:
1. Zero false BLOCKs across all 800 benign updates (non-negotiable).
2. Highest cluster BLOCK recall on DEV+VAL+TEST-A (179 clusters).
3. Lowest benign alert rate (must not rise by >3/100 without notification).
4. 95% confidence upper bound on false BLOCK rate (Rule of Three: ~3/N).
"""

from __future__ import annotations

import copy
import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from release_sentinel.models import Decision, Evidence, Severity
from release_sentinel.policy import BlockRequires, Policy, decide, load_policy

# Load benign evidence
tuning_smoke = list(csv.DictReader(open("data/smoke_results_v5.csv", encoding="utf-8")))
val_smoke = list(csv.DictReader(open("data/smoke_validation_v5.csv", encoding="utf-8")))
matched_neg = [
    json.loads(line) for line in open("data/matched_negatives_results_v5.jsonl", encoding="utf-8")
]

# Standard default severities from content_scanner & differ
DEFAULT_SEVERITIES: dict[str, Severity] = {
    "dynamic_code": Severity.HIGH,
    "long_encoded_blob": Severity.MEDIUM,
    "high_entropy_string": Severity.MEDIUM,
    "notable_new_file": Severity.MEDIUM,
    "install_script_added": Severity.HIGH,
    "install_script_changed": Severity.HIGH,
    "install_script_present": Severity.LOW,
    "install_script_network": Severity.CRITICAL,
    "install_script_executes": Severity.CRITICAL,
    "install_script_dynamic": Severity.CRITICAL,
    "install_script_env_harvesting": Severity.CRITICAL,
    "decode_and_execute": Severity.HIGH,
    "credential_leak": Severity.CRITICAL,
    "credential_file_read": Severity.HIGH,
    "network_access": Severity.HIGH,
    "hardcoded_url": Severity.LOW,
    "hardcoded_ip": Severity.HIGH,
    "process_exec": Severity.HIGH,
    "env_enumeration": Severity.HIGH,
    "registry_token": Severity.CRITICAL,
    "ci_write": Severity.HIGH,
    "shell_profile_write": Severity.HIGH,
    "obfuscated_code": Severity.HIGH,
    "large_size_jump": Severity.MEDIUM,
    "large_file_count_jump": Severity.MEDIUM,
    "new_files_summary": Severity.MEDIUM,
    "dependency_added": Severity.LOW,
    "dependency_removed": Severity.MEDIUM,
    "dependency_version_changed": Severity.MEDIUM,
    "bin_entry_added": Severity.MEDIUM,
    "bin_entry_changed": Severity.MEDIUM,
    "unresolvable_dependency": Severity.INFO,
    "inspection_incomplete": Severity.MEDIUM,
    "inspection_failed": Severity.MEDIUM,
}


def make_evidence_list(ev_types: list[str]) -> list[Evidence]:
    return [
        Evidence(
            id=eid,
            severity=DEFAULT_SEVERITIES.get(eid, Severity.MEDIUM),
            explanation="",
            legitimate_use_note="",
        )
        for eid in ev_types
    ]


# Prepare 800 benign entries
benign_entries: list[dict[str, Any]] = []
for r in tuning_smoke:
    evs = [s.strip() for s in r["evidence_types"].split(";") if s.strip()]
    benign_entries.append(
        {"set": "tuning", "pkg": r["package"], "evidence": make_evidence_list(evs)}
    )
for r in val_smoke:
    evs = [s.strip() for s in r["evidence_types"].split(";") if s.strip()]
    benign_entries.append(
        {"set": "val", "pkg": r["package"], "evidence": make_evidence_list(evs)}
    )
for r in matched_neg:
    evs = r.get("evidence_types", [])
    benign_entries.append(
        {"set": "matched", "pkg": r["package"], "evidence": make_evidence_list(evs)}
    )

# Prepare 179 unlocked malicious clusters
eval_results = [json.loads(line) for line in open("data/eval_results_v5.jsonl", encoding="utf-8")]
clusters = json.load(open("data/eval_clusters_v5.json", encoding="utf-8"))
test_cids = sorted(
    {e["cluster_id"] for e in eval_results if e["split"] == "TEST"},
    key=lambda cid: (clusters[cid]["earliest_discovery"], clusters[cid]["rank"], cid),
)
test_a_cids = set(test_cids[:98])
for e in eval_results:
    if e["split"] == "TEST":
        e["split"] = "TEST-A" if e["cluster_id"] in test_a_cids else "TEST-B"

unlocked_pairs = [e for e in eval_results if e["split"] in ("DEV", "VAL", "TEST-A")]
cluster_pairs = defaultdict(list)
for p in unlocked_pairs:
    cluster_pairs[p["cluster_id"]].append(p)

print(
    f"Loaded {len(benign_entries)} benign entries and {len(cluster_pairs)} unlocked clusters."
)


def evaluate_policy(name: str, policy: Policy) -> dict[str, Any]:
    # 1. Benign evaluation
    b_blocks = {"tuning": 0, "val": 0, "matched": 0, "total": 0}
    b_warns = {"tuning": 0, "val": 0, "matched": 0, "total": 0}

    for b in benign_entries:
        dec, _ = decide(b["evidence"], policy=policy)
        sname = b["set"]
        if dec == Decision.BLOCK:
            b_blocks[sname] += 1
            b_blocks["total"] += 1
        elif dec == Decision.WARN:
            b_warns[sname] += 1
            b_warns["total"] += 1

    total_benign = len(benign_entries)
    alert_rate = (b_blocks["total"] + b_warns["total"]) / total_benign * 100
    t_alert_rate = (b_blocks["tuning"] + b_warns["tuning"]) / 100 * 100
    v_alert_rate = (b_blocks["val"] + b_warns["val"]) / 100 * 100
    m_alert_rate = (b_blocks["matched"] + b_warns["matched"]) / 600 * 100

    # 2. Malicious evaluation across 179 clusters
    lenient_block = 0
    lenient_warn = 0
    macro_block_sum = 0.0
    macro_warn_sum = 0.0

    cohort_blocks = {"DEV": 0, "VAL": 0, "TEST-A": 0}

    for _cid, cpairs in cluster_pairs.items():
        c_blocks = 0
        c_warns = 0
        split = cpairs[0]["split"]

        for p in cpairs:
            evs = make_evidence_list(p.get("evidence_types", []))
            dec, _ = decide(evs, policy=policy)
            if dec == Decision.BLOCK:
                c_blocks += 1
            if dec in (Decision.WARN, Decision.BLOCK):
                c_warns += 1

        if c_blocks > 0:
            lenient_block += 1
            cohort_blocks[split] += 1
        if c_warns > 0:
            lenient_warn += 1

        macro_block_sum += c_blocks / len(cpairs)
        macro_warn_sum += c_warns / len(cpairs)

    n_c = len(cluster_pairs)
    return {
        "name": name,
        "false_blocks": b_blocks["total"],
        "benign_alert_rate": alert_rate,
        "tuning_rate": t_alert_rate,
        "val_rate": v_alert_rate,
        "matched_rate": m_alert_rate,
        "cluster_block_lenient": f"{lenient_block}/{n_c} ({lenient_block/n_c*100:.2f}%)",
        "cluster_block_macro": f"{macro_block_sum/n_c*100:.2f}%",
        "dev_block": f"{cohort_blocks['DEV']}/69 ({cohort_blocks['DEV']/69*100:.1f}%)",
        "val_block": f"{cohort_blocks['VAL']}/12 ({cohort_blocks['VAL']/12*100:.1f}%)",
        "test_a_block": f"{cohort_blocks['TEST-A']}/98 ({cohort_blocks['TEST-A']/98*100:.1f}%)",
        "raw_block": lenient_block,
    }


def main() -> None:
    # Build 5 Policy Variants
    v1_0 = load_policy(Path("data/policy_default.toml"))

    # Variant 1: Obfuscation Corroboration (dynamic_code + long_encoded_blob)
    var1 = copy.deepcopy(v1_0)
    var1.block_requires.append(
        BlockRequires(
            signals=["dynamic_code", "long_encoded_blob"],
            description="Dynamic code execution combined with encoded blob",
        )
    )

    # Variant 2: Obfuscation + Size Jump
    var2 = copy.deepcopy(var1)
    var2.block_requires.append(
        BlockRequires(
            signals=["dynamic_code", "large_size_jump"],
            description="Dynamic code execution combined with large size jump",
        )
    )

    # Variant 3: Obfuscation + Corroborated Dependency Addition
    var3 = copy.deepcopy(var2)
    var3.block_requires.extend([
        BlockRequires(
            signals=["dependency_added", "install_script_added"],
            description="Added dependency alongside added lifecycle script",
        ),
        BlockRequires(
            signals=["dependency_added", "dynamic_code"],
            description="Added dependency combined with dynamic code execution",
        ),
        BlockRequires(
            signals=["dependency_added", "hardcoded_ip"],
            description="Added dependency combined with hardcoded IP",
        ),
    ])

    # Variant 4: Variant 3 + Noise Reduction (downgrade signals with lift < 1.5)
    var4 = copy.deepcopy(var3)
    var4.severity_overrides.update({
        "dependency_version_changed": Severity.LOW,
        "large_file_count_jump": Severity.LOW,
        "dependency_removed": Severity.LOW,
    })

    # Variant 5: Variant 4 + Bin Entry Downgrades (lift < 1.5)
    var5 = copy.deepcopy(var4)
    var5.severity_overrides.update({
        "bin_entry_added": Severity.LOW,
        "bin_entry_changed": Severity.LOW,
    })

    variants = [
        ("v1.0 Frozen Baseline", v1_0),
        ("Variant 1 (Dynamic + Encoded Blob)", var1),
        ("Variant 2 (Dynamic + Encoded Blob + Size Jump)", var2),
        ("Variant 3 (Var 2 + Corroborated Dep Added)", var3),
        ("Variant 4 (Var 3 + Low-Lift Downgrades)", var4),
        ("Variant 5 (Var 4 + Bin Entry Downgrades)", var5),
    ]

    print("\n" + "=" * 120)
    print("STAGE 5c POLICY SWEEP RESULTS (DEV + VAL + TEST-A: 179 Clusters | Benign: 800 Updates)")
    print("=" * 120)
    print(
        f"{'Variant':<42} | {'False BLOCK':<11} | {'Alert Rate':<10} | {'Tuning':<7} | "
        f"{'Val':<7} | {'Matched':<7} | {'Cluster BLOCK':<18} | {'DEV':<12} | "
        f"{'VAL':<10} | {'TEST-A':<12}"
    )
    print("-" * 145)

    for name, pol in variants:
        res = evaluate_policy(name, pol)
        print(
            f"{res['name']:<42} | {res['false_blocks']:<11d} | {res['benign_alert_rate']:<9.2f}% | "
            f"{res['tuning_rate']:<6.1f}% | {res['val_rate']:<6.1f}% | "
            f"{res['matched_rate']:<6.1f}% | {res['cluster_block_lenient']:<18} | "
            f"{res['dev_block']:<12} | {res['val_block']:<10} | {res['test_a_block']:<12}"
        )


if __name__ == "__main__":
    main()
