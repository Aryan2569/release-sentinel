"""Verify rule support across campaigns (Stage 5d Part 1)."""

import json
from collections import defaultdict

campaigns = json.load(open("data/eval_campaigns.json", encoding="utf-8"))
results_v6 = [json.loads(line) for line in open("data/eval_results_v6.jsonl", encoding="utf-8")]
clusters = json.load(open("data/eval_clusters_v6.json", encoding="utf-8"))

test_cids = sorted(
    {e["cluster_id"] for e in results_v6 if e["split"] == "TEST"},
    key=lambda cid: (clusters[cid]["earliest_discovery"], clusters[cid]["rank"], cid),
)
test_a_cids = set(test_cids[:98])
pair_to_split = {}
for e in results_v6:
    s = e["split"]
    if s == "TEST":
        s = "TEST-A" if e["cluster_id"] in test_a_cids else "TEST-B"
    pair_to_split[(e["package"], e["old"], e["new"])] = s

pair_to_camp = {}
for cid, c in campaigns.items():
    for m in c["members"]:
        pair_to_camp[m] = cid

rules_to_check = [
    "install_script_network",
    "install_script_executes",
    "ci_write",
    "obfuscated_code",
    ("dynamic_code", "long_encoded_blob"),
]

rule_campaigns = defaultdict(set)
rule_campaign_splits = defaultdict(lambda: defaultdict(set))

for r in results_v6:
    pair_key = f"{r['package']}@{r['old']}@{r['new']}"
    split = pair_to_split.get((r["package"], r["old"], r["new"]), "DEV")
    if split not in ("DEV", "VAL", "TEST-A"):
        continue
    cid = pair_to_camp.get(pair_key)
    if not cid:
        continue
    evs = set(r.get("evidence_types", []))

    for rule in rules_to_check:
        if isinstance(rule, tuple):
            if all(sub in evs for sub in rule):
                rule_campaigns["dynamic_code + long_encoded_blob"].add(cid)
                rule_campaign_splits["dynamic_code + long_encoded_blob"][split].add(cid)
        else:
            if rule in evs:
                rule_campaigns[rule].add(cid)
                rule_campaign_splits[rule][split].add(cid)

print("Independent campaign support across DEV+VAL+TEST-A:")
for rule, camps in rule_campaigns.items():
    splits_summary = {s: len(rule_campaign_splits[rule][s]) for s in ["DEV", "VAL", "TEST-A"]}
    print(f"  {rule}: {len(camps)} campaigns total ({splits_summary}) -> {sorted(camps)}")
