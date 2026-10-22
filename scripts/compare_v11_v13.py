import json
import sys

sys.path.insert(0, ".")
from collections import defaultdict

from scripts.build_campaigns import assign_split, clopper_pearson

# Load results
v11_rows = [json.loads(line) for line in open("data/eval_results_v6.jsonl", encoding="utf-8")]
v13_rows = [json.loads(line) for line in open("data/eval_results_v9.jsonl", encoding="utf-8")]
v121_rows = [json.loads(line) for line in open("data/eval_results_v8.jsonl", encoding="utf-8")]

camps = json.load(open("data/eval_campaigns.json", encoding="utf-8"))
pair_to_camp = {}
for cid, c in camps.items():
    for m in c["members"]:
        pair_to_camp[m] = cid

top5_cids = [c["campaign_id"] for c in sorted(camps.values(), key=lambda c: c["size"], reverse=True)[:5]]

def analyze_version(name, rows):
    by_split = defaultdict(list)
    by_camp = defaultdict(list)
    pair_map = {}
    for r in rows:
        pair_key = f"{r['package']}@{r['old']}@{r['new']}"
        s = assign_split(r["package"], r["discovery_date"])
        r["eval_split"] = s
        by_split[s].append(r)
        by_split["ALL"].append(r)
        cid = pair_to_camp.get(pair_key)
        if cid:
            by_camp[cid].append(r)
        pair_map[pair_key] = r

    print(f"\n================ {name} ================")
    print("--- Pair-level recall ---")
    for s in ["ALL", "DEV", "VAL", "TEST-A", "TEST-B"]:
        r_list = by_split[s]
        n = len(r_list)
        warn_cnt = sum(1 for r in r_list if r.get("decision") in ("WARN", "BLOCK"))
        block_cnt = sum(1 for r in r_list if r.get("decision") == "BLOCK")
        print(f"  {s:7s} (n={n:4d}): WARN+ = {warn_cnt:4d} ({warn_cnt/n*100:5.2f}%), BLOCK = {block_cnt:4d} ({block_cnt/n*100:5.2f}%)")

    print("\n--- Campaign-level recall ---")
    for s in ["ALL", "DEV", "VAL", "TEST-A", "TEST-B"]:
        if s == "ALL":
            target_cids = list(camps.keys())
        else:
            target_cids = [cid for cid, c in camps.items() if c["primary_split"] == s]
        n_camps = len(target_cids)
        lenient_warn = 0
        lenient_block = 0
        macro_warn_sum = 0.0
        macro_block_sum = 0.0

        for cid in target_cids:
            c_pairs = [r for r in by_camp[cid] if (s == "ALL" or r["eval_split"] == s)]
            if not c_pairs:
                continue
            c_warn = sum(1 for r in c_pairs if r.get("decision") in ("WARN", "BLOCK"))
            c_block = sum(1 for r in c_pairs if r.get("decision") == "BLOCK")
            if c_warn > 0:
                lenient_warn += 1
            if c_block > 0:
                lenient_block += 1
            macro_warn_sum += (c_warn / len(c_pairs))
            macro_block_sum += (c_block / len(c_pairs))

        lw_pct = lenient_warn / n_camps * 100
        lb_pct = lenient_block / n_camps * 100
        mw_pct = macro_warn_sum / n_camps * 100
        mb_pct = macro_block_sum / n_camps * 100
        lw_ci = clopper_pearson(lenient_warn, n_camps)
        lb_ci = clopper_pearson(lenient_block, n_camps)
        print(f"  {s:7s} ({lenient_warn}/{n_camps}): Lenient WARN = {lw_pct:5.2f}% [{lw_ci[0]*100:.1f}%, {lw_ci[1]*100:.1f}%], Lenient BLOCK = {lenient_block}/{n_camps} ({lb_pct:5.2f}%) [{lb_ci[0]*100:.1f}%, {lb_ci[1]*100:.1f}%] | Macro WARN = {mw_pct:5.2f}%, Macro BLOCK = {mb_pct:5.2f}%")

    print("\n--- Top 5 Campaigns member pair recall ---")
    for cid in top5_cids:
        c = camps[cid]
        c_pairs = by_camp[cid]
        n_m = len(c_pairs)
        w_cnt = sum(1 for r in c_pairs if r.get("decision") in ("WARN", "BLOCK"))
        b_cnt = sum(1 for r in c_pairs if r.get("decision") == "BLOCK")
        print(f"  {cid} ({c['primary_split']}, size={n_m}): WARN+ = {w_cnt}/{n_m} ({w_cnt/n_m*100:5.2f}%), BLOCK = {b_cnt}/{n_m} ({b_cnt/n_m*100:5.2f}%)")

analyze_version("v1.1 (eval_results_v6)", v11_rows)
analyze_version("v1.3 (eval_results_v9)", v13_rows)
analyze_version("v1.2.1 (eval_results_v8)", v121_rows)
