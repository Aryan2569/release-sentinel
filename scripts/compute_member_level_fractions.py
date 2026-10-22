import json
from pathlib import Path

# Load campaigns
with open("data/eval_campaigns.json", encoding="utf-8") as f:
    campaigns = json.load(f)

# Large campaigns (> 50 members)
large_cids = ["camp_0048", "camp_0052", "camp_0065", "camp_0066", "camp_0136"]

versions = {
    "v1.1": Path("data/eval_results_v6.jsonl"),
    "v1.2.1": Path("data/eval_results_v8.jsonl"),
    "v1.3": Path("data/eval_results_v9.jsonl"),
}

for ver, vpath in versions.items():
    rows = [json.loads(line) for line in open(vpath, encoding="utf-8")]
    pair_map = {f"{r['package']}@{r['old']}@{r['new']}": r for r in rows}

    print(f"\n==================== Version: {ver} ====================")
    # TEST-B overall
    test_b_rows = [r for r in rows if r.get("split") == "TEST-B" or (r["discovery_date"] >= "2026-06-17")]
    tb_n = len(test_b_rows)
    tb_fc_warn = sum(1 for r in test_b_rows if r.get("decision") in ("WARN", "BLOCK"))
    tb_fc_block = sum(1 for r in test_b_rows if r.get("decision") == "BLOCK")
    tb_eo_warn = sum(1 for r in test_b_rows if r.get("evidence_only_decision") in ("WARN", "BLOCK"))
    tb_eo_block = sum(1 for r in test_b_rows if r.get("evidence_only_decision") == "BLOCK")

    print(f"TEST-B Overall Member-Level ({tb_n} pairs):")
    print(f"  Fail-closed WARN+: {tb_fc_warn}/{tb_n} ({tb_fc_warn/tb_n*100:.2f}%)")
    print(f"  Fail-closed BLOCK: {tb_fc_block}/{tb_n} ({tb_fc_block/tb_n*100:.2f}%)")
    print(f"  Evidence-only WARN+: {tb_eo_warn}/{tb_n} ({tb_eo_warn/tb_n*100:.2f}%)")
    print(f"  Evidence-only BLOCK: {tb_eo_block}/{tb_n} ({tb_eo_block/tb_n*100:.2f}%)")

    print("\nCampaigns with > 50 members:")
    for cid in large_cids:
        c = campaigns[cid]
        members = c["members"]
        m_rows = [pair_map[m] for m in members if m in pair_map]
        n_m = len(m_rows)
        c_fc_warn = sum(1 for r in m_rows if r.get("decision") in ("WARN", "BLOCK"))
        c_fc_block = sum(1 for r in m_rows if r.get("decision") == "BLOCK")
        c_eo_warn = sum(1 for r in m_rows if r.get("evidence_only_decision") in ("WARN", "BLOCK"))
        c_eo_block = sum(1 for r in m_rows if r.get("evidence_only_decision") == "BLOCK")

        lenient_warn = "YES (1/1)" if c_fc_warn > 0 else "NO (0/1)"
        lenient_block = "YES (1/1)" if c_fc_block > 0 else "NO (0/1)"

        print(f"  {cid} ({c['primary_split']}, n={n_m}, leader={c['leader'][:40]}...):")
        print(f"    Lenient: WARN+={lenient_warn}, BLOCK={lenient_block}")
        print(f"    Member-level FC: WARN+={c_fc_warn}/{n_m} ({c_fc_warn/n_m*100:.2f}%), BLOCK={c_fc_block}/{n_m} ({c_fc_block/n_m*100:.2f}%)")
        print(f"    Member-level EO: WARN+={c_eo_warn}/{n_m} ({c_eo_warn/n_m*100:.2f}%), BLOCK={c_eo_block}/{n_m} ({c_eo_block/n_m*100:.2f}%)")
