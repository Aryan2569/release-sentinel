import json

v11 = [json.loads(line) for line in open('data/eval_results_v6.jsonl', encoding='utf-8')]
v121 = [json.loads(line) for line in open('data/eval_results_v8.jsonl', encoding='utf-8')]
camps = json.load(open('data/eval_campaigns.json', encoding='utf-8'))

# Old split mapping (prior to pure date cutoff)
def old_assign_split(package, discovery_date):
    if discovery_date < "2026-01-01":
        return "DEV"
    if discovery_date <= "2026-04-30":
        return "VAL"
    if discovery_date < "2026-06-17":
        return "TEST-A"
    if discovery_date == "2026-06-17":
        if package <= "@mastra/clickhouse" or package == "@mastra/openai":
            return "TEST-A"
        return "TEST-B"
    return "TEST-B"

pair_to_camp = {}
for cid, c in camps.items():
    for m in c['members']:
        pair_to_camp[m] = cid

v11_map = {f"{r['package']}@{r['old']}@{r['new']}": r for r in v11}
v121_map = {f"{r['package']}@{r['old']}@{r['new']}": r for r in v121}

diffs = []
for k in v11_map:
    r11 = v11_map[k]
    r121 = v121_map[k]
    old_split = old_assign_split(r11['package'], r11['discovery_date'])
    if r11['decision'] != r121['decision'] and old_split == 'TEST-A':
        diffs.append((k, r11['decision'], r121['decision'], r11.get('evidence_types'), r121.get('evidence_types'), pair_to_camp.get(k)))

print(f"Total TEST-A differences (old boundary): {len(diffs)}")
for d in diffs:
    print(d[0], "camp:", d[5], "v1.1:", d[1], "v1.2.1:", d[2], "ev_diff:", set(d[4]) - set(d[3]))
