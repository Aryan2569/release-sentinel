import json
from collections import Counter
from pathlib import Path

# Load camp_0066 from eval_campaigns.json
campaigns_file = Path("data/eval_campaigns.json")
with open(campaigns_file, encoding="utf-8") as f:
    camps = json.load(f)

camp = camps["camp_0066"]
print(f"Campaign: {camp['campaign_id']}, Size: {camp['size']}, Split: {camp['primary_split']}")
members = set(camp["members"])

# Parse member strings: "pkg@old@new"
member_keys = set()
for m in members:
    parts = m.split("@")
    if m.startswith("@"):
        # Scoped package: @scope/name@old@new
        pkg = f"@{parts[1]}"
        old = parts[2]
        new = parts[3]
    else:
        pkg = parts[0]
        old = parts[1]
        new = parts[2]
    member_keys.add((pkg, old, new))

print(f"Total member keys parsed: {len(member_keys)}")

# Load results from eval_results_v9.jsonl
results_file = Path("data/eval_results_v9.jsonl")
eval_res = []
with open(results_file, encoding="utf-8") as f:
    for line in f:
        data = json.loads(line)
        key = (data["package"], data.get("old", ""), data["new"])
        if key in member_keys:
            eval_res.append(data)

print(f"Found in eval_results_v9: {len(eval_res)}")
decisions = Counter(r["decision"] for r in eval_res)
print("Decisions:", decisions)

# Check distinct evidence combinations
ev_combos = Counter()
all_ev_counts = Counter()
for r in eval_res:
    ev_list = tuple(sorted(r["evidence_types"]))
    ev_combos[ev_list] += 1
    for ev in r["evidence_types"]:
        all_ev_counts[ev] += 1

print("\nDistinct evidence combinations:")
for combo, count in ev_combos.items():
    print(f"  Count: {count}")
    for item in combo:
        print(f"    - {item}")

print("\nTotal counts across all 60 pairs:")
for ev, count in all_ev_counts.most_common():
    print(f"  {ev}: {count}")

# Sample pair details
print("\nSample pair details:")
for r in eval_res[:3]:
    print(f"  {r['package']}@{r.get('old', '')} -> {r['new']}")
    print(f"  Decision: {r['decision']}, max_severity: {r['max_severity']}")
    print(f"  Evidence: {r['evidence_types']}")
