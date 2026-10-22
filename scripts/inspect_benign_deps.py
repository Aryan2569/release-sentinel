import csv
import json
from collections import Counter
from pathlib import Path

# Examine all 800 benign pairs for dependency_added
sets = [
    ("Tuning smoke (100)", Path("data/smoke_results_v9.csv"), "csv"),
    ("Validation smoke (100)", Path("data/smoke_validation_v9.csv"), "csv"),
    ("Matched negatives (600)", Path("data/matched_negatives_results_v9.jsonl"), "jsonl"),
]

total_pairs = 0
total_dep_added = 0
dep_decisions = Counter()
dep_pairs = []

for set_name, path, fmt in sets:
    if fmt == "csv":
        rows = list(csv.DictReader(open(path, encoding="utf-8")))
        for r in rows:
            total_pairs += 1
            ev_str = r.get("evidence_types", "")
            ev_list = [e.strip() for e in ev_str.split(";") if e.strip()] if ev_str else []
            if "dependency_added" in ev_list:
                total_dep_added += 1
                dep_decisions[r["decision"]] += 1
                dep_pairs.append({
                    "set": set_name,
                    "pkg": r["package"],
                    "old": r.get("old") or r.get("old_version", ""),
                    "new": r.get("new") or r.get("new_version", ""),
                    "decision": r["decision"],
                    "evidence": ev_list,
                })
    else:
        with open(path, encoding="utf-8") as f:
            for line in f:
                total_pairs += 1
                r = json.loads(line)
                ev_list = r.get("evidence_types", [])
                if "dependency_added" in ev_list:
                    total_dep_added += 1
                    dep_decisions[r["decision"]] += 1
                    dep_pairs.append({
                        "set": set_name,
                        "pkg": r["package"],
                        "old": r.get("old") or r.get("old_version", ""),
                        "new": r.get("new") or r.get("new_version", ""),
                        "decision": r["decision"],
                        "evidence": ev_list,
                    })

print(f"Total benign pairs examined: {total_pairs}")
print(f"Benign pairs adding dependencies: {total_dep_added}")
print("Decisions for pairs adding dependencies:", dep_decisions)
print("\nDetails of pairs adding dependencies:")
for p in dep_pairs:
    print(f"  [{p['set']}] {p['pkg']}@{p['old']} -> {p['new']}: {p['decision']}")
    print(f"    Evidence: {p['evidence']}")
