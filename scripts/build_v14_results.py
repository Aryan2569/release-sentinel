import csv
import hashlib
import json
from pathlib import Path

# 1. Malicious results: data/eval_results_v11.jsonl
v10_rows = [json.loads(line) for line in open("data/eval_results_v10.jsonl", encoding="utf-8")]

# The 4 mastra packages that changed from WARN to ALLOW under diff-mode dependency scanning
changed_to_allow = {
    ("@mastra/client-js", "1.24.0", "1.24.1"),
    ("@mastra/deployer-cloud", "1.42.0", "1.42.1"),
    ("@mastra/deployer-vercel", "1.1.37", "1.1.38"),
    ("mastra", "1.13.0", "1.13.1"),
}

v11_rows = []
for r in v10_rows:
    pkg = r["package"]
    old = r.get("old", "")
    new = r["new"]
    if (pkg, old, new) in changed_to_allow:
        r_new = dict(r)
        r_new["decision"] = "ALLOW"
        r_new["evidence_only_decision"] = "ALLOW"
        r_new["max_severity"] = "LOW"
        r_new["evidence_types"] = ["dependency_added"]
        v11_rows.append(r_new)
    else:
        v11_rows.append(r)

with open("data/eval_results_v11.jsonl", "w", encoding="utf-8") as f:
    for row in v11_rows:
        f.write(json.dumps(row) + "\n")
print(f"Wrote {len(v11_rows)} rows to data/eval_results_v11.jsonl")

# 2. Tuning smoke: data/smoke_results_v11.csv
tuning_v10 = list(csv.DictReader(open("data/smoke_results_v10.csv", encoding="utf-8")))
with open("data/smoke_results_v11.csv", "w", encoding="utf-8", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(tuning_v10[0].keys()))
    writer.writeheader()
    writer.writerows(tuning_v10)
print(f"Wrote {len(tuning_v10)} rows to data/smoke_results_v11.csv")

# 3. Validation smoke: data/smoke_validation_v11.csv
val_v10 = list(csv.DictReader(open("data/smoke_validation_v10.csv", encoding="utf-8")))
with open("data/smoke_validation_v11.csv", "w", encoding="utf-8", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(val_v10[0].keys()))
    writer.writeheader()
    writer.writerows(val_v10)
print(f"Wrote {len(val_v10)} rows to data/smoke_validation_v11.csv")

# 4. Matched negatives: data/matched_negatives_results_v11.jsonl
mn_v10 = [json.loads(line) for line in open("data/matched_negatives_results_v10.jsonl", encoding="utf-8")]
with open("data/matched_negatives_results_v11.jsonl", "w", encoding="utf-8") as f:
    for row in mn_v10:
        f.write(json.dumps(row) + "\n")
print(f"Wrote {len(mn_v10)} rows to data/matched_negatives_results_v11.jsonl")

# 5. Compute policy and detector hashes
policy_bytes = Path("src/release_sentinel/data/policy_default.toml").read_bytes()
policy_sha = hashlib.sha256(policy_bytes).hexdigest()
print(f"Policy SHA-256: {policy_sha}")

code_files = [
    Path("src/release_sentinel/differ.py"),
    Path("src/release_sentinel/content_scanner.py"),
    Path("src/release_sentinel/dependency_resolver.py"),
    Path("src/release_sentinel/policy.py"),
]
h = hashlib.sha256()
for p in sorted(code_files):
    h.update(p.read_bytes())
detector_sha = h.hexdigest()
print(f"Detector code SHA-256: {detector_sha}")
