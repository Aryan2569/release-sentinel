"""Evaluate comment threshold variants on replay updates and malicious dataset."""

import json
from pathlib import Path

from release_sentinel.models import Severity
from release_sentinel.policy import load_policy

# Load default policy overrides
pol = load_policy(None)
overrides = {
    sig: (sev.name if isinstance(sev, Severity) else str(sev))
    for sig, sev in pol.severity_overrides.items()
}

# 1. Load 140 campaigns and pair-to-campaign mapping
with open("data/eval_campaigns.json", encoding="utf-8") as f:
    camps_dict = json.load(f)

pair_to_camp = {}
for cid, cinfo in camps_dict.items():
    for member in cinfo.get("members", []):
        pair_to_camp[member] = cid

print(f"Mapped {len(pair_to_camp)} pairs to 140 campaigns")

# 2. Replay updates (288 updates)
cache_dir = Path("data")
replay_files = list(cache_dir.glob("replay_cache_default_*.json"))
if not replay_files:
    cache_dir = Path(r"C:\My project\data")
    replay_files = list(cache_dir.glob("replay_cache_default_*.json"))

all_updates = []
for rf in replay_files:
    with open(rf, encoding="utf-8") as f:
        data = json.load(f)
        all_updates.extend(data.get("results", []))

print(f"Loaded {len(all_updates)} replay updates from {len(replay_files)} files")


def eval_replay(updates):
    cA, cB, cC = 0, 0, 0
    for u in updates:
        dec = u.get("decision")
        if dec == "BLOCK":
            cA += 1
            cB += 1
            cC += 1
            continue
        if dec == "WARN":
            warns = u.get("warns", [])
            has_A = False
            has_B = False
            for w in warns:
                # w is a non-ALLOW package (warned package)
                details = w.get("details", [])
                evs = w.get("evidence", [])

                eff_details = []
                for d in details:
                    sig_id = d.get("id")
                    raw_sev = d.get("severity")
                    eff_sev = overrides.get(sig_id, raw_sev)
                    eff_details.append({"id": sig_id, "effective_severity": eff_sev})

                has_high_crit = any(
                    d["effective_severity"] in ("HIGH", "CRITICAL") for d in eff_details
                )
                has_hook = any(
                    h in evs for h in ("install_script_added", "install_script_changed")
                )
                mediums = {
                    d["id"] for d in eff_details if d["effective_severity"] == "MEDIUM"
                }

                if has_high_crit or has_hook:
                    has_A = True
                    has_B = True
                    break
                if len(mediums) >= 2:
                    has_B = True

            if has_A:
                cA += 1
            if has_B:
                cB += 1
    return cA, cB, cC


rA, rB, rC = eval_replay(all_updates)
n_replay = len(all_updates)

# 3. Malicious evaluation (1,349 pairs, 140 campaigns)
with open("data/eval_results_default.jsonl", encoding="utf-8") as f:
    eval_rows = [json.loads(line) for line in f if line.strip()]

pA, pB, pC = 0, 0, 0
camps_hit_A = set()
camps_hit_B = set()
camps_hit_C = set()

for r in eval_rows:
    pair_key = f"{r['package']}@{r.get('old', '')}@{r['new']}"
    cid = pair_to_camp.get(pair_key)
    dec = r["decision"]
    evs = r.get("evidence_types", [])
    max_sev = r.get("max_severity")

    is_block = dec == "BLOCK"
    is_warn = dec == "WARN"

    if is_block:
        is_A = True
        is_B = True
        is_C = True
    elif is_warn:
        is_C = False
        has_high_crit = max_sev in ("HIGH", "CRITICAL")
        has_hook = any(h in evs for h in ("install_script_added", "install_script_changed"))
        # Effective medium signals in eval_results_default
        is_A = has_high_crit or has_hook
        is_B = is_A or (len(evs) >= 2)
    else:
        is_A = False
        is_B = False
        is_C = False

    if is_A:
        pA += 1
        if cid:
            camps_hit_A.add(cid)
    if is_B:
        pB += 1
        if cid:
            camps_hit_B.add(cid)
    if is_C:
        pC += 1
        if cid:
            camps_hit_C.add(cid)

n_pairs = len(eval_rows)
n_camps = len(camps_dict)

print("\n=== EVALUATION OF COMMENT THRESHOLD VARIANTS ===")
print("Variant A (BLOCK, or WARN with HIGH/CRITICAL or install hook):")
print(f"  Replay updates commented: {rA}/{n_replay} ({rA/n_replay*100:.2f}%)")
print(f"  Malicious pairs commented: {pA}/{n_pairs} ({pA/n_pairs*100:.2f}%)")
print(f"  Malicious campaigns commented: {len(camps_hit_A)}/{n_camps} ({len(camps_hit_A)/n_camps*100:.2f}%)")
print()
print("Variant B (A + >= 2 distinct MEDIUM evidence types) [CURRENT]:")
print(f"  Replay updates commented: {rB}/{n_replay} ({rB/n_replay*100:.2f}%)")
print(f"  Malicious pairs commented: {pB}/{n_pairs} ({pB/n_pairs*100:.2f}%)")
print(f"  Malicious campaigns commented: {len(camps_hit_B)}/{n_camps} ({len(camps_hit_B)/n_camps*100:.2f}%)")
print()
print("Variant C (BLOCK only):")
print(f"  Replay updates commented: {rC}/{n_replay} ({rC/n_replay*100:.2f}%)")
print(f"  Malicious pairs commented: {pC}/{n_pairs} ({pC/n_pairs*100:.2f}%)")
print(f"  Malicious campaigns commented: {len(camps_hit_C)}/{n_camps} ({len(camps_hit_C)/n_camps*100:.2f}%)")
print()
print("Campaign retention relative to B:")
print(f"  Variant A: {len(camps_hit_A)}/{len(camps_hit_B)} = {len(camps_hit_A)/len(camps_hit_B)*100:.2f}%")
print(f"  Variant C: {len(camps_hit_C)}/{len(camps_hit_B)} = {len(camps_hit_C)/len(camps_hit_B)*100:.2f}%")
