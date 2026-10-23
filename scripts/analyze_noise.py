"""Detailed noise breakdown and root-cause classifier for Stage 6b Part 1."""

import glob
import json
from pathlib import Path

caches = glob.glob("data/replay_cache_*.json")
all_updates = []
for cpath in caches:
    repo_name = (
        cpath.replace("data\\replay_cache_", "")
        .replace("data/replay_cache_", "")
        .replace(".json", "")
    )
    data = json.loads(Path(cpath).read_text(encoding="utf-8"))
    for res in data.get("results", []):
        res["repo"] = repo_name
        all_updates.append(res)

print(f"Total updates: {len(all_updates)}")
block_updates = [u for u in all_updates if u["decision"] == "BLOCK"]
warn_updates = [u for u in all_updates if u["decision"] == "WARN"]
allow_updates = [u for u in all_updates if u["decision"] == "ALLOW"]
print(f"ALLOW: {len(allow_updates)}, WARN: {len(warn_updates)}, BLOCK: {len(block_updates)}")

# Classify root causes:
# (a) pattern bug
# (b) hook npm does not run for registry dependencies (prepare/prepublish)
# (c) multi-version jump or large bundled dev tool
# (d) legitimate install-time binary download
# (e) other

print("\n--- BLOCK UPDATES & DRIVERS ---")
for idx, u in enumerate(block_updates, 1):
    print(f"\nBLOCK Update #{idx}: {u['repo']} {u['pair_key']} ({u['subject'][:60]})")
    for b in u.get("blocks", []):
        pkg = b.get("package")
        ver = b.get("version")
        evs = b.get("evidence", [])
        # Find old version if available
        old_ver = "unknown"
        for pkg_res in u.get("package_results", []):
            if pkg_res.get("package") == pkg:
                old_ver = pkg_res.get("old_version", "none")
                break

        # Root cause classification
        ev_set = set(evs)
        rc = "(e) other"
        if pkg in ("enhanced-resolve", "xo", "cacheable-request", "chardet") and any("prepare" in str(d) or "prepublish" in str(d) for d in b.get("details", [])):
            rc = "(b) hook npm does not run for registry dependencies (prepare/prepublish)"
        elif pkg == "fsevents":
            rc = "(d) legitimate install-time binary download"
        elif any(k in pkg for k in ("vitest", "js-yaml", "bundlewatch", "esbuild", "jest", "webdriver", "prettier", "tapable", "terser", "unicorn", "iconv-lite")):
            rc = "(c) multi-version jump or large bundled dev tool"
        elif "decode_and_execute" in ev_set:
            rc = "(a) pattern bug"

        top_evs = [d.get("id") for d in b.get("details", []) if d.get("severity") in ("HIGH", "CRITICAL")]
        print(f"  * {pkg}@{old_ver}->{ver} | Driving: {list(set(top_evs))} | Class: {rc}")

print("\n--- WARN UPDATES & DRIVERS ---")
for idx, u in enumerate(warn_updates, 1):
    print(f"\nWARN Update #{idx}: {u['repo']} {u['pair_key']} ({u['subject'][:60]})")
    warn_pkgs = [p for p in u.get("package_results", []) if p.get("decision") == "WARN"]
    if not warn_pkgs:
        print(f"  * [Update-level limitation or replay error]: {u.get('evidence', [])}")
    for p in warn_pkgs:
        pkg = p.get("package")
        old_v = p.get("old_version")
        new_v = p.get("new_version")
        evs = p.get("evidence", [])
        ev_set = set(evs)

        rc = "(e) other"
        if any(sig in ev_set for sig in ("native_binary_present", "install_script_changed")):
            rc = "(d) legitimate install-time binary download / build"
        elif any(sig in ev_set for sig in ("large_size_jump", "high_entropy_string", "long_encoded_blob", "notable_new_file", "env_enumeration", "dynamic_code", "network_access")):
            rc = "(c) multi-version jump or large bundled dev tool"
        elif "inspection_failed" in ev_set or "replay_error" in ev_set:
            rc = "(e) other (extraction/replay limitation)"

        print(f"  * {pkg}@{old_v}->{new_v} | Evs: {list(ev_set)} | Class: {rc}")
