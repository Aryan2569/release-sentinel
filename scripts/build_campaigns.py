"""Build detector-independent campaign IDs via Union-Find (Stage 5d Part 1).

Linkage conditions between malicious pairs:
1. Identical new or changed non-metadata file hash (>= 200 bytes, existing rule).
2. Identical added direct runtime dependency (excluding any dependency name in ANY of the 800 benign pairs).
3. Identical added lifecycle command string.
4. Identical added hardcoded public IP or attacker C2 domain.
"""

from __future__ import annotations

import csv
import json
import math
import re
import zipfile
from collections import defaultdict
from pathlib import Path
from typing import Any

from release_sentinel.extractor import extract_release_in_memory

CACHE_DIR = Path.home() / ".cache" / "release_sentinel"
SAMPLES_ROOT = Path(r"C:\rs-data\datadog")
EVAL_PAIRS_CSV = Path("data/eval_pairs.csv")
EVAL_RESULTS_V4 = Path("data/eval_results_v4.jsonl")
EVAL_RESULTS_V6 = Path("data/eval_results_v6.jsonl")
CLUSTERS_V6 = Path("data/eval_clusters_v6.json")
HASHES_V6 = Path("data/eval_payload_hashes_v6.json")

LIFECYCLE_KEYS = ("preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishOnly")
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
C2_RE = re.compile(
    r"https?://([a-zA-Z0-9.-]+\.(?:api-monitor\.com|webhook\.site|oastify\.com|burpcollaborator\.net|ngrok\.io|interact\.sh|pipedream\.net|beeceptor\.com))",
    re.I,
)


def is_public_ip(ip: str) -> bool:
    parts = [int(p) for p in ip.split(".")]
    if parts[0] in (0, 10, 127):
        return False
    if parts[0] == 172 and 16 <= parts[1] <= 31:
        return False
    if parts[0] == 192 and parts[1] == 168:
        return False
    if parts[0] >= 224 or parts == [255, 255, 255, 255]:
        return False
    return True


class UnionFind:
    def __init__(self, elements: list[str]) -> None:
        self.parent = {e: e for e in elements}
        self.rank = dict.fromkeys(elements, 0)

    def find(self, x: str) -> str:
        if self.parent[x] != x:
            self.parent[x] = self.find(self.parent[x])
        return self.parent[x]

    def union(self, x: str, y: str) -> None:
        rx, ry = self.find(x), self.find(y)
        if rx == ry:
            return
        if self.rank[rx] < self.rank[ry]:
            self.parent[rx] = ry
        elif self.rank[rx] > self.rank[ry]:
            self.parent[ry] = rx
        else:
            self.parent[ry] = rx
            self.rank[rx] += 1


def get_split_mapping() -> dict[tuple[str, str, str], str]:
    results_v6 = [json.loads(line) for line in open(EVAL_RESULTS_V6, encoding="utf-8")]
    clusters = json.load(open(CLUSTERS_V6, encoding="utf-8"))
    test_cids = sorted(
        {e["cluster_id"] for e in results_v6 if e["split"] == "TEST"},
        key=lambda cid: (clusters[cid]["earliest_discovery"], clusters[cid]["rank"], cid),
    )
    test_a_cids = set(test_cids[:98])
    key_to_split: dict[tuple[str, str, str], str] = {}
    for e in results_v6:
        s = e["split"]
        if s == "TEST":
            s = "TEST-A" if e["cluster_id"] in test_a_cids else "TEST-B"
        key_to_split[(e["package"], e["old"], e["new"])] = s
    return key_to_split


def get_benign_dependencies() -> set[str]:
    benign_deps: set[str] = set()
    for p_csv in ["data/smoke_results_v6.csv", "data/smoke_validation_v6.csv", "data/matched_negatives.csv"]:
        if Path(p_csv).exists():
            for r in csv.DictReader(open(p_csv, encoding="utf-8")):
                pkg = r.get("package")
                new_v = r.get("new") or r.get("new_version")
                tgz = CACHE_DIR / pkg / f"{pkg}-{new_v}.tgz"
                if tgz.exists():
                    try:
                        rc = extract_release_in_memory(tgz)
                        pj = rc.package_json() or {}
                        for dep_sec in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                            benign_deps.update((pj.get(dep_sec) or {}).keys())
                    except Exception:
                        pass
    return benign_deps


def build_campaigns() -> tuple[dict[str, Any], dict[str, str]]:
    benign_deps = get_benign_dependencies()
    payload_hashes: dict[str, list[str]] = json.load(open(HASHES_V6, encoding="utf-8"))
    key_to_split = get_split_mapping()
    eval_pairs = [p for p in csv.DictReader(open(EVAL_PAIRS_CSV, encoding="utf-8")) if p.get("status") == "ok"]

    pair_features: dict[str, dict[str, Any]] = {}

    for p in eval_pairs:
        pkg = p["package"]
        old_ver = p["old_version"]
        new_ver = p["new_version"]
        pair_key = f"{pkg}@{old_ver}@{new_ver}"
        split = key_to_split.get((pkg, old_ver, new_ver), "DEV")

        hashes = set(payload_hashes.get(pair_key, []))

        # Fast load new package.json
        zp = SAMPLES_ROOT / p["zip_path"]
        new_pj: dict[str, Any] = {}
        try:
            with zipfile.ZipFile(zp) as z:
                z.setpassword(b"infected")
                for info in z.infolist():
                    if info.filename.endswith("package.json"):
                        new_pj = json.loads(z.read(info))
                        break
        except Exception:
            pass

        # Fast load old package.json
        old_pj: dict[str, Any] = {}
        tar_path = CACHE_DIR / pkg / f"{pkg}-{old_ver}.tgz"
        if tar_path.exists():
            try:
                rc = extract_release_in_memory(tar_path)
                old_pj = rc.package_json() or {}
            except Exception:
                pass

        # 2. Added direct dependencies
        old_deps = set((old_pj.get("dependencies") or {}).keys()) if isinstance(old_pj, dict) else set()
        new_deps = set((new_pj.get("dependencies") or {}).keys()) if isinstance(new_pj, dict) else set()
        added_deps = (new_deps - old_deps) - benign_deps

        # 3. Added lifecycle commands
        old_scripts = (old_pj.get("scripts") or {}) if isinstance(old_pj, dict) else {}
        new_scripts = (new_pj.get("scripts") or {}) if isinstance(new_pj, dict) else {}
        added_cmds = set()
        hosts_or_ips = set()
        for k in LIFECYCLE_KEYS:
            n_cmd = new_scripts.get(k)
            o_cmd = old_scripts.get(k)
            if n_cmd and n_cmd != o_cmd:
                cmd_str = str(n_cmd).strip()
                if len(cmd_str) > 5 and not cmd_str.lower().startswith(("echo", "exit")):
                    added_cmds.add(cmd_str)
                    for ip in IP_RE.findall(cmd_str):
                        if is_public_ip(ip):
                            hosts_or_ips.add(ip)
                    for c2 in C2_RE.findall(cmd_str):
                        hosts_or_ips.add(c2.lower())

        pair_features[pair_key] = {
            "pair": p,
            "split": split,
            "discovery_date": p["discovery_date"],
            "hashes": hashes,
            "added_deps": added_deps,
            "added_cmds": added_cmds,
            "hosts_or_ips": hosts_or_ips,
        }

    all_keys = list(pair_features.keys())
    uf = UnionFind(all_keys)

    hash_to_pairs: dict[str, list[str]] = defaultdict(list)
    dep_to_pairs: dict[str, list[str]] = defaultdict(list)
    cmd_to_pairs: dict[str, list[str]] = defaultdict(list)
    host_to_pairs: dict[str, list[str]] = defaultdict(list)

    for k, feat in pair_features.items():
        for h in feat["hashes"]:
            hash_to_pairs[h].append(k)
        for d in feat["added_deps"]:
            dep_to_pairs[d].append(k)
        for c in feat["added_cmds"]:
            cmd_to_pairs[c].append(k)
        for hst in feat["hosts_or_ips"]:
            host_to_pairs[hst].append(k)

    for _name, idx in [
        ("hashes", hash_to_pairs),
        ("added_deps", dep_to_pairs),
        ("added_cmds", cmd_to_pairs),
        ("hosts_or_ips", host_to_pairs),
    ]:
        for _val, plist in idx.items():
            if len(plist) > 1:
                first = plist[0]
                for o in plist[1:]:
                    uf.union(first, o)

    campaign_members: dict[str, list[str]] = defaultdict(list)
    for k in all_keys:
        campaign_members[uf.find(k)].append(k)

    campaign_meta = []
    for leader, members in campaign_members.items():
        earliest_date = min(pair_features[m]["discovery_date"] for m in members)
        splits = sorted({pair_features[m]["split"] for m in members})
        earliest_members = [m for m in members if pair_features[m]["discovery_date"] == earliest_date]
        primary_split = pair_features[earliest_members[0]]["split"]
        campaign_meta.append({
            "leader": leader,
            "earliest_date": earliest_date,
            "primary_split": primary_split,
            "splits": splits,
            "size": len(members),
            "members": sorted(members),
        })

    campaign_meta.sort(key=lambda c: (c["earliest_date"], -c["size"], c["leader"]))

    pair_to_campaign: dict[str, str] = {}
    campaigns_dict: dict[str, Any] = {}
    for idx, c in enumerate(campaign_meta, 1):
        camp_id = f"camp_{idx:04d}"
        c["campaign_id"] = camp_id
        campaigns_dict[camp_id] = c
        for m in c["members"]:
            pair_to_campaign[m] = camp_id

    return campaigns_dict, pair_to_campaign


def binom_cdf(k: int, n: int, p: float) -> float:
    return sum(math.comb(n, j) * (p**j) * ((1 - p) ** (n - j)) for j in range(k + 1))


def clopper_pearson(k: int, n: int, alpha: float = 0.05) -> tuple[float, float]:
    """Exact Clopper-Pearson 95% binomial confidence interval."""
    if n == 0:
        return 0.0, 1.0
    if k == 0:
        lower = 0.0
    else:
        lo, hi = 0.0, 1.0
        for _ in range(100):
            mid = (lo + hi) / 2
            prob = sum(math.comb(n, j) * (mid**j) * ((1 - mid) ** (n - j)) for j in range(k, n + 1))
            if prob < alpha / 2:
                lo = mid
            else:
                hi = mid
        lower = (lo + hi) / 2
    if k == n:
        upper = 1.0
    else:
        lo, hi = 0.0, 1.0
        for _ in range(100):
            mid = (lo + hi) / 2
            prob = binom_cdf(k, n, mid)
            if prob < alpha / 2:
                hi = mid
            else:
                lo = mid
        upper = (lo + hi) / 2
    return lower, upper


def evaluate_version_on_campaigns(
    results_path: Path,
    campaigns_dict: dict[str, Any],
    pair_to_campaign: dict[str, str],
    key_to_split: dict[tuple[str, str, str], str],
) -> dict[str, Any]:
    rows = [json.loads(line) for line in open(results_path, encoding="utf-8")]

    # Normalize split on each row using key_to_split
    camp_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        pair_tuple = (r["package"], r["old"], r["new"])
        pair_key = f"{r['package']}@{r['old']}@{r['new']}"
        r_split = key_to_split.get(pair_tuple, r.get("split", "DEV"))
        r["eval_split"] = r_split
        cid = pair_to_campaign.get(pair_key)
        if cid:
            camp_rows[cid].append(r)

    split_stats: dict[str, Any] = {}
    for split in ["ALL", "DEV", "VAL", "TEST-A", "TEST-B"]:
        if split == "ALL":
            target_cids = list(campaigns_dict.keys())
        else:
            target_cids = [
                cid
                for cid, c in campaigns_dict.items()
                if c["primary_split"] == split
            ]

        n_camps = len(target_cids)
        if n_camps == 0:
            continue

        lenient_fc_warn = 0
        lenient_fc_block = 0
        lenient_eo_warn = 0
        lenient_eo_block = 0

        macro_fc_warn_sum = 0.0
        macro_fc_block_sum = 0.0
        macro_eo_warn_sum = 0.0
        macro_eo_block_sum = 0.0

        for cid in target_cids:
            r_list = camp_rows.get(cid, [])
            if not r_list:
                continue

            n_pairs = len(r_list)

            c_fc_warn = sum(1 for r in r_list if r.get("decision") in ("WARN", "BLOCK"))
            c_fc_block = sum(1 for r in r_list if r.get("decision") == "BLOCK")
            c_eo_warn = sum(1 for r in r_list if r.get("evidence_only_decision") in ("WARN", "BLOCK"))
            c_eo_block = sum(1 for r in r_list if r.get("evidence_only_decision") == "BLOCK")

            if c_fc_warn > 0:
                lenient_fc_warn += 1
            if c_fc_block > 0:
                lenient_fc_block += 1
            if c_eo_warn > 0:
                lenient_eo_warn += 1
            if c_eo_block > 0:
                lenient_eo_block += 1

            macro_fc_warn_sum += c_fc_warn / n_pairs
            macro_fc_block_sum += c_fc_block / n_pairs
            macro_eo_warn_sum += c_eo_warn / n_pairs
            macro_eo_block_sum += c_eo_block / n_pairs

        split_stats[split] = {
            "campaigns": n_camps,
            "lenient_fc_warn": lenient_fc_warn,
            "lenient_fc_warn_pct": lenient_fc_warn / n_camps * 100,
            "lenient_fc_block": lenient_fc_block,
            "lenient_fc_block_pct": lenient_fc_block / n_camps * 100,
            "lenient_eo_warn": lenient_eo_warn,
            "lenient_eo_warn_pct": lenient_eo_warn / n_camps * 100,
            "lenient_eo_block": lenient_eo_block,
            "lenient_eo_block_pct": lenient_eo_block / n_camps * 100,
            "lenient_eo_warn_ci": list(clopper_pearson(lenient_eo_warn, n_camps)),
            "lenient_eo_block_ci": list(clopper_pearson(lenient_eo_block, n_camps)),
            "macro_fc_warn_pct": macro_fc_warn_sum / n_camps * 100,
            "macro_fc_block_pct": macro_fc_block_sum / n_camps * 100,
            "macro_eo_warn_pct": macro_eo_warn_sum / n_camps * 100,
            "macro_eo_block_pct": macro_eo_block_sum / n_camps * 100,
        }

    return split_stats


if __name__ == "__main__":
    campaigns_dict, pair_to_campaign = build_campaigns()
    with open("data/eval_campaigns.json", "w", encoding="utf-8") as f:
        json.dump(campaigns_dict, f, indent=2)
    print(f"Total campaigns: {len(campaigns_dict)}")

    key_to_split = get_split_mapping()

    split_counts: dict[str, int] = defaultdict(int)
    for c in campaigns_dict.values():
        for s in c["splits"]:
            split_counts[s] += 1
    print("Campaign counts per split (with multi-split overlap):")
    for s in ["DEV", "VAL", "TEST-A", "TEST-B"]:
        print(f"  {s}: {split_counts[s]} campaigns")

    # Evaluate v1.0 vs v1.1
    print("\n--- CAMPAIGN-LEVEL RECALL: v1.0 ---")
    v10_stats = evaluate_version_on_campaigns(EVAL_RESULTS_V4, campaigns_dict, pair_to_campaign, key_to_split)
    print(json.dumps(v10_stats, indent=2))

    print("\n--- CAMPAIGN-LEVEL RECALL: v1.1 ---")
    v11_stats = evaluate_version_on_campaigns(EVAL_RESULTS_V6, campaigns_dict, pair_to_campaign, key_to_split)
    print(json.dumps(v11_stats, indent=2))
