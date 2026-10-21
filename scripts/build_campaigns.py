"""Build detector-independent campaign IDs via Union-Find (Stage 5f Part 0 & 1).

Linkage conditions between malicious pairs:
1. Identical new or changed non-metadata file hash (>= 200 bytes, existing rule) within 30 days.
2. Identical added direct runtime dependency (truly new in both old baselines, not in benign vocabulary) within 30 days.
3. Identical added lifecycle command string (truly new in both old baselines) within 30 days.
4. Identical added hardcoded public IP or attacker C2 domain within 30 days.

Suppression rules:
- Any link key shared by >50 pairs spanning >60 days is suppressed / ignored as a common hub.
- All dependency names appearing in any of the 800 benign pairs are excluded as common vocabulary.
- Explicit split assignment (DEV, VAL, TEST-A, TEST-B) with no silent fallback.
- Campaign recall evaluated strictly on member pairs falling within the campaign's assigned split.
"""

from __future__ import annotations

import csv
import json
import math
import os
import re
import tarfile
import zipfile
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from release_sentinel.registry import _safe_filename

CACHE_DIR = Path.home() / ".cache" / "release_sentinel"
SAMPLES_ROOT = Path(os.environ.get("RS_SAMPLES_ROOT", r"C:\rs-data\datadog"))
EVAL_PAIRS_CSV = Path("data/eval_pairs.csv")
EVAL_RESULTS_V5 = Path("data/eval_results_v5.jsonl")
EVAL_RESULTS_V6 = Path("data/eval_results_v6.jsonl")
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


def assign_split(package: str, discovery_date: str) -> str:
    """Explicitly assign an eval pair to DEV, VAL, TEST-A, or TEST-B.

    No silent fallbacks allowed.
    """
    if not discovery_date:
        raise ValueError(f"Missing discovery_date for package {package}")
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


def get_split_mapping() -> dict[tuple[str, str, str], str]:
    """Map every (package, old, new) tuple explicitly to its split."""
    eval_pairs = [p for p in csv.DictReader(open(EVAL_PAIRS_CSV, encoding="utf-8")) if p.get("status") == "ok"]
    key_to_split: dict[tuple[str, str, str], str] = {}
    for p in eval_pairs:
        s = assign_split(p["package"], p["discovery_date"])
        key_to_split[(p["package"], p["old_version"], p["new_version"])] = s
    return key_to_split


def _read_package_json_from_tarball(tgz_path: Path) -> dict[str, Any] | None:
    if not tgz_path.exists():
        return None
    try:
        with tarfile.open(tgz_path, "r:*") as tf:
            for m in tf.getmembers():
                if m.name.endswith("package.json") and not m.name.startswith((".", "/")) and "node_modules" not in m.name:
                    f = tf.extractfile(m)
                    if f:
                        return json.loads(f.read().decode("utf-8", errors="replace"))
    except Exception:
        return None
    return None


def get_benign_dependencies() -> set[str]:
    """Extract all dependency names from all 800 benign pairs across all sections."""
    benign_deps: set[str] = set()
    total_benign_checked = 0
    failed_reads = 0

    for p_csv in ["data/smoke_results_v6.csv", "data/smoke_validation_v6.csv", "data/matched_negatives.csv"]:
        if Path(p_csv).exists():
            for r in csv.DictReader(open(p_csv, encoding="utf-8")):
                total_benign_checked += 1
                pkg = r.get("package") or ""
                new_v = r.get("new") or r.get("new_version") or ""
                safe_name = _safe_filename(pkg)
                tgz = CACHE_DIR / safe_name / f"{safe_name}-{new_v}.tgz"
                pj = _read_package_json_from_tarball(tgz)
                if pj is not None:
                    for dep_sec in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                        benign_deps.update((pj.get(dep_sec) or {}).keys())
                else:
                    failed_reads += 1

    if total_benign_checked > 0 and (failed_reads / total_benign_checked) > 0.01:
        raise RuntimeError(
            f"Failed to read {failed_reads}/{total_benign_checked} benign package.jsons (>1% failure limit)"
        )

    return benign_deps


def build_campaigns() -> tuple[dict[str, Any], dict[str, str]]:
    benign_deps = get_benign_dependencies()
    payload_hashes: dict[str, list[str]] = json.load(open(HASHES_V6, encoding="utf-8"))
    eval_pairs = [p for p in csv.DictReader(open(EVAL_PAIRS_CSV, encoding="utf-8")) if p.get("status") == "ok"]

    pair_features: dict[str, dict[str, Any]] = {}
    old_pj_failures = 0

    for p in eval_pairs:
        pkg = p["package"]
        old_ver = p["old_version"]
        new_ver = p["new_version"]
        pair_key = f"{pkg}@{old_ver}@{new_ver}"
        d_date = datetime.strptime(p["discovery_date"], "%Y-%m-%d")
        split = assign_split(pkg, p["discovery_date"])

        hashes = set(payload_hashes.get(pair_key, []))

        # Fast load new package.json from encrypted sample zip
        zp = SAMPLES_ROOT / p["zip_path"]
        new_pj: dict[str, Any] = {}
        try:
            with zipfile.ZipFile(zp) as z:
                z.setpassword(b"infected")
                for info in z.infolist():
                    if info.filename.endswith("package.json"):
                        new_pj = json.loads(z.read(info).decode("utf-8", errors="replace"))
                        break
        except Exception:
            pass

        # Fast load old baseline package.json from registry disk cache
        safe_name = _safe_filename(pkg)
        tar_path = CACHE_DIR / safe_name / f"{safe_name}-{old_ver}.tgz"
        old_pj = _read_package_json_from_tarball(tar_path)
        if old_pj is None:
            old_pj_failures += 1
            old_loaded = False
        else:
            old_loaded = True

        # Added direct runtime dependencies
        old_deps = set((old_pj.get("dependencies") or {}).keys()) if old_loaded and isinstance(old_pj, dict) else set()
        new_deps = set((new_pj.get("dependencies") or {}).keys()) if isinstance(new_pj, dict) else set()
        added_deps = (new_deps - old_deps) - benign_deps if old_loaded else set()

        # Added lifecycle commands
        old_scripts = (old_pj.get("scripts") or {}) if old_loaded and isinstance(old_pj, dict) else {}
        new_scripts = (new_pj.get("scripts") or {}) if isinstance(new_pj, dict) else {}
        added_cmds = set()
        hosts_or_ips = set()
        if old_loaded:
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
            "date": d_date,
            "discovery_date": p["discovery_date"],
            "hashes": hashes,
            "added_deps": added_deps,
            "added_cmds": added_cmds,
            "hosts_or_ips": hosts_or_ips,
        }

    if (old_pj_failures / len(eval_pairs)) > 0.01:
        raise RuntimeError(
            f"Failed to load old package.json for {old_pj_failures}/{len(eval_pairs)} pairs (>1% threshold)"
        )

    all_keys = list(pair_features.keys())
    uf = UnionFind(all_keys)

    # Collect keys to pairs
    all_keys_map: dict[tuple[str, str], list[tuple[str, datetime]]] = defaultdict(list)
    for k, feat in pair_features.items():
        for h in feat["hashes"]:
            all_keys_map[("hash", h)].append((k, feat["date"]))
        for d in feat["added_deps"]:
            all_keys_map[("dep", d)].append((k, feat["date"]))
        for c in feat["added_cmds"]:
            all_keys_map[("cmd", c)].append((k, feat["date"]))
        for hst in feat["hosts_or_ips"]:
            all_keys_map[("host", hst)].append((k, feat["date"]))

    # Apply suppression and 30-day window linking
    for (_ktype, _kval), plist in all_keys_map.items():
        count = len(plist)
        dates = [d for _, d in plist]
        span = (max(dates) - min(dates)).days
        # Ignore any key shared by more than 50 pairs spanning more than 60 days
        if count > 50 and span > 60:
            continue

        # Link pairs within 30 days of each other
        s_plist = sorted(plist, key=lambda x: x[1])
        for i in range(len(s_plist)):
            p1, d1 = s_plist[i]
            for j in range(i + 1, len(s_plist)):
                p2, d2 = s_plist[j]
                if (d2 - d1).days <= 30:
                    uf.union(p1, p2)
                else:
                    break

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
) -> dict[str, Any]:
    rows = [json.loads(line) for line in open(results_path, encoding="utf-8")]

    camp_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        pair_key = f"{r['package']}@{r['old']}@{r['new']}"
        cid = pair_to_campaign.get(pair_key)
        r["eval_split"] = assign_split(r["package"], r["discovery_date"])
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
            all_r_list = camp_rows.get(cid, [])
            if not all_r_list:
                continue

            # Evaluate recall ONLY on member pairs that fall within this split (Part 1b)
            if split == "ALL":
                r_list = all_r_list
            else:
                r_list = [r for r in all_r_list if r["eval_split"] == split]

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

    sizes = sorted([c["size"] for c in campaigns_dict.values()], reverse=True)
    print(f"Top 10 campaign sizes: {sizes[:10]}")

    split_counts: dict[str, int] = defaultdict(int)
    for c in campaigns_dict.values():
        split_counts[c["primary_split"]] += 1
    print("Disjoint campaign counts per split (assigned by earliest discovery date):")
    for s in ["DEV", "VAL", "TEST-A", "TEST-B"]:
        print(f"  {s}: {split_counts[s]} campaigns")

    # Evaluate v1.0 vs v1.1
    print("\n--- CAMPAIGN-LEVEL RECALL: v1.0 (eval_results_v5) ---")
    v10_stats = evaluate_version_on_campaigns(EVAL_RESULTS_V5, campaigns_dict, pair_to_campaign)
    print(json.dumps(v10_stats, indent=2))

    print("\n--- CAMPAIGN-LEVEL RECALL: v1.1 (eval_results_v6) ---")
    v11_stats = evaluate_version_on_campaigns(EVAL_RESULTS_V6, campaigns_dict, pair_to_campaign)
    print(json.dumps(v11_stats, indent=2))
