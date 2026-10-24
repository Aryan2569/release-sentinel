"""Build matched negatives dataset for Stage 4b.

For each distinct package in data/eval_pairs.csv (cap 600 packages, at most one per
campaign cluster where possible), builds one benign-to-benign pair from the same package:
  - version before the baseline (old) version (old_version = v_pre)
  - baseline version (new_version = v_base)
  - same major version
  - neither version listed as affected in the DataDog manifest
  - as_of = publish timestamp of new_version
"""

from __future__ import annotations

import csv
import json
import logging
from datetime import UTC, datetime
from pathlib import Path

from release_sentinel.registry import NpmRegistryClient

logger = logging.getLogger("build_matched_negatives")


def parse_semver(v: str) -> tuple[int, int, int] | None:
    try:
        parts = v.split(".")
        if len(parts) == 3 and all(p.isdigit() for p in parts):
            return (int(parts[0]), int(parts[1]), int(parts[2]))
    except Exception as exc:
        logger.debug("Failed parsing semver %r: %s", v, exc)
    return None


def main() -> int:
    from release_sentinel.eval import get_samples_root

    manifest_path = get_samples_root() / "samples" / "npm" / "manifest.json"
    with open(manifest_path, encoding="utf-8") as f:
        manifest = json.load(f)

    with open("data/eval_clusters_v2.json", encoding="utf-8") as f:
        clusters = json.load(f)

    with open("data/eval_pairs.csv", encoding="utf-8") as f:
        eval_pairs = [r for r in csv.DictReader(f) if r["status"] == "ok"]

    # Package -> baseline version from eval_pairs
    pkg_to_old: dict[str, str] = {}
    for r in eval_pairs:
        pkg = r["package"]
        if pkg not in pkg_to_old:
            pkg_to_old[pkg] = r["old_version"]

    client = NpmRegistryClient(cache_dir=Path.home() / ".cache" / "release_sentinel")

    def get_matched_pair(pkg: str) -> tuple[str, str, str] | None:
        v_base = pkg_to_old[pkg]
        v_base_semver = parse_semver(v_base)
        if not v_base_semver:
            return None
        try:
            meta = client.get_metadata(pkg, as_of=datetime.now(UTC))
        except Exception:
            return None
        time_map = {
            k: v for k, v in meta.get("time", {}).items() if k not in ("created", "modified")
        }
        versions_map = meta.get("versions", {})
        if v_base not in versions_map:
            return None

        affected = set(manifest.get(pkg, []))
        if v_base in affected:
            return None

        stables = [v for v in versions_map if parse_semver(v) and v in time_map]
        base_maj = v_base_semver[0]
        candidates = [
            u for u in stables
            if parse_semver(u)[0] == base_maj
            and parse_semver(u) < v_base_semver
            and u not in affected
        ]
        if not candidates:
            return None
        v_pre = max(candidates, key=parse_semver)
        pub_time = time_map.get(v_base, "")
        return (v_pre, v_base, pub_time)

    matched: list[dict[str, str]] = []
    used_pkgs: set[str] = set()

    # Round 1: at most one per campaign cluster
    for cid, cinfo in clusters.items():
        pkgs_in_cluster = []
        for m in cinfo["members"]:
            pkg = m.split("@")[0] if not m.startswith("@") else "@" + m[1:].split("@")[0]
            if pkg in pkg_to_old and pkg not in pkgs_in_cluster and pkg not in used_pkgs:
                pkgs_in_cluster.append(pkg)
        for pkg in pkgs_in_cluster:
            pair = get_matched_pair(pkg)
            if pair:
                matched.append({
                    "package": pkg,
                    "old_version": pair[0],
                    "new_version": pair[1],
                    "as_of": pair[2],
                    "cluster_id": cid,
                })
                used_pkgs.add(pkg)
                break

    print(f"Round 1 (1 per cluster): {len(matched)}")

    # Round 2: fill up to 600 from remaining packages
    if len(matched) < 600:
        for cid, cinfo in clusters.items():
            if len(matched) >= 600:
                break
            pkgs_in_cluster = []
            for m in cinfo["members"]:
                pkg = m.split("@")[0] if not m.startswith("@") else "@" + m[1:].split("@")[0]
                if pkg in pkg_to_old and pkg not in pkgs_in_cluster and pkg not in used_pkgs:
                    pkgs_in_cluster.append(pkg)
            for pkg in pkgs_in_cluster:
                if len(matched) >= 600:
                    break
                pair = get_matched_pair(pkg)
                if pair:
                    matched.append({
                        "package": pkg,
                        "old_version": pair[0],
                        "new_version": pair[1],
                        "as_of": pair[2],
                        "cluster_id": cid,
                    })
                    used_pkgs.add(pkg)

    print(f"Total matched negatives selected: {len(matched)}")

    out_csv = Path("data/matched_negatives.csv")
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["package", "old_version", "new_version", "as_of", "cluster_id"]
    with open(out_csv, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(matched)

    print(f"Written to {out_csv}")
    return 0


if __name__ == "__main__":
    main()
