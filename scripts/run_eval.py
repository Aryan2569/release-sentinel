"""Release Sentinel - Stage 3b Evaluation Runner.

Runs the frozen detector over all buildable eval pairs in data/eval_pairs.csv.
MEASUREMENT ONLY: does not modify detection rules, severities, or policy.

Rules and constraints enforced:
- Rule 7: Samples remain encrypted at rest in C:\\rs-data\\datadog.
  Members are read in memory only. No sample content is written to disk.
- Output contains NO snippets or sample file contents.
- Evaluation split: DEV (< 2026-01-01) vs TEST (>= 2026-01-01).
- Per-pair 60s timeout limit (records 'timeout').
- Baseline downloads retried once (records 'baseline_download_failed').
- Resumable: writes to data/eval_results.jsonl, skips existing pairs on re-run.
- Progress printed every 50 pairs only.
- Union-Find campaign clustering over qualifying new/changed file SHA-256 hashes.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import subprocess
import sys
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx

from release_sentinel.engine import decide
from release_sentinel.eval import analyze_eval_pair, parse_discovery_date_as_of
from release_sentinel.models import Severity
from release_sentinel.registry import (
    NpmRegistryClient,
    RegistryError,
    VersionNotFoundError,
)

logging.basicConfig(level=logging.WARNING, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("run_eval")


def get_split(discovery_date: str) -> str:
    """Walk-forward split: DEV (< 2026-01-01), VAL (2026-01-01 to 2026-04-30),
    TEST (>= 2026-05-01).
    """
    if discovery_date < "2026-01-01":
        return "DEV"
    if discovery_date <= "2026-04-30":
        return "VAL"
    return "TEST"

# Severity ordering (highest first)
_SEV_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]

SAMPLES_ROOT = Path(r"C:\rs-data\datadog")
CACHE_DIR = Path.home() / ".cache" / "release_sentinel"
EVAL_PAIRS_CSV = Path("data/eval_pairs.csv")
RESULTS_JSONL = Path("data/eval_results.jsonl")
HASHES_CACHE_FILE = Path("data/eval_payload_hashes.json")
CLUSTERS_JSON = Path("data/eval_clusters.json")


class UnionFind:
    """Disjoint Set Union (DSU) with path compression and union by rank."""

    def __init__(self, n: int) -> None:
        self.parent = list(range(n))
        self.rank = [0] * n

    def find(self, x: int) -> int:
        if self.parent[x] != x:
            self.parent[x] = self.find(self.parent[x])
        return self.parent[x]

    def union(self, x: int, y: int) -> None:
        rx = self.find(x)
        ry = self.find(y)
        if rx == ry:
            return
        if self.rank[rx] < self.rank[ry]:
            self.parent[rx] = ry
        elif self.rank[rx] > self.rank[ry]:
            self.parent[ry] = rx
        else:
            self.parent[ry] = rx
            self.rank[rx] += 1


def load_eval_pairs(csv_path: Path) -> list[dict[str, str]]:
    """Load pairs with status == 'ok' from eval_pairs.csv."""
    pairs: list[dict[str, str]] = []
    with open(csv_path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("status") == "ok":
                pairs.append(row)
    return pairs


def load_existing_results(jsonl_path: Path) -> dict[tuple[str, str, str], dict[str, Any]]:
    """Load existing results by (package, old, new)."""
    results: dict[tuple[str, str, str], dict[str, Any]] = {}
    if not jsonl_path.exists():
        return results

    with open(jsonl_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
                key = (row["package"], row["old"], row["new"])
                results[key] = row
            except (json.JSONDecodeError, KeyError) as exc:
                logger.warning("Skipping malformed jsonl line: %s", exc)
                continue
    return results


def load_hashes_cache(cache_path: Path) -> dict[str, list[str]]:
    """Load cached payload hashes mapping f'{package}@{old}@{new}' -> list of hashes."""
    if not cache_path.exists():
        return {}
    try:
        with open(cache_path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_hashes_cache(cache_path: Path, data: dict[str, list[str]]) -> None:
    """Save payload hashes atomically."""
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = cache_path.with_suffix(".tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    tmp_path.replace(cache_path)


def get_max_severity_name(evidence: list[Any]) -> str | None:
    """Return the name of the highest severity in evidence, or None."""
    if not evidence:
        return None
    ev_sevs = {e.severity for e in evidence}
    for s in _SEV_ORDER:
        if s in ev_sevs:
            return s.name
    return None


def ensure_baseline_tarball(
    client: NpmRegistryClient,
    package: str,
    version: str,
    as_of: datetime,
    dest_dir: Path,
    download_lock: threading.Lock | None = None,
) -> bool:
    """Download baseline tarball, retrying once on network/HTTP error. Return True on success."""
    for attempt in range(2):
        try:
            if download_lock is not None:
                with download_lock:
                    client.download_tarball(
                        name=package, version=version, as_of=as_of, dest_dir=dest_dir
                    )
            else:
                client.download_tarball(
                    name=package, version=version, as_of=as_of, dest_dir=dest_dir
                )
            return True
        except (RegistryError, httpx.HTTPError, OSError) as exc:
            if attempt == 0:
                logger.warning(
                    "Baseline download failed for %s@%s (attempt 1/2): %s; retrying...",
                    package,
                    version,
                    exc,
                )
                time.sleep(1.0)
            else:
                logger.error(
                    "Baseline download failed for %s@%s after retry: %s",
                    package,
                    version,
                    exc,
                )
                return False
        except VersionNotFoundError as exc:
            logger.error("Baseline version not found for %s@%s: %s", package, version, exc)
            return False
    return False


def run_worker(pair: dict[str, str]) -> None:
    """Execute analysis for a single pair in an isolated worker process."""
    package = pair["package"]
    old_ver = pair["old_version"]
    new_ver = pair["new_version"]
    discovery_date = pair["discovery_date"]
    zip_rel_path = pair["zip_path"]
    split = get_split(discovery_date)

    zip_path = SAMPLES_ROOT / zip_rel_path
    if not zip_path.exists():
        row = {
            "package": package,
            "old": old_ver,
            "new": new_ver,
            "discovery_date": discovery_date,
            "cluster_id": "pending",
            "split": split,
            "status": "error",
            "decision": None,
            "evidence_only_decision": None,
            "max_severity": None,
            "evidence_types": [],
            "limitation_count": 0,
            "seconds": 0.0,
        }
        print("EVAL_WORKER_RESULT:" + json.dumps({"row": row, "payload_hashes": []}))
        return

    t0 = time.perf_counter()
    client = NpmRegistryClient(cache_dir=CACHE_DIR)
    try:
        eval_res = analyze_eval_pair(
            package=package,
            old_version=old_ver,
            zip_path=zip_path,
            discovery_date=discovery_date,
            new_version=new_ver,
            registry_client=client,
        )
        elapsed = round(time.perf_counter() - t0, 3)
        ev_types = sorted({e.id for e in eval_res.evidence})
        max_sev = get_max_severity_name(eval_res.evidence)
        status = "inspection_incomplete" if "inspection_incomplete" in ev_types else "ok"

        # Evidence-only decision without inspection_incomplete
        ev_without_inc = [e for e in eval_res.evidence if e.id != "inspection_incomplete"]
        ev_only_dec, _ = decide(ev_without_inc, is_full_scan=eval_res.is_full_scan)

        row = {
            "package": package,
            "old": old_ver,
            "new": new_ver,
            "discovery_date": discovery_date,
            "cluster_id": "pending",
            "split": split,
            "status": status,
            "decision": eval_res.decision.name,
            "evidence_only_decision": ev_only_dec.name,
            "max_severity": max_sev,
            "evidence_types": ev_types,
            "limitation_count": len(eval_res.limitations),
            "seconds": elapsed,
            "mode": "full_scan" if eval_res.is_full_scan else "diff",
            "deps_added_count": eval_res.dependencies_added_count,
            "deps_resolved_live": eval_res.dependencies_resolved_live,
            "deps_resolved_replayed": eval_res.dependencies_resolved_replayed,
            "deps_unresolvable": eval_res.dependencies_unresolvable,
        }
        res_payload = {"row": row, "payload_hashes": eval_res.payload_hashes}
        print("EVAL_WORKER_RESULT:" + json.dumps(res_payload))
    except Exception as exc:
        elapsed = round(time.perf_counter() - t0, 3)
        logger.error("Analysis failed for %s@%s: %s", package, new_ver, exc)
        row = {
            "package": package,
            "old": old_ver,
            "new": new_ver,
            "discovery_date": discovery_date,
            "cluster_id": "pending",
            "split": split,
            "status": "error",
            "decision": None,
            "evidence_only_decision": None,
            "max_severity": None,
            "evidence_types": [],
            "limitation_count": 0,
            "seconds": elapsed,
        }
        print("EVAL_WORKER_RESULT:" + json.dumps({"row": row, "payload_hashes": []}))
    finally:
        client.close()


def run_one_pair(
    pair: dict[str, str],
    client: NpmRegistryClient,
    download_lock: threading.Lock | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Run analysis on a single pair using an isolated worker process with 60s timeout."""
    package = pair["package"]
    old_ver = pair["old_version"]
    new_ver = pair["new_version"]
    discovery_date = pair["discovery_date"]
    zip_rel_path = pair["zip_path"]
    split = get_split(discovery_date)

    zip_path = SAMPLES_ROOT / zip_rel_path
    if not zip_path.exists():
        return (
            {
                "package": package,
                "old": old_ver,
                "new": new_ver,
                "discovery_date": discovery_date,
                "cluster_id": "pending",
                "split": split,
                "status": "error",
                "decision": None,
                "evidence_only_decision": None,
                "max_severity": None,
                "evidence_types": [],
                "limitation_count": 0,
                "seconds": 0.0,
            },
            [],
        )

    as_of = parse_discovery_date_as_of(discovery_date)
    dest_temp = CACHE_DIR / "tarballs" / "eval_tmp"

    t0 = time.perf_counter()

    # 1. Ensure baseline tarball exists with 1 retry
    tarball_ok = ensure_baseline_tarball(
        client=client,
        package=package,
        version=old_ver,
        as_of=as_of,
        dest_dir=dest_temp,
        download_lock=download_lock,
    )
    if not tarball_ok:
        logger.info(
            "Baseline tarball unavailable for %s@%s; proceeding to full-scan mode in worker",
            package,
            old_ver,
        )

    # 2. Run in isolated subprocess with 60-second timeout
    cmd = [sys.executable, str(Path(__file__).resolve()), "--worker"]
    payload = json.dumps({"pair": pair})

    try:
        proc = subprocess.run(  # noqa: S603
            cmd,
            input=payload,
            capture_output=True,
            text=True,
            timeout=300.0,
        )
    except subprocess.TimeoutExpired:
        elapsed = 300.0
        logger.warning("Pair %s@%s timed out after 300s wall-clock backstop", package, new_ver)
        return (
            {
                "package": package,
                "old": old_ver,
                "new": new_ver,
                "discovery_date": discovery_date,
                "cluster_id": "pending",
                "split": split,
                "status": "inspection_incomplete",
                "decision": "WARN",
                "evidence_only_decision": "ALLOW",
                "max_severity": "MEDIUM",
                "evidence_types": ["inspection_incomplete"],
                "limitation_count": 1,
                "seconds": elapsed,
            },
            [],
        )

    elapsed = round(time.perf_counter() - t0, 3)
    if proc.returncode != 0:
        logger.error(
            "Worker process failed for %s@%s (code %s): %s",
            package,
            new_ver,
            proc.returncode,
            proc.stderr,
        )
        return (
            {
                "package": package,
                "old": old_ver,
                "new": new_ver,
                "discovery_date": discovery_date,
                "cluster_id": "pending",
                "split": split,
                "status": "error",
                "decision": None,
                "evidence_only_decision": None,
                "max_severity": None,
                "evidence_types": [],
                "limitation_count": 0,
                "seconds": elapsed,
            },
            [],
        )

    # Find the result marker in worker output
    for line in reversed(proc.stdout.splitlines()):
        if line.startswith("EVAL_WORKER_RESULT:"):
            try:
                data = json.loads(line[len("EVAL_WORKER_RESULT:") :])
                row = data["row"]
                if "inspection_incomplete" in row.get("evidence_types", []):
                    row["status"] = "inspection_incomplete"
                return (row, data["payload_hashes"])
            except Exception as exc:
                logger.error("Failed to decode worker result for %s: %s", package, exc)
                break

    return (
        {
            "package": package,
            "old": old_ver,
            "new": new_ver,
            "discovery_date": discovery_date,
            "cluster_id": "pending",
            "split": split,
            "status": "error",
            "decision": None,
            "evidence_only_decision": None,
            "max_severity": None,
            "evidence_types": [],
            "limitation_count": 0,
            "seconds": elapsed,
        },
        [],
    )


def cluster_all_pairs(
    pairs: list[dict[str, str]],
    hashes_map: dict[str, list[str]],
) -> tuple[dict[tuple[str, str, str], str], dict[str, Any]]:
    """Run Union-Find campaign clustering over all pairs.

    Returns:
    - pair_to_cluster: mapping (package, old, new) -> cluster_id
    - cluster_metadata: dict of cluster statistics and member lists
    """
    n = len(pairs)
    uf = UnionFind(n)
    hash_to_first_pair: dict[str, int] = {}

    pair_hashes_list: list[list[str]] = []
    for pair in pairs:
        key_str = f"{pair['package']}@{pair['old_version']}@{pair['new_version']}"
        h_list = hashes_map.get(key_str, [])
        pair_hashes_list.append(h_list)

    for i, hashes in enumerate(pair_hashes_list):
        if not hashes:
            continue
        for h in hashes:
            if h in hash_to_first_pair:
                uf.union(i, hash_to_first_pair[h])
            else:
                hash_to_first_pair[h] = i

    groups: dict[int, list[int]] = defaultdict(list)
    for i in range(n):
        root = uf.find(i)
        groups[root].append(i)

    # Sort clusters: largest size first, then earliest discovery date, then package name
    sorted_roots = sorted(
        groups.keys(),
        key=lambda r: (
            -len(groups[r]),
            min(pairs[i]["discovery_date"] for i in groups[r]),
            min(pairs[i]["package"] for i in groups[r]),
        ),
    )

    pair_to_cluster: dict[tuple[str, str, str], str] = {}
    cluster_metadata: dict[str, Any] = {}

    for rank, root in enumerate(sorted_roots, start=1):
        cid = f"cluster_{rank:04d}"
        members = groups[root]
        member_pairs = [
            (pairs[i]["package"], pairs[i]["old_version"], pairs[i]["new_version"])
            for i in members
        ]
        for m_key in member_pairs:
            pair_to_cluster[m_key] = cid

        cluster_hashes = sorted(
            {h for i in members for h in pair_hashes_list[i]}
        )
        cluster_metadata[cid] = {
            "rank": rank,
            "size": len(members),
            "share_pct": round(len(members) / n * 100, 2),
            "earliest_discovery": min(pairs[i]["discovery_date"] for i in members),
            "hashes_count": len(cluster_hashes),
            "members": [
                f"{pairs[i]['package']}@{pairs[i]['new_version']}" for i in members
            ],
        }

    return pair_to_cluster, cluster_metadata


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Release Sentinel evaluation.")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of pairs to process")
    parser.add_argument(
        "--workers", type=int, default=8, help="Number of worker threads (default: 8)"
    )
    parser.add_argument(
        "--results-file",
        type=Path,
        default=Path("data/eval_results_v4.jsonl"),
        help="Path to results jsonl file (default: data/eval_results_v4.jsonl)",
    )
    parser.add_argument(
        "--hashes-file",
        type=Path,
        default=Path("data/eval_payload_hashes_v4.json"),
        help="Path to hashes cache file (default: data/eval_payload_hashes_v4.json)",
    )
    parser.add_argument(
        "--clusters-file",
        type=Path,
        default=Path("data/eval_clusters_v4.json"),
        help="Path to clusters json file (default: data/eval_clusters_v4.json)",
    )
    parser.add_argument("--force-recluster", action="store_true", help="Only run re-clustering")
    parser.add_argument(
        "--worker", action="store_true", help="Run in worker mode for a single pair"
    )
    args = parser.parse_args()

    if args.worker:
        input_data = sys.stdin.read()
        if not input_data.strip():
            logger.error("No input provided to worker")
            return 1
        data = json.loads(input_data)
        run_worker(data["pair"])
        return 0

    results_jsonl = args.results_file
    hashes_cache_file = args.hashes_file
    clusters_json = args.clusters_file

    pairs = load_eval_pairs(EVAL_PAIRS_CSV)
    if args.limit:
        pairs = pairs[: args.limit]

    total_pairs = len(pairs)
    print(f"Loaded {total_pairs} buildable pairs from {EVAL_PAIRS_CSV}")

    existing_results = load_existing_results(results_jsonl)
    hashes_cache = load_hashes_cache(hashes_cache_file)
    print(f"Found {len(existing_results)} already completed pairs in {results_jsonl}")

    if not args.force_recluster:
        registry_client = NpmRegistryClient(cache_dir=CACHE_DIR)
        processed_count = len(existing_results)
        write_lock = threading.Lock()
        download_lock = threading.Lock()

        # Filter pending pairs
        pending_pairs = [
            p
            for p in pairs
            if (p["package"], p["old_version"], p["new_version"]) not in existing_results
            or f"{p['package']}@{p['old_version']}@{p['new_version']}" not in hashes_cache
        ]
        print(f"Processing {len(pending_pairs)} pending pairs with {args.workers} workers...")

        # Open jsonl file in append mode
        results_jsonl.parent.mkdir(parents=True, exist_ok=True)
        jsonl_f = open(results_jsonl, "a", encoding="utf-8")

        try:
            if pending_pairs:
                with ThreadPoolExecutor(max_workers=args.workers) as pool:
                    future_to_pair = {
                        pool.submit(run_one_pair, p, registry_client, download_lock): p
                        for p in pending_pairs
                    }
                    for future in as_completed(future_to_pair):
                        pair = future_to_pair[future]
                        key = (pair["package"], pair["old_version"], pair["new_version"])
                        key_str = f"{key[0]}@{key[1]}@{key[2]}"
                        try:
                            row, payload_hashes = future.result()
                        except Exception as exc:
                            logger.error("Pair %s raised unhandled: %s", key_str, exc)
                            split = get_split(pair["discovery_date"])
                            row = {
                                "package": pair["package"],
                                "old": pair["old_version"],
                                "new": pair["new_version"],
                                "discovery_date": pair["discovery_date"],
                                "cluster_id": "pending",
                                "split": split,
                                "status": "error",
                                "decision": None,
                                "evidence_only_decision": None,
                                "max_severity": None,
                                "evidence_types": [],
                                "limitation_count": 0,
                                "seconds": 0.0,
                            }
                            payload_hashes = []

                        with write_lock:
                            existing_results[key] = row
                            hashes_cache[key_str] = payload_hashes
                            jsonl_f.write(json.dumps(row) + "\n")
                            jsonl_f.flush()
                            processed_count += 1
                            if processed_count % 100 == 0 or processed_count == total_pairs:
                                print(f"[{processed_count}/{total_pairs}] processed...", flush=True)
                                save_hashes_cache(hashes_cache_file, hashes_cache)
        finally:
            jsonl_f.close()
            registry_client.close()
            save_hashes_cache(hashes_cache_file, hashes_cache)

    # 3. Campaign clustering over all loaded pairs
    print("Running Union-Find campaign clustering...")
    pair_to_cluster, cluster_meta = cluster_all_pairs(pairs, hashes_cache)

    # Attach decisions to cluster metadata
    for cid, cinfo in cluster_meta.items():
        # Find decisions of all members
        decisions: list[str] = []
        ev_only_decisions: list[str] = []
        statuses: list[str] = []
        for pair in pairs:
            m_key = (pair["package"], pair["old_version"], pair["new_version"])
            if pair_to_cluster.get(m_key) == cid:
                res = existing_results.get(m_key)
                if res:
                    statuses.append(res.get("status", "unknown"))
                    dec = res.get("decision")
                    if dec:
                        decisions.append(dec)
                    ev_dec = res.get("evidence_only_decision")
                    if ev_dec:
                        ev_only_decisions.append(ev_dec)

        if "BLOCK" in decisions:
            cluster_decision = "BLOCK"
        elif "WARN" in decisions:
            cluster_decision = "WARN"
        elif "ALLOW" in decisions:
            cluster_decision = "ALLOW"
        else:
            cluster_decision = "UNDETECTED"

        if "BLOCK" in ev_only_decisions:
            ev_only_cluster_dec = "BLOCK"
        elif "WARN" in ev_only_decisions:
            ev_only_cluster_dec = "WARN"
        elif "ALLOW" in ev_only_decisions:
            ev_only_cluster_dec = "ALLOW"
        else:
            ev_only_cluster_dec = "UNDETECTED"

        cinfo["decision"] = cluster_decision
        cinfo["evidence_only_decision"] = ev_only_cluster_dec
        cinfo["statuses"] = dict(defaultdict(int, {s: statuses.count(s) for s in set(statuses)}))

    with open(clusters_json, "w", encoding="utf-8") as f:
        json.dump(cluster_meta, f, indent=2)

    # Rewrite data/eval_results.jsonl with final cluster_id
    tmp_jsonl = results_jsonl.with_suffix(".tmp")
    with open(tmp_jsonl, "w", encoding="utf-8") as f:
        for pair in pairs:
            key = (pair["package"], pair["old_version"], pair["new_version"])
            row = existing_results.get(key)
            if row:
                row["cluster_id"] = pair_to_cluster.get(key, "singleton")
                f.write(json.dumps(row) + "\n")
    tmp_jsonl.replace(results_jsonl)

    # Print summary
    statuses_cnt: dict[str, int] = defaultdict(int)
    decisions_cnt: dict[str, int] = defaultdict(int)
    for pair in pairs:
        key = (pair["package"], pair["old_version"], pair["new_version"])
        row = existing_results.get(key, {})
        statuses_cnt[row.get("status", "missing")] += 1
        if row.get("decision"):
            decisions_cnt[row["decision"]] += 1

    print("\n=== Stage 4a Execution Complete ===")
    print(f"Total pairs: {len(pairs)}")
    print(f"Statuses: {dict(statuses_cnt)}")
    print(f"Decisions: {dict(decisions_cnt)}")
    print(f"Total clusters: {len(cluster_meta)}")
    top1 = list(cluster_meta.values())[0] if cluster_meta else {}
    print(f"Largest cluster size: {top1.get('size')} ({top1.get('share_pct')}%)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
