"""Runner for matched negatives evaluation in Stage 4b.

Runs Release Sentinel detector over data/matched_negatives.csv:
- Resumable (skips already completed pairs in data/matched_negatives_results.jsonl)
- 8 worker threads with polite retries and caching
- Process-level isolation with 60-second timeout per pair
- Reports decision distribution, alert rate per 100, and lists any BLOCK decisions.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from release_sentinel.differ import analyze_release
from release_sentinel.engine import decide
from release_sentinel.extractor import ExtractionConfig, extract_release
from release_sentinel.registry import NpmRegistryClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("run_matched_negatives")

CACHE_DIR = Path.home() / ".cache" / "release_sentinel"
MATCHED_CSV = Path("data/matched_negatives.csv")
RESULTS_JSONL = Path("data/matched_negatives_results.jsonl")


def load_existing_results(jsonl_path: Path) -> dict[tuple[str, str, str], dict[str, Any]]:
    results = {}
    if not jsonl_path.exists():
        return results
    with open(jsonl_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
                key = (row["package"], row["old_version"], row["new_version"])
                results[key] = row
            except Exception as exc:
                logger.debug("Skipping invalid JSON line: %s", exc)
                continue
    return results


def run_worker(pair: dict[str, Any]) -> None:
    package = pair["package"]
    old_ver = pair["old_version"]
    new_ver = pair["new_version"]
    as_of_str = pair.get("as_of", "")
    cluster_id = pair.get("cluster_id", "none")

    try:
        as_of = datetime.fromisoformat(as_of_str.replace("Z", "+00:00")).astimezone(UTC)
    except Exception:
        as_of = datetime.now(UTC)

    client = NpmRegistryClient(cache_dir=CACHE_DIR)
    ext_cfg = ExtractionConfig()

    with tempfile.TemporaryDirectory(prefix="matched-neg-") as tmp:
        tmp_path = Path(tmp)
        t0 = time.perf_counter()

        old_tgz = client.download_tarball(
            package, old_ver, as_of=as_of, dest_dir=tmp_path / "old"
        )
        new_tgz = client.download_tarball(
            package, new_ver, as_of=as_of, dest_dir=tmp_path / "new"
        )

        old_res = extract_release(old_tgz, tmp_path / "old_ext", config=ext_cfg)
        new_res = extract_release(new_tgz, tmp_path / "new_ext", config=ext_cfg)

        evidence = analyze_release(
            new=new_res,
            baseline=old_res,
            as_of=as_of,
            registry_client=client,
            dest_dir=tmp_path / "dep_tarballs",
        )
        decision, limitations = decide(evidence)
        elapsed = round(time.perf_counter() - t0, 3)

        ev_ids = sorted({e.id for e in evidence})
        max_sev = "NONE"
        if evidence:
            sev_order = {"INFO": -1, "LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
            max_sev = max((e.severity.value for e in evidence), key=lambda s: sev_order.get(s, 0))

        has_inc = any(e.id == "inspection_incomplete" for e in evidence)
        status = "inspection_incomplete" if has_inc else "ok"

        output = {
            "package": package,
            "old_version": old_ver,
            "new_version": new_ver,
            "cluster_id": cluster_id,
            "status": status,
            "decision": decision.value,
            "max_severity": max_sev,
            "evidence_types": ev_ids,
            "limitation_count": len(limitations),
            "seconds": elapsed,
        }
        print(json.dumps(output))


def run_one_pair(
    pair: dict[str, Any],
    client: NpmRegistryClient,
    download_lock: threading.Lock,
) -> dict[str, Any]:
    package = pair["package"]
    old_ver = pair["old_version"]
    new_ver = pair["new_version"]
    cluster_id = pair.get("cluster_id", "none")
    as_of_str = pair.get("as_of", "")

    try:
        as_of = datetime.fromisoformat(as_of_str.replace("Z", "+00:00")).astimezone(UTC)
    except Exception:
        as_of = datetime.now(UTC)

    t0 = time.perf_counter()

    # Ensure tarballs exist
    dest_temp = CACHE_DIR / "tarballs" / "eval_tmp"
    dest_temp.mkdir(parents=True, exist_ok=True)

    for ver in (old_ver, new_ver):
        tarball_ok = False
        for attempt in range(2):
            try:
                with download_lock:
                    client.download_tarball(package, ver, as_of=as_of, dest_dir=dest_temp)
                tarball_ok = True
                break
            except Exception as exc:
                if attempt == 0:
                    time.sleep(1.0)
                else:
                    logger.warning("Failed downloading tarball for %s@%s: %s", package, ver, exc)

        if not tarball_ok:
            elapsed = round(time.perf_counter() - t0, 3)
            return {
                "package": package,
                "old_version": old_ver,
                "new_version": new_ver,
                "cluster_id": cluster_id,
                "status": "baseline_download_failed",
                "decision": None,
                "max_severity": None,
                "evidence_types": [],
                "limitation_count": 0,
                "seconds": elapsed,
            }

    # Run in isolated subprocess with 60s timeout
    cmd = [sys.executable, str(Path(__file__).resolve()), "--worker"]
    payload = json.dumps({"pair": pair})

    try:
        proc = subprocess.run(  # noqa: S603
            cmd,
            input=payload,
            capture_output=True,
            text=True,
            timeout=60.0,
        )
    except subprocess.TimeoutExpired:
        elapsed = 60.0
        logger.warning("Pair %s %s->%s timed out after 60s", package, old_ver, new_ver)
        return {
            "package": package,
            "old_version": old_ver,
            "new_version": new_ver,
            "cluster_id": cluster_id,
            "status": "inspection_incomplete",
            "decision": "WARN",
            "max_severity": "MEDIUM",
            "evidence_types": ["inspection_incomplete"],
            "limitation_count": 1,
            "seconds": elapsed,
        }

    elapsed = round(time.perf_counter() - t0, 3)
    if proc.returncode != 0:
        err_msg = proc.stderr[:300]
        logger.error("Worker failed for %s %s->%s: %s", package, old_ver, new_ver, err_msg)
        return {
            "package": package,
            "old_version": old_ver,
            "new_version": new_ver,
            "cluster_id": cluster_id,
            "status": "error",
            "decision": None,
            "max_severity": None,
            "evidence_types": [],
            "limitation_count": 0,
            "seconds": elapsed,
        }

    out_line = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ""
    if not out_line:
        return {
            "package": package,
            "old_version": old_ver,
            "new_version": new_ver,
            "cluster_id": cluster_id,
            "status": "error",
            "decision": None,
            "max_severity": None,
            "evidence_types": [],
            "limitation_count": 0,
            "seconds": elapsed,
        }

    return json.loads(out_line)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Matched Negatives Evaluation")
    parser.add_argument(
        "--workers", type=int, default=8, help="Number of worker threads (default: 8)"
    )
    parser.add_argument(
        "--results-file",
        type=Path,
        default=RESULTS_JSONL,
        help="Path to results jsonl file (default: data/matched_negatives_results.jsonl)",
    )
    parser.add_argument(
        "--worker", action="store_true", help="Run in worker mode for a single pair"
    )
    args = parser.parse_args()

    if args.worker:
        input_data = sys.stdin.read()
        if not input_data.strip():
            return 1
        data = json.loads(input_data)
        run_worker(data["pair"])
        return 0

    with open(MATCHED_CSV, encoding="utf-8") as f:
        pairs = list(csv.DictReader(f))

    results_file = args.results_file
    print(f"Loaded {len(pairs)} matched negative pairs from {MATCHED_CSV}")
    existing_results = load_existing_results(results_file)
    print(f"Found {len(existing_results)} already completed in {results_file}")

    pending = [
        p for p in pairs
        if (p["package"], p["old_version"], p["new_version"]) not in existing_results
    ]
    print(f"Processing {len(pending)} pending pairs with {args.workers} workers...")

    results_file.parent.mkdir(parents=True, exist_ok=True)
    jsonl_f = open(results_file, "a", encoding="utf-8")
    write_lock = threading.Lock()
    download_lock = threading.Lock()
    client = NpmRegistryClient(cache_dir=CACHE_DIR)

    completed_count = len(existing_results)

    try:
        if pending:
            with ThreadPoolExecutor(max_workers=args.workers) as pool:
                future_to_pair = {
                    pool.submit(run_one_pair, p, client, download_lock): p
                    for p in pending
                }
                for future in as_completed(future_to_pair):
                    pair = future_to_pair[future]
                    try:
                        row = future.result()
                    except Exception as exc:
                        logger.error("Unhandled exception for %s: %s", pair["package"], exc)
                        row = {
                            "package": pair["package"],
                            "old_version": pair["old_version"],
                            "new_version": pair["new_version"],
                            "cluster_id": pair.get("cluster_id", "none"),
                            "status": "error",
                            "decision": None,
                            "max_severity": None,
                            "evidence_types": [],
                            "limitation_count": 0,
                            "seconds": 0.0,
                        }

                    with write_lock:
                        jsonl_f.write(json.dumps(row) + "\n")
                        jsonl_f.flush()
                        key = (row["package"], row["old_version"], row["new_version"])
                        existing_results[key] = row
                        completed_count += 1
                        if completed_count % 50 == 0 or completed_count == len(pairs):
                            msg = f"Progress: {completed_count}/{len(pairs)} completed"
                            print(msg)
    finally:
        jsonl_f.close()

    # Summary
    all_res = list(existing_results.values())
    total = len(all_res)
    decisions = [r["decision"] for r in all_res if r.get("decision")]
    allow_cnt = sum(1 for d in decisions if d == "ALLOW")
    warn_cnt = sum(1 for d in decisions if d == "WARN")
    block_cnt = sum(1 for d in decisions if d == "BLOCK")

    alert_count = warn_cnt + block_cnt
    alert_rate = (alert_count / total * 100) if total else 0.0

    print("\n=== Matched Negatives Evaluation Results ===")
    print(f"Total pairs evaluated: {total}")
    print(f"ALLOW: {allow_cnt} ({allow_cnt/total*100:.2f}%)")
    print(f"WARN:  {warn_cnt} ({warn_cnt/total*100:.2f}%)")
    print(f"BLOCK: {block_cnt} ({block_cnt/total*100:.2f}%)")
    print(f"Alert rate: {alert_rate:.2f} alerts per 100 updates")

    if block_cnt > 0:
        print("\nBLOCK Decisions:")
        for r in all_res:
            if r.get("decision") == "BLOCK":
                p_str = f"  {r['package']} {r['old_version']}->{r['new_version']}"
                print(f"{p_str}: evidence={r['evidence_types']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
