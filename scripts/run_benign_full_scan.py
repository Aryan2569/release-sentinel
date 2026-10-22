"""Run benign full-scan validation on 500 popular, actively maintained npm packages.

Rules enforced:
- Rule 1: Never execute code (static in-memory inspection only).
- Rule 2: Safe extraction in memory with caps.
- Rule 5: Writes only to project directory and cache dir.
"""

from __future__ import annotations

import json
import logging
import math
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from release_sentinel.differ import analyze_release
from release_sentinel.engine import decide
from release_sentinel.extractor import ExtractionConfig, extract_release_in_memory
from release_sentinel.policy import load_policy
from release_sentinel.registry import NpmRegistryClient

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("benign_full_scan")

CACHE_DIR = Path.home() / ".cache" / "release_sentinel"
CORPUS_FILE = Path("data/benign_full_scan_500.json")
RESULTS_FILE = Path("data/benign_full_scan_results.json")


def clopper_pearson(k: int, n: int, alpha: float = 0.05) -> tuple[float, float]:
    """Exact Clopper-Pearson 95% confidence interval."""
    if n == 0:
        return 0.0, 1.0

    def binom_cdf(k_val: int, n_val: int, p_val: float) -> float:
        return sum(math.comb(n_val, j) * (p_val**j) * ((1 - p_val) ** (n_val - j)) for j in range(k_val + 1))

    if k == 0:
        lower = 0.0
    else:
        lo, hi = 0.0, 1.0
        for _ in range(60):
            mid = (lo + hi) / 2
            if 1 - binom_cdf(k - 1, n, mid) > alpha / 2:
                lo = mid
            else:
                hi = mid
        lower = (lo + hi) / 2

    if k == n:
        upper = 1.0
    else:
        lo, hi = 0.0, 1.0
        for _ in range(60):
            mid = (lo + hi) / 2
            if binom_cdf(k, n, mid) < alpha / 2:
                hi = mid
            else:
                lo = mid
        upper = (lo + hi) / 2

    return lower, upper


def select_corpus() -> list[dict[str, str]]:
    if CORPUS_FILE.exists():
        with open(CORPUS_FILE, encoding="utf-8") as f:
            data = json.load(f)
            if len(data) >= 500:
                return data

    with open("data/popular_packages_2000.json", encoding="utf-8") as f:
        pkg_names = json.load(f)

    client = NpmRegistryClient(cache_dir=CACHE_DIR)
    pkgs_with_date: list[dict[str, str]] = []

    print("Selecting 500 actively maintained popular packages across size/kind spectrum...")
    now_utc = datetime.now(tz=UTC)

    for pkg in pkg_names:
        try:
            meta = client.get_metadata(pkg, as_of=now_utc)
            versions = meta.get("versions", {})
            dist_tags = meta.get("dist-tags", {})
            time_map = meta.get("time", {})
            latest_ver = dist_tags.get("latest")
            if not latest_ver or latest_ver not in versions:
                continue

            pub_time = time_map.get(latest_ver, "")
            if not pub_time:
                continue

            pkgs_with_date.append({
                "package": pkg,
                "version": latest_ver,
                "published_at": pub_time,
            })
        except Exception:
            continue

    client.close()
    pkgs_with_date.sort(key=lambda x: x["published_at"], reverse=True)
    selected = pkgs_with_date[:500]
    print(f"Selected {len(selected)} packages. Saving to {CORPUS_FILE}...")
    with open(CORPUS_FILE, "w", encoding="utf-8") as f:
        json.dump(selected, f, indent=2)
    return selected


def scan_single_package(
    pkg_info: dict[str, str],
    client: NpmRegistryClient,
    policy,
) -> dict[str, Any]:
    pkg = pkg_info["package"]
    ver = pkg_info["version"]
    pub_dt = datetime.fromisoformat(pkg_info["published_at"].replace("Z", "+00:00")).astimezone(UTC)

    t0 = time.perf_counter()
    dest_dir = CACHE_DIR / "tarballs" / "full_scan_tmp"
    dest_dir.mkdir(parents=True, exist_ok=True)

    try:
        tarball_path = client.download_tarball(pkg, ver, as_of=pub_dt, dest_dir=dest_dir)
        cfg = ExtractionConfig()
        rc = extract_release_in_memory(tarball_path, config=cfg)
        evidence = analyze_release(
            new=rc,
            baseline=None,  # full-scan mode
            policy=policy,
            config=cfg,
            as_of=pub_dt,
            registry_client=client,
        )
        decision, limitations = decide(evidence, policy=policy, is_full_scan=True)
        elapsed = round(time.perf_counter() - t0, 3)

        ev_ids = sorted({e.id for e in evidence})
        has_dynamic_and_blob = ("dynamic_code" in ev_ids and "long_encoded_blob" in ev_ids)

        return {
            "package": pkg,
            "version": ver,
            "decision": decision.name,
            "evidence": ev_ids,
            "evidence_count": len(evidence),
            "limitations_count": len(limitations),
            "seconds": elapsed,
            "has_dynamic_and_blob": has_dynamic_and_blob,
            "status": "ok",
        }
    except Exception as exc:
        elapsed = round(time.perf_counter() - t0, 3)
        return {
            "package": pkg,
            "version": ver,
            "decision": "ERROR",
            "evidence": [],
            "evidence_count": 0,
            "limitations_count": 0,
            "seconds": elapsed,
            "has_dynamic_and_blob": False,
            "status": f"error: {exc}",
        }


def main() -> None:
    corpus = select_corpus()
    print(f"Loaded corpus of {len(corpus)} packages.")

    policy = load_policy()
    client = NpmRegistryClient(cache_dir=CACHE_DIR)

    results: list[dict[str, Any]] = []
    print(f"Running in-memory full-scan over {len(corpus)} packages with 8 workers...")

    with ThreadPoolExecutor(max_workers=8) as pool:
        future_to_pkg = {pool.submit(scan_single_package, p, client, policy): p for p in corpus}
        count = 0
        for future in as_completed(future_to_pkg):
            res = future.result()
            results.append(res)
            count += 1
            if count % 50 == 0 or count == len(corpus):
                print(f"[{count}/{len(corpus)}] scanned...", flush=True)

    client.close()

    # Save results
    with open(RESULTS_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"Saved full-scan results to {RESULTS_FILE}")

    # Summary
    decisions = Counter(r["decision"] for r in results)
    print("\n=== Full-Scan Validation Results ===")
    print(f"Total packages: {len(results)}")
    for d, c in decisions.most_common():
        print(f"  {d}: {c} ({c / len(results) * 100:.2f}%)")

    n = len(results)
    k_block = decisions.get("BLOCK", 0)
    lo, hi = clopper_pearson(k_block, n)
    print(f"\nBLOCK Rate: {k_block}/{n} ({k_block/n*100:.2f}%) [95% CI: {lo*100:.2f}%, {hi*100:.2f}%]")

    # Check dynamic_code + long_encoded_blob
    dyn_blob_pkgs = [r for r in results if r.get("has_dynamic_and_blob")]
    print(f"\nPackages hitting dynamic_code + long_encoded_blob ({len(dyn_blob_pkgs)}):")
    for r in dyn_blob_pkgs:
        print(f"  {r['package']}@{r['version']} -> decision={r['decision']}, ev={r['evidence']}")

    # Check all BLOCKs and WARNs
    blocks = [r for r in results if r["decision"] == "BLOCK"]
    warns = [r for r in results if r["decision"] == "WARN"]
    print(f"\nTotal BLOCKs: {len(blocks)}")
    for r in blocks:
        print(f"  BLOCK: {r['package']}@{r['version']} -> {r['evidence']}")

    print(f"\nTotal WARNs: {len(warns)}")
    warn_by_ev = Counter()
    for r in warns:
        for ev in r["evidence"]:
            warn_by_ev[ev] += 1
    print("Most common evidence in WARN packages:")
    for ev, c in warn_by_ev.most_common(10):
        print(f"  {ev}: {c}")


if __name__ == "__main__":
    main()
