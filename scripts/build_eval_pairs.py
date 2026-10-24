"""Build data/eval_pairs.csv for Release Sentinel Stage 3a (Resumable, No Tarball Downloads).

For each compromised sample present in the DataDog dataset:
- Look up previous benign release from the npm registry:
  - Highest stable semver of the same major lower than the malicious version
  - Not listed as affected in manifest.json
  - Version exists in registry metadata with dist info present
- Record status:
  - ok: baseline found in metadata with dist tarball present
  - no_baseline: package on npm, but no lower stable version in same major
  - package_removed: package 404 / unpublished from npm
  - other: any error (network failure after retry, unparseable semver, missing dist)

Features:
- Resumable: writes rows incrementally and flushes; skips pairs already done.
- Caches registry metadata on disk (including 404s).
- Polite: small delay between requests, timeouts, and one retry.
- Does NOT download tarballs (handled at analysis time).
"""

from __future__ import annotations

import csv
import json
import logging
import re
import time
import urllib.parse
from pathlib import Path
from typing import Any

import httpx

from release_sentinel.eval import get_samples_root
from release_sentinel.registry import _safe_filename

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

CACHE_DIR = Path.home() / ".cache" / "release_sentinel"
METADATA_CACHE = CACHE_DIR / "metadata"

MANIFEST_PATH = get_samples_root() / "samples" / "npm" / "manifest.json"
LABELS_PATH = Path("data/labels_npm_compromised.csv")
OUTPUT_PATH = Path("data/eval_pairs.csv")

SEMVER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
SEMVER_PREFIX_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)")


def parse_semver_strict(v: str) -> tuple[int, int, int] | None:
    m = SEMVER_RE.match(v)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def parse_semver_loose(v: str) -> tuple[int, int, int] | None:
    m = SEMVER_PREFIX_RE.match(v)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def fetch_package_metadata(
    pkg: str,
    client: httpx.Client,
) -> tuple[dict[str, Any] | None, int, str]:
    """Fetch package packument from npm registry or disk cache.

    Caches on disk to ~/.cache/release_sentinel/metadata.
    Returns (metadata_dict, http_status_code, error_message).
    """
    safe_name = _safe_filename(pkg)
    cache_file = METADATA_CACHE / f"{safe_name}.json"
    if cache_file.exists():
        try:
            cached_data = json.loads(cache_file.read_text(encoding="utf-8"))
            if cached_data.get("_not_found"):
                return None, 404, "Package not found on npm registry (404/unpublished)"
            return cached_data, 200, ""
        except Exception as exc:
            logger.warning("Corrupt metadata cache for %s: %s", pkg, exc)

    encoded_name = urllib.parse.quote(pkg, safe="@")
    url = f"https://registry.npmjs.org/{encoded_name}"

    for attempt in range(2):
        try:
            time.sleep(0.05)  # Polite delay
            resp = client.get(url, timeout=15.0)
            if resp.status_code == 200:
                data = resp.json()
                METADATA_CACHE.mkdir(parents=True, exist_ok=True)
                cache_file.write_text(json.dumps(data), encoding="utf-8")
                return data, 200, ""
            elif resp.status_code == 404:
                METADATA_CACHE.mkdir(parents=True, exist_ok=True)
                cache_file.write_text(json.dumps({"_not_found": True}), encoding="utf-8")
                return None, 404, "Package not found on npm registry (404/unpublished)"
            else:
                if attempt == 0:
                    time.sleep(0.5)
                    continue
                return None, resp.status_code, f"HTTP {resp.status_code} from registry"
        except Exception as exc:
            if attempt == 0:
                time.sleep(0.5)
                continue
            return None, 0, f"Network error: {exc}"

    return None, 0, "Unknown registry error"


def main() -> None:
    METADATA_CACHE.mkdir(parents=True, exist_ok=True)

    logger.info("Loading manifest from %s", MANIFEST_PATH)
    with open(MANIFEST_PATH, encoding="utf-8") as f:
        manifest = json.load(f)

    logger.info("Loading samples from %s", LABELS_PATH)
    samples: list[dict[str, str]] = []
    with open(LABELS_PATH, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            if r["sample_present"] == "True":
                samples.append(r)

    logger.info("Total samples with samples present: %d", len(samples))

    # Read existing completed pairs if output CSV already exists
    completed: set[tuple[str, str]] = set()
    fieldnames = [
        "package",
        "old_version",
        "new_version",
        "discovery_date",
        "zip_path",
        "status",
        "reason",
    ]

    if OUTPUT_PATH.exists():
        with open(OUTPUT_PATH, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for r in reader:
                completed.add((r["package"], r["new_version"]))
        logger.info("Found %d already completed pairs in %s", len(completed), OUTPUT_PATH)

    client = httpx.Client(
        headers={"User-Agent": "release-sentinel/0.1.0 (eval-builder)"},
        follow_redirects=True,
    )

    # In-memory session cache for this run
    mem_cache: dict[str, tuple[dict[str, Any] | None, int, str]] = {}

    write_header = not OUTPUT_PATH.exists() or OUTPUT_PATH.stat().st_size == 0
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_PATH, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if write_header:
            writer.writeheader()
            f.flush()

        done_count = len(completed)
        for _idx, s in enumerate(samples, 1):
            pkg = s["package"]
            new_v = s["version"]
            pair_key = (pkg, new_v)

            if pair_key in completed:
                continue

            if pkg not in mem_cache:
                mem_cache[pkg] = fetch_package_metadata(pkg, client)

            meta, status_code, err_msg = mem_cache[pkg]

            old_version = ""
            status = "ok"
            reason = ""

            if meta is None:
                if status_code == 404:
                    status = "package_removed"
                    reason = err_msg
                else:
                    status = "other"
                    reason = err_msg
            else:
                new_tuple = parse_semver_loose(new_v)
                if not new_tuple:
                    status = "other"
                    reason = f"Unparseable malicious version: {new_v}"
                else:
                    new_maj = new_tuple[0]
                    versions_map = meta.get("versions", {})
                    affected_set = set(manifest.get(pkg) or [])

                    candidates: list[tuple[tuple[int, int, int], str]] = []
                    for v_str in versions_map:
                        v_tup = parse_semver_strict(v_str)
                        if not v_tup:
                            continue
                        if v_tup[0] == new_maj and v_tup < new_tuple and v_str not in affected_set:
                            candidates.append((v_tup, v_str))

                    if not candidates:
                        status = "no_baseline"
                        reason = f"No prior stable version in major {new_maj} lower than {new_v}"
                    else:
                        best_tuple, best_ver = max(candidates, key=lambda c: c[0])
                        v_obj = versions_map.get(best_ver, {})
                        tarball_url = v_obj.get("dist", {}).get("tarball")
                        if not tarball_url:
                            status = "other"
                            reason = f"Missing dist.tarball in metadata for {best_ver}"
                        else:
                            old_version = best_ver
                            status = "ok"
                            reason = ""

            writer.writerow(
                {
                    "package": pkg,
                    "old_version": old_version,
                    "new_version": new_v,
                    "discovery_date": s["discovery_date"],
                    "zip_path": s["zip_path"],
                    "status": status,
                    "reason": reason,
                }
            )
            f.flush()
            completed.add(pair_key)
            done_count += 1

            if done_count % 100 == 0 or done_count == len(samples):
                logger.info("Progress: %d / %d pairs processed", done_count, len(samples))

    client.close()

    # Summary
    with open(OUTPUT_PATH, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        all_rows = list(reader)

    status_counts: dict[str, int] = {}
    for r in all_rows:
        st = r["status"]
        status_counts[st] = status_counts.get(st, 0) + 1

    logger.info("Complete! Total rows in %s: %d", OUTPUT_PATH, len(all_rows))
    logger.info("Status distribution: %s", status_counts)


if __name__ == "__main__":
    main()
