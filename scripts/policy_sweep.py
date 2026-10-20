"""Policy Sweep Tooling (Release Sentinel Stage 5c).

Evaluates policy variants against real benign and malicious evidence:
- Automatically re-scans or invalidates cache when scanner source code changes.
- Caches full Evidence objects to avoid synthetic severity mismatches.
- Evaluates across benign updates (Tuning, Validation, Matched Negatives) and malicious clusters.
- Enforces guardrails: 0 false BLOCKs, highest cluster BLOCK recall, lowest alert burden.
"""

from __future__ import annotations

import csv
import hashlib
import json
import logging
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Any

from release_sentinel.differ import analyze_release
from release_sentinel.engine import decide
from release_sentinel.extractor import extract_release_in_memory
from release_sentinel.models import Decision, Evidence, Severity
from release_sentinel.policy import Policy
from release_sentinel.registry import NpmRegistryClient

logger = logging.getLogger("policy_sweep")

CACHE_DIR = Path.home() / ".cache" / "release_sentinel"
SAMPLES_ROOT = Path(r"C:\rs-data\datadog")

SCANNER_FILES = [
    Path("src/release_sentinel/differ.py"),
    Path("src/release_sentinel/content_scanner.py"),
    Path("src/release_sentinel/extractor.py"),
    Path("src/release_sentinel/engine.py"),
    Path("src/release_sentinel/eval.py"),
]


def compute_scanner_hash() -> str:
    """Compute a deterministic hash of all scanner and extraction source files."""
    h = hashlib.sha256()
    for f in SCANNER_FILES:
        if f.exists():
            h.update(f.read_bytes())
    return h.hexdigest()[:16]


def get_benign_evidence_cache_path(scanner_hash: str) -> Path:
    return Path(f"data/cache/benign_evidence_{scanner_hash}.json")


def load_benign_pairs() -> list[dict[str, Any]]:
    """Load metadata for all 800 benign evaluation updates."""
    tuning_rows = list(csv.DictReader(open("data/smoke_results_v5.csv", encoding="utf-8")))
    val_smoke_rows = list(csv.DictReader(open("data/smoke_validation_v5.csv", encoding="utf-8")))
    matched_neg_rows = [
        json.loads(line)
        for line in open("data/matched_negatives_results_v5.jsonl", encoding="utf-8")
        if line.strip()
    ]

    all_pairs: list[dict[str, Any]] = []
    for r in tuning_rows:
        all_pairs.append(
            {
                "set": "tuning",
                "package": r["package"],
                "old": r["old"],
                "new": r["new"],
                "published_new": r.get("published_new", "2026-01-01T00:00:00Z"),
            }
        )
    for r in val_smoke_rows:
        all_pairs.append(
            {
                "set": "val_smoke",
                "package": r["package"],
                "old": r["old"],
                "new": r["new"],
                "published_new": r.get("published_new", "2026-01-01T00:00:00Z"),
            }
        )
    for r in matched_neg_rows:
        all_pairs.append(
            {
                "set": "matched_neg",
                "package": r["package"],
                "old": r["old_version"],
                "new": r["new_version"],
                "published_new": r.get("as_of", "2026-01-01T00:00:00Z"),
            }
        )

    return all_pairs


def get_or_scan_benign_evidence(
    client: NpmRegistryClient,
    workers: int = 8,
) -> list[dict[str, Any]]:
    """Load benign evidence from cache keyed on scanner hash, or scan and cache."""
    s_hash = compute_scanner_hash()
    cache_path = get_benign_evidence_cache_path(s_hash)

    if cache_path.exists():
        print(f"Loading cached benign evidence from {cache_path} (scanner hash: {s_hash})...")
        try:
            raw = json.loads(cache_path.read_text(encoding="utf-8"))
            return raw
        except Exception as exc:
            logger.warning("Cache read failed (%s); re-scanning...", exc)

    print(f"Scanning 800 benign pairs with {workers} workers (scanner hash: {s_hash})...")
    benign_pairs = load_benign_pairs()
    dest_temp = CACHE_DIR / "tarballs" / "eval_tmp"
    dest_temp.mkdir(parents=True, exist_ok=True)

    def scan_one_benign(pair: dict[str, Any]) -> dict[str, Any]:
        pkg = pair["package"]
        old_v = pair["old"]
        new_v = pair["new"]
        pub_dt = datetime.fromisoformat(pair["published_new"].replace("Z", "+00:00"))

        try:
            old_tgz = client.download_tarball(pkg, old_v, as_of=pub_dt, dest_dir=dest_temp)
            new_tgz = client.download_tarball(pkg, new_v, as_of=pub_dt, dest_dir=dest_temp)

            rc_old = extract_release_in_memory(old_tgz)
            rc_new = extract_release_in_memory(new_tgz)

            ev_list = analyze_release(
                new=rc_new,
                baseline=rc_old,
                as_of=pub_dt,
                registry_client=client,
                dest_dir=dest_temp,
            )
            serialized_ev = [
                {
                    "id": e.id,
                    "severity": e.severity.value,
                    "file": e.file,
                    "explanation": e.explanation,
                    "legitimate_use_note": e.legitimate_use_note,
                }
                for e in ev_list
            ]
        except Exception as exc:
            logger.error("Failed scanning benign %s %s->%s: %s", pkg, old_v, new_v, exc)
            serialized_ev = []

        return {
            "set": pair["set"],
            "package": pkg,
            "old": old_v,
            "new": new_v,
            "evidence": serialized_ev,
        }

    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(scan_one_benign, benign_pairs))

    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(results), encoding="utf-8")
    print(f"Saved {len(results)} scanned benign results to {cache_path}")
    return results


def evaluate_policy_on_evidence(
    policy: Policy,
    benign_results: list[dict[str, Any]],
    malicious_results: list[dict[str, Any]],
    malicious_clusters: dict[str, Any],
) -> dict[str, Any]:
    """Score a single policy against benign and malicious evidence."""
    # 1. Benign evaluation
    b_blocks = {"tuning": 0, "val_smoke": 0, "matched_neg": 0, "total": 0}
    b_warns = {"tuning": 0, "val_smoke": 0, "matched_neg": 0, "total": 0}
    b_allows = {"tuning": 0, "val_smoke": 0, "matched_neg": 0, "total": 0}

    for b in benign_results:
        ev_objs = [
            Evidence(
                id=e["id"],
                severity=Severity(e["severity"]),
                file=e.get("file"),
                explanation=e.get("explanation", ""),
                legitimate_use_note=e.get("legitimate_use_note", ""),
            )
            for e in b["evidence"]
        ]
        dec, _ = decide(ev_objs, policy=policy, is_full_scan=False)
        set_name = b["set"]
        if dec == Decision.BLOCK:
            b_blocks[set_name] += 1
            b_blocks["total"] += 1
        elif dec == Decision.WARN:
            b_warns[set_name] += 1
            b_warns["total"] += 1
        else:
            b_allows[set_name] += 1
            b_allows["total"] += 1

    total_benign = len(benign_results)
    alert_burden = (b_blocks["total"] + b_warns["total"]) / total_benign * 100

    # 2. Malicious evaluation
    cluster_pairs = defaultdict(list)
    for m in malicious_results:
        cid = m.get("cluster_id")
        if cid in malicious_clusters:
            cluster_pairs[cid].append(m)

    lenient_block = 0
    lenient_warn_plus = 0
    macro_block_sum = 0.0
    macro_warn_sum = 0.0

    for cid in malicious_clusters:
        cpairs = cluster_pairs.get(cid, [])
        if not cpairs:
            continue
        c_blocks = 0
        c_warn_plus = 0
        for p in cpairs:
            ev_objs = [
                Evidence(
                    id=e["id"],
                    severity=Severity(e["severity"]),
                    file=e.get("file"),
                    explanation=e.get("explanation", ""),
                    legitimate_use_note=e.get("legitimate_use_note", ""),
                )
                for e in p["evidence"]
            ]
            dec, _ = decide(ev_objs, policy=policy, is_full_scan=p.get("is_full_scan", False))
            if dec == Decision.BLOCK:
                c_blocks += 1
            if dec in (Decision.WARN, Decision.BLOCK):
                c_warn_plus += 1

        if c_blocks > 0:
            lenient_block += 1
        if c_warn_plus > 0:
            lenient_warn_plus += 1

        macro_block_sum += c_blocks / len(cpairs)
        macro_warn_sum += c_warn_plus / len(cpairs)

    n_clusters = len(malicious_clusters)
    return {
        "false_blocks": b_blocks["total"],
        "false_blocks_tuning": b_blocks["tuning"],
        "false_blocks_val": b_blocks["val_smoke"],
        "false_blocks_matched": b_blocks["matched_neg"],
        "benign_alert_burden": alert_burden,
        "tuning_alerts_per_100": (b_blocks["tuning"] + b_warns["tuning"]) / 100 * 100,
        "val_alerts_per_100": (b_blocks["val_smoke"] + b_warns["val_smoke"]) / 100 * 100,
        "matched_alerts_per_100": (b_blocks["matched_neg"] + b_warns["matched_neg"]) / 600 * 100,
        "mal_clusters_lenient_block": (
            f"{lenient_block}/{n_clusters} ({lenient_block / n_clusters * 100:.2f}%)"
        ),
        "mal_clusters_macro_block": f"{macro_block_sum / n_clusters * 100:.2f}%",
        "mal_clusters_lenient_warn": (
            f"{lenient_warn_plus}/{n_clusters} ({lenient_warn_plus / n_clusters * 100:.2f}%)"
        ),
        "mal_clusters_macro_warn": f"{macro_warn_sum / n_clusters * 100:.2f}%",
        "raw_lenient_block": lenient_block,
        "raw_macro_block": macro_block_sum / n_clusters * 100,
    }
