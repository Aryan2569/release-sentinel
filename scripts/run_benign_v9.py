"""Re-evaluate the three benign benchmark sets (800 pairs) under v1.3 detector.

Inputs:
- data/smoke_results_v8.csv (100 tuning pairs)
- data/smoke_validation_v8.csv (100 validation pairs)
- data/matched_negatives.csv / data/matched_negatives_results_v8.jsonl (600 matched negative pairs)

Outputs:
- data/smoke_results_v9.csv
- data/smoke_validation_v9.csv
- data/matched_negatives_results_v9.jsonl
"""

import csv
import json
import logging
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from release_sentinel.differ import analyze_release
from release_sentinel.engine import decide
from release_sentinel.extractor import ExtractionConfig, extract_release
from release_sentinel.models import Severity
from release_sentinel.policy import load_policy
from release_sentinel.registry import NpmRegistryClient

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("run_benign_v9")

CACHE_DIR = Path.home() / ".cache" / "release_sentinel"
_SEV_ORDER = {
    Severity.INFO: -1,
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


def evaluate_pair(
    client: NpmRegistryClient,
    pkg: str,
    old_ver: str,
    new_ver: str,
    as_of: datetime,
    policy,
) -> dict[str, Any]:
    t0 = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="benign-v9-") as tmp:
        tmp_path = Path(tmp)
        old_tgz = client.download_tarball(pkg, old_ver, as_of, tmp_path / "old")
        new_tgz = client.download_tarball(pkg, new_ver, as_of, tmp_path / "new")

        ext_cfg = ExtractionConfig()
        old_res = extract_release(old_tgz, tmp_path / "old_ext", config=ext_cfg)
        new_res = extract_release(new_tgz, tmp_path / "new_ext", config=ext_cfg)

        evidence = analyze_release(
            new=new_res,
            baseline=old_res,
            policy=policy,
            config=ext_cfg,
            as_of=as_of,
            registry_client=client,
            dest_dir=tmp_path / "dep_tarballs",
        )

    decision, limitations = decide(evidence, policy=policy)
    elapsed = round(time.perf_counter() - t0, 3)

    max_sev = "NONE"
    if evidence:
        max_sev = max((e.severity for e in evidence), key=lambda s: _SEV_ORDER[s]).value

    ev_types = sorted({e.id for e in evidence})
    return {
        "decision": decision.name,
        "max_severity": max_sev,
        "evidence_types": ev_types,
        "limitation_count": len(limitations),
        "seconds": elapsed,
    }


def run_smoke_csv(
    in_csv: Path,
    out_csv: Path,
    client: NpmRegistryClient,
    policy,
) -> None:
    rows = list(csv.DictReader(open(in_csv, encoding="utf-8")))
    fieldnames = [
        "package", "old", "new", "published_new", "decision",
        "max_severity", "evidence_types", "limitation_count", "seconds"
    ]
    out_rows = []
    print(f"Processing {len(rows)} pairs from {in_csv} -> {out_csv}...")
    for idx, r in enumerate(rows, 1):
        pkg = r["package"]
        old_ver = r["old"]
        new_ver = r["new"]
        pub_str = r.get("published_new")
        if pub_str:
            as_of = datetime.fromisoformat(pub_str.replace("Z", "+00:00")).astimezone(UTC)
        else:
            as_of = datetime.now(tz=UTC)

        res = evaluate_pair(client, pkg, old_ver, new_ver, as_of, policy)
        out_r = {
            "package": pkg,
            "old": old_ver,
            "new": new_ver,
            "published_new": r.get("published_new", as_of.isoformat()),
            "decision": res["decision"],
            "max_severity": res["max_severity"],
            "evidence_types": ";".join(res["evidence_types"]),
            "limitation_count": res["limitation_count"],
            "seconds": res["seconds"],
        }
        out_rows.append(out_r)
        if idx % 20 == 0:
            print(f"  [{idx}/{len(rows)}] processed...")

    with open(out_csv, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(out_rows)
    print(f"Saved {len(out_rows)} rows to {out_csv}")


def run_matched_negatives(
    in_jsonl: Path,
    out_jsonl: Path,
    client: NpmRegistryClient,
    policy,
) -> None:
    rows = [json.loads(line) for line in open(in_jsonl, encoding="utf-8")]
    out_rows = []
    print(f"Processing {len(rows)} pairs from {in_jsonl} -> {out_jsonl}...")
    for idx, r in enumerate(rows, 1):
        pkg = r["package"]
        old_ver = r["old_version"]
        new_ver = r["new_version"]
        as_of = datetime.now(tz=UTC)

        res = evaluate_pair(client, pkg, old_ver, new_ver, as_of, policy)
        out_r = {
            "package": pkg,
            "old_version": old_ver,
            "new_version": new_ver,
            "cluster_id": r.get("cluster_id", f"cluster_{idx:04d}"),
            "status": "ok",
            "decision": res["decision"],
            "max_severity": res["max_severity"],
            "evidence_types": res["evidence_types"],
            "limitation_count": res["limitation_count"],
            "seconds": res["seconds"],
        }
        out_rows.append(out_r)
        if idx % 100 == 0 or idx == len(rows):
            print(f"  [{idx}/{len(rows)}] processed...")

    with open(out_jsonl, "w", encoding="utf-8") as f:
        for r in out_rows:
            f.write(json.dumps(r) + "\n")
    print(f"Saved {len(out_rows)} rows to {out_jsonl}")


def main() -> None:
    policy = load_policy()
    client = NpmRegistryClient(cache_dir=CACHE_DIR)
    try:
        run_smoke_csv(
            Path("data/smoke_results_v8.csv"),
            Path("data/smoke_results_v9.csv"),
            client,
            policy,
        )
        run_smoke_csv(
            Path("data/smoke_validation_v8.csv"),
            Path("data/smoke_validation_v9.csv"),
            client,
            policy,
        )
        run_matched_negatives(
            Path("data/matched_negatives_results_v8.jsonl"),
            Path("data/matched_negatives_results_v9.jsonl"),
            client,
            policy,
        )
    finally:
        client.close()


if __name__ == "__main__":
    main()
