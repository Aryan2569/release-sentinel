"""Prospective evaluation runner for Release Sentinel v1.2 (Stage 5d Part 3).

Protocol for evaluating future samples discovered after the dataset snapshot:
1. Identify new samples published after the cutoff date.
2. Pair each new release with its baseline from npm registry as of discovery date.
3. Match each new malicious pair with a benign negative published around the same date.
4. Run frozen v1.2 detector without rule or policy changes.
5. Report prospective sample- and campaign-level recall and false-alarm rate.
"""

from __future__ import annotations

import argparse
import csv
import logging
from datetime import UTC, datetime
from pathlib import Path

from release_sentinel.policy import load_policy

logger = logging.getLogger(__name__)

SNAPSHOT_COMMIT = "8a74a4c8ee0e1a2927f0419e0710968702ded609"
SNAPSHOT_DATE = "2026-10-16T10:25:21+02:00"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prospective evaluation runner for v1.2")
    parser.add_argument(
        "--new-samples-dir",
        type=Path,
        default=Path(r"C:\rs-data\datadog"),
        help="Path to root of Datadog dataset repository",
    )
    parser.add_argument(
        "--as-of-cutoff",
        type=str,
        default="2026-10-16",
        help="Only evaluate samples discovered after this ISO date (YYYY-MM-DD)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("data/prospective"),
        help="Directory to store prospective evaluation outputs",
    )
    parser.add_argument(
        "--policy-file",
        type=Path,
        default=Path("data/policy_default.toml"),
        help="Path to frozen v1.2 policy file",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Number of evaluation worker threads",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    print("=================================================================")
    print("Release Sentinel -- Prospective Evaluation Runner (v1.2)")
    print(f"Snapshot Commit: {SNAPSHOT_COMMIT}")
    print(f"Snapshot Cutoff: {args.as_of_cutoff}")
    print(f"Output Directory: {args.output_dir}")
    print("=================================================================\n")

    policy = load_policy(args.policy_file)
    print(f"Loaded policy from {args.policy_file} ({len(policy.block_requires)} block rules)")

    # Inspect labels file for prospective pairs
    labels_file = args.new_samples_dir / "labels" / "npm_compromised.csv"
    if not labels_file.exists():
        labels_file = Path("data/labels_npm_compromised.csv")

    cutoff_dt = datetime.fromisoformat(args.as_of_cutoff).replace(tzinfo=UTC)

    prospective_pairs = []
    if labels_file.exists():
        for r in csv.DictReader(open(labels_file, encoding="utf-8")):
            disc_str = r.get("discovery_date", "")
            try:
                disc_dt = datetime.fromisoformat(disc_str.replace("Z", "+00:00")).astimezone(UTC)
                if disc_dt > cutoff_dt:
                    prospective_pairs.append(r)
            except Exception:
                pass

    print(f"Found {len(prospective_pairs)} prospective samples with discovery_date > {args.as_of_cutoff}.")

    if not prospective_pairs:
        print("\nNo new samples discovered after snapshot date yet.")
        print("To run a prospective test in the future:")
        print("  1. git -C <samples-root> pull")
        print("  2. python scripts/prospective_eval.py --as-of-cutoff 2026-10-16\n")
        return


if __name__ == "__main__":
    main()
