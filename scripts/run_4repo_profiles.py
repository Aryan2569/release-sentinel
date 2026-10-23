"""Run 4-repo replay evaluation for both default and strict profiles."""

import json
import logging
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, ".")

from scripts.replay_repo import (
    DEFAULT_REPOS,
    ensure_repo_cloned,
    get_lockfile_commits,
    read_lockfile_at_commit,
)

from release_sentinel.lockfile import DEFAULT_CACHE_DIR, scan_lockfile_diff
from release_sentinel.policy import load_policy

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("replay_profiles")


def evaluate_repos(profile: str):
    policy = load_policy(profile=profile)
    logger.info("==================================================")
    logger.info("Evaluating 4 repos under profile: %s", profile)
    logger.info("==================================================")

    total_updates = 0
    total_pkgs = 0
    total_allow = 0
    total_warn = 0
    total_block = 0
    all_blocks = []
    all_warns = []
    t_start = time.perf_counter()

    for repo_cfg in DEFAULT_REPOS:
        repo_name = repo_cfg["name"]
        repo_url = repo_cfg["url"]
        lockfile = repo_cfg["lockfile"]
        depth = repo_cfg["depth"]

        repo_dir = ensure_repo_cloned(repo_url, repo_name, depth=depth)
        commits = get_lockfile_commits(repo_dir, lockfile, max_commits=30)
        cache_file = Path("data") / f"replay_cache_{profile}_{repo_name}.json"

        results = []
        completed = {}
        if cache_file.exists():
            try:
                cdata = json.loads(cache_file.read_text(encoding="utf-8"))
                for r in cdata.get("results", []):
                    completed[r["pair_key"]] = r
            except Exception:
                pass

        logger.info("Repo %s: %d commits, %d cached", repo_name, len(commits), len(completed))

        for idx in range(1, len(commits)):
            base_commit = commits[idx - 1]
            head_commit = commits[idx]
            pair_key = f"{base_commit['sha'][:8]}..{head_commit['sha'][:8]}"

            if pair_key in completed:
                update_res = completed[pair_key]
            else:
                t0 = time.perf_counter()
                try:
                    base_json = read_lockfile_at_commit(repo_dir, base_commit["sha"], lockfile)
                    head_json = read_lockfile_at_commit(repo_dir, head_commit["sha"], lockfile)

                    report = scan_lockfile_diff(
                        base_content=base_json,
                        head_content=head_json,
                        base_source=base_commit["sha"][:8],
                        head_source=head_commit["sha"][:8],
                        policy=policy,
                        max_packages=200,
                        cache_dir=DEFAULT_CACHE_DIR,
                        as_of=datetime.now(UTC),
                    )
                    elapsed = time.perf_counter() - t0

                    update_res = {
                        "pair_key": pair_key,
                        "base_sha": base_commit["sha"],
                        "head_sha": head_commit["sha"],
                        "date": head_commit["date"],
                        "subject": head_commit["subject"],
                        "packages_scanned": report.total_packages_scanned,
                        "decision": report.decision.name,
                        "evidence": [ev for pkg in report.package_results for ev in pkg.get("evidence", [])],
                        "blocks": [
                            {
                                "package": pkg["package"],
                                "old_version": pkg.get("old_version"),
                                "version": pkg["new_version"],
                                "evidence": pkg["evidence"],
                                "details": pkg.get("evidence_details", []),
                            }
                            for pkg in report.package_results
                            if pkg["decision"] == "BLOCK"
                        ],
                        "warns": [
                            {
                                "package": pkg["package"],
                                "old_version": pkg.get("old_version"),
                                "version": pkg["new_version"],
                                "evidence": pkg["evidence"],
                                "details": pkg.get("evidence_details", []),
                            }
                            for pkg in report.package_results
                            if pkg["decision"] == "WARN"
                        ],
                        "elapsed_sec": round(elapsed, 3),
                    }
                except Exception as exc:
                    elapsed = time.perf_counter() - t0
                    logger.warning("Error replaying %s on %s: %s", pair_key, repo_name, exc)
                    update_res = {
                        "pair_key": pair_key,
                        "base_sha": base_commit["sha"],
                        "head_sha": head_commit["sha"],
                        "date": head_commit["date"],
                        "subject": head_commit["subject"],
                        "packages_scanned": 0,
                        "decision": "WARN",
                        "evidence": ["replay_error"],
                        "blocks": [],
                        "warns": [],
                        "elapsed_sec": round(elapsed, 3),
                    }

            results.append(update_res)
            total_updates += 1
            total_pkgs += update_res["packages_scanned"]
            d = update_res["decision"]
            if d == "BLOCK":
                total_block += 1
                all_blocks.extend(update_res["blocks"])
            elif d == "WARN":
                total_warn += 1
                all_warns.extend(update_res.get("warns", []))
            else:
                total_allow += 1

        # Save cache
        cache_file.write_text(json.dumps({"repo": repo_name, "profile": profile, "results": results}, indent=2), encoding="utf-8")
        logger.info("Saved %s cache with %d results", cache_file, len(results))

    total_time = round(time.perf_counter() - t_start, 2)
    logger.info("Profile %s Complete: %d updates, %d pkgs scanned in %.2fs", profile, total_updates, total_pkgs, total_time)
    logger.info("Decisions: %d ALLOW (%.1f%%), %d WARN (%.1f%%), %d BLOCK (%.1f%%)",
                total_allow, total_allow/total_updates*100,
                total_warn, total_warn/total_updates*100,
                total_block, total_block/total_updates*100)
    logger.info("Total blocked package instances: %d", len(all_blocks))
    return {
        "profile": profile,
        "total_updates": total_updates,
        "total_pkgs": total_pkgs,
        "allow": total_allow,
        "warn": total_warn,
        "block": total_block,
        "blocks": all_blocks,
        "warns": all_warns,
    }

if __name__ == "__main__":
    strict_res = evaluate_repos("strict")
    default_res = evaluate_repos("default")
