"""12-Repository Replay Script across default and strict profiles (Stage 6b Part 6).

Replays historical lockfile updates across 12 popular open-source repositories
under both `default` and `strict` profiles, measuring alert burden, false-BLOCK rate,
and top evidence IDs.
"""

from __future__ import annotations

import collections
import json
import logging
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, '.')
from scripts.replay_repo import ensure_repo_cloned, get_lockfile_commits, read_lockfile_at_commit

from release_sentinel.lockfile import DEFAULT_CACHE_DIR, scan_lockfile_diff
from release_sentinel.policy import load_policy

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("replay_12repos")

REPOS_12 = [
    {"name": "superagent", "url": "https://github.com/ladjs/superagent.git", "lockfile": "package-lock.json", "depth": 300},
    {"name": "socket.io", "url": "https://github.com/socketio/socket.io.git", "lockfile": "package-lock.json", "depth": 400},
    {"name": "mocha", "url": "https://github.com/mochajs/mocha.git", "lockfile": "package-lock.json", "depth": 300},
    {"name": "bootstrap", "url": "https://github.com/twbs/bootstrap.git", "lockfile": "package-lock.json", "depth": 300},
    {"name": "commander", "url": "https://github.com/tj/commander.js.git", "lockfile": "package-lock.json", "depth": 400},
    {"name": "helmet", "url": "https://github.com/helmetjs/helmet.git", "lockfile": "package-lock.json", "depth": 400},
    {"name": "winston", "url": "https://github.com/winstonjs/winston.git", "lockfile": "package-lock.json", "depth": 400},
    {"name": "marked", "url": "https://github.com/markedjs/marked.git", "lockfile": "package-lock.json", "depth": 400},
    {"name": "nodemon", "url": "https://github.com/remy/nodemon.git", "lockfile": "package-lock.json", "depth": 400},
    {"name": "rimraf", "url": "https://github.com/isaacs/rimraf.git", "lockfile": "package-lock.json", "depth": 400},
    {"name": "glob", "url": "https://github.com/isaacs/node-glob.git", "lockfile": "package-lock.json", "depth": 400},
    {"name": "terser", "url": "https://github.com/terser/terser.git", "lockfile": "package-lock.json", "depth": 400},
]


def run_replay_for_profile(profile: str, max_commits_per_repo: int = 25) -> dict[str, Any]:
    policy = load_policy(profile=profile)
    logger.info("==================================================")
    logger.info("Running 12-Repo Replay under profile: %s", profile)
    logger.info("==================================================")

    total_updates = 0
    total_pkgs = 0
    total_allow = 0
    total_warn = 0
    total_block = 0
    repo_summaries = []
    evidence_counter: collections.Counter[str] = collections.Counter()
    all_blocks = []
    all_updates = []
    skipped_updates = []
    t_start = time.perf_counter()

    for repo_cfg in REPOS_12:
        repo_name = repo_cfg["name"]
        repo_url = repo_cfg["url"]
        lockfile = repo_cfg["lockfile"]
        depth = repo_cfg["depth"]

        repo_dir = ensure_repo_cloned(repo_url, repo_name, depth=depth)
        commits = get_lockfile_commits(repo_dir, lockfile, max_commits=max_commits_per_repo)
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

        logger.info("Repo %s: %d commits found, %d cached", repo_name, len(commits), len(completed))

        repo_allow = 0
        repo_warn = 0
        repo_block = 0
        repo_pkgs = 0
        repo_time = 0.0

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

                    ev_ids = [ev for pkg in report.package_results for ev in pkg.get("evidence", [])]
                    update_res = {
                        "pair_key": pair_key,
                        "base_sha": base_commit["sha"],
                        "head_sha": head_commit["sha"],
                        "date": head_commit["date"],
                        "subject": head_commit["subject"],
                        "packages_scanned": report.total_packages_scanned,
                        "decision": report.decision.name,
                        "evidence": ev_ids,
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
                    logger.warning(
                        "Skipped update %s on %s (lockfile git-show failure): %s",
                        pair_key,
                        repo_name,
                        exc,
                    )
                    update_res = {
                        "pair_key": pair_key,
                        "base_sha": base_commit["sha"],
                        "head_sha": head_commit["sha"],
                        "date": head_commit["date"],
                        "subject": head_commit["subject"],
                        "packages_scanned": 0,
                        "decision": "WARN",
                        "evidence": ["replay_error"],
                        "skipped": True,
                        "skip_reason": f"lockfile not present in commit: {exc}",
                        "blocks": [],
                        "warns": [],
                        "elapsed_sec": round(elapsed, 3),
                    }

            results.append(update_res)
            d = update_res["decision"]
            repo_pkgs += update_res["packages_scanned"]
            repo_time += update_res.get("elapsed_sec", 0.0)
            if d == "BLOCK":
                repo_block += 1
                all_blocks.extend(update_res["blocks"])
            elif d == "WARN":
                repo_warn += 1
            else:
                repo_allow += 1

            if update_res.get("skipped"):
                skipped_updates.append({
                    "repo": repo_name,
                    "pair_key": pair_key,
                    "base_sha": update_res["base_sha"],
                    "head_sha": update_res["head_sha"],
                    "reason": update_res.get("skip_reason", "lockfile not present in commit"),
                })

            all_updates.append({
                "repo": repo_name,
                "pair_key": pair_key,
                "base_sha": update_res["base_sha"],
                "head_sha": update_res["head_sha"],
                "decision": d,
                "evidence": update_res.get("evidence", []),
                "skipped": update_res.get("skipped", False),
            })

            for ev in update_res.get("evidence", []):
                evidence_counter[ev] += 1

        total_updates += len(results)
        total_pkgs += repo_pkgs
        total_allow += repo_allow
        total_warn += repo_warn
        total_block += repo_block

        cache_file.write_text(json.dumps({"repo": repo_name, "profile": profile, "results": results}, indent=2), encoding="utf-8")
        logger.info("Saved %s cache with %d results", cache_file, len(results))

        n_up = len(results) if results else 1
        repo_summaries.append({
            "repo": repo_name,
            "updates": len(results),
            "packages_scanned": repo_pkgs,
            "allow": repo_allow,
            "allow_pct": round(repo_allow / n_up * 100, 1),
            "warn": repo_warn,
            "warn_pct": round(repo_warn / n_up * 100, 1),
            "block": repo_block,
            "block_pct": round(repo_block / n_up * 100, 1),
            "avg_time": round(repo_time / n_up, 2),
        })

    total_time = round(time.perf_counter() - t_start, 2)
    logger.info("Profile %s Complete: %d updates, %d pkgs scanned in %.2fs", profile, total_updates, total_pkgs, total_time)
    logger.info(
        "Decisions: %d ALLOW (%.1f%%), %d WARN (%.1f%%), %d BLOCK (%.1f%%)",
        total_allow, total_allow / total_updates * 100 if total_updates else 0,
        total_warn, total_warn / total_updates * 100 if total_updates else 0,
        total_block, total_block / total_updates * 100 if total_updates else 0,
    )
    logger.info("Total blocked package instances: %d", len(all_blocks))
    logger.info("Top 10 evidence IDs among alerts: %s", evidence_counter.most_common(10))

    return {
        "profile": profile,
        "total_updates": total_updates,
        "total_pkgs": total_pkgs,
        "allow": total_allow,
        "warn": total_warn,
        "block": total_block,
        "blocked_instances": len(all_blocks),
        "total_time_sec": total_time,
        "repo_summaries": repo_summaries,
        "top_evidence": evidence_counter.most_common(15),
        "skipped_updates": skipped_updates,
        "updates": all_updates,
    }


def main():
    res_strict = run_replay_for_profile("strict", max_commits_per_repo=25)
    res_default = run_replay_for_profile("default", max_commits_per_repo=25)

    out_file = Path("data/replay_12repos_summary.json")
    out_file.write_text(json.dumps({"strict": res_strict, "default": res_default}, indent=2), encoding="utf-8")
    logger.info("Saved 12-repo replay summary to %s", out_file)


if __name__ == "__main__":
    main()
