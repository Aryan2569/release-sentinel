"""Dependency resolver for Release Sentinel (Stage 5a).

Resolves newly added dependencies as of an as_of cut-off timestamp:
- Live resolver: queries npm registry metadata, matches the highest version satisfying
  the declared semver range published on or before as_of (using node-semver), fetches
  the tarball, and analyzes it in full-scan mode.
- Replay resolver: in evaluation mode, if the live registry no longer serves the package
  (e.g. removed or unpublished), searches Datadog encrypted samples, extracts in memory,
  runs full-scan mode, and marks evidence as `replayed_from_dataset`.
- If unresolvable, emits an `unresolvable_dependency` evidence item (INFO severity) so it
  does not count as a detection.
"""

from __future__ import annotations

import logging
import re
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from functools import cmp_to_key
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx
import nodesemver

from release_sentinel.extractor import ExtractionConfig, extract_release_in_memory
from release_sentinel.models import Evidence, Severity
from release_sentinel.registry import (
    IntegrityError,
    NpmRegistryClient,
    RegistryError,
    VersionNotFoundError,
    _parse_npm_time,
)
from release_sentinel.zip_loader import load_zip_release

if TYPE_CHECKING:
    from release_sentinel.policy import Policy

logger = logging.getLogger(__name__)


def _semver_cmp(a: str, b: str) -> int:
    try:
        return int(nodesemver.compare(a, b, loose=True))
    except Exception:
        return (a > b) - (a < b)


def _valid_semver(v: str) -> bool:
    try:
        return bool(nodesemver.valid(v, loose=True))
    except Exception:
        return False


def _parse_semver(v: str) -> object:
    try:
        return nodesemver.parse(v, loose=True)
    except Exception:
        return None


def select_baseline_for_added_package(
    name: str,
    new_version: str,
    metadata: dict[str, Any],
    as_of: datetime,
) -> str | None:
    """Select baseline version for an added package under the maturity rule (Stage 7a Part 0b).

    (i) Maturity rule: The package must have been first published at least 90 days
        before `as_of` AND have at least 5 published versions on or before `as_of`.
        If not satisfied, diff mode is not allowed (returns None -> full-scan).
    (ii) Baseline selection: Picks the previous version in the SAME major line
        (highest lower semver published before `new_version`), falling back to
        previous-by-publish-time across all versions only if none exists in the same major.
    """
    if as_of.tzinfo is None:
        as_of = as_of.replace(tzinfo=UTC)

    time_map = {
        k: v
        for k, v in metadata.get("time", {}).items()
        if k not in ("created", "modified")
    }

    # (i) Check maturity rule
    created_str = metadata.get("time", {}).get("created")
    if not created_str and time_map:
        created_str = min(time_map.values())

    if not created_str:
        return None

    try:
        created_dt = _parse_npm_time(created_str)
        is_old_enough = (as_of - created_dt).total_seconds() >= 90 * 86400
    except Exception:
        return None

    if not is_old_enough:
        return None

    versions_dict = metadata.get("versions", {})
    available_versions = list(versions_dict.keys()) if versions_dict else list(time_map.keys())
    if len(available_versions) < 5:
        return None

    # (ii) Baseline selection for new_version
    target_time = time_map.get(new_version, "")

    earlier_versions: list[str] = []
    for v in available_versions:
        if v == new_version:
            continue
        v_time = time_map.get(v, "")
        if target_time and v_time:
            if v_time < target_time:
                earlier_versions.append(v)
        elif (
            not target_time
            and _valid_semver(v)
            and _valid_semver(new_version)
        ):
            if nodesemver.lt(v, new_version, loose=True):
                earlier_versions.append(v)
        else:
            if _valid_semver(v) and _valid_semver(new_version):
                if nodesemver.lt(v, new_version, loose=True):
                    earlier_versions.append(v)

    if not earlier_versions:
        return None

    # Try same major line first: highest lower semver published before new_version
    if _valid_semver(new_version):
        target_sem = _parse_semver(new_version)
        if target_sem is not None:
            target_major = target_sem.major
            same_major_candidates = [
                v
                for v in earlier_versions
                if _valid_semver(v)
                and _parse_semver(v) is not None
                and _parse_semver(v).major == target_major
                and nodesemver.lt(v, new_version, loose=True)
            ]
            if same_major_candidates:
                return max(
                    same_major_candidates,
                    key=cmp_to_key(_semver_cmp),
                )

    # Fallback to previous-by-publish-time
    if target_time:
        candidates_with_time = [v for v in earlier_versions if time_map.get(v)]
        if candidates_with_time:
            return max(candidates_with_time, key=lambda v: time_map.get(v, ""))

    valid_earlier = [v for v in earlier_versions if _valid_semver(v)]
    if valid_earlier:
        return max(valid_earlier, key=cmp_to_key(_semver_cmp))

    return max(earlier_versions)


def resolve_highest_version(
    versions: list[str],
    spec: str,
) -> str | None:
    """Return the highest version from *versions* satisfying *spec*.

    Uses node-semver for full npm range compatibility.
    Handles 'latest', '*', or empty strings cleanly.
    """
    valid_versions = [v for v in versions if nodesemver.valid(v, loose=True)]
    if not valid_versions:
        return None

    clean_spec = spec.strip()
    if not clean_spec or clean_spec in ("latest", "*"):
        clean_spec = "*"

    try:
        match = nodesemver.max_satisfying(valid_versions, clean_spec, loose=True)
        if match:
            return str(match)
    except Exception as exc:
        logger.debug("nodesemver.max_satisfying error for spec %r: %s", spec, exc)

    # Fallback if range parsing fails: check for exact match
    if clean_spec in valid_versions:
        return clean_spec

    return None


def resolve_added_dependency(
    name: str,
    spec: str,
    as_of: datetime,
    registry_client: NpmRegistryClient,
    dest_dir: Path,
    samples_root: Path | None = None,
    config: ExtractionConfig | None = None,
    policy: Policy | None = None,
    analyze_fn: Callable[..., list[Evidence]] | None = None,
    mode: str = "live",
) -> tuple[str | None, list[Evidence], str]:
    """Resolve an added dependency and analyze it in full-scan mode.

    Parameters
    ----------
    name:
        Dependency package name (e.g. "bun" or "@nx/key").
    spec:
        Declared semver range string (e.g. "^1.3.13" or "4.2.1").
    as_of:
        Time cut-off timestamp.
    registry_client:
        NpmRegistryClient instance.
    dest_dir:
        Directory for storing downloaded dependency tarballs.
    samples_root:
        Optional path to local Datadog repository for replay resolution.
    config:
        Optional extraction caps and limits.
    policy:
        Optional detection policy.
    analyze_fn:
        Callable for full-scan analysis (e.g. `analyze_release`).

    Returns
    -------
    tuple[str | None, list[Evidence], str]
        (resolved_version, evidence_list, status)
        status is one of: "live", "replayed", "unresolvable"
    """
    if as_of.tzinfo is None:
        as_of = as_of.replace(tzinfo=UTC)

    # 1. Try Live Registry
    last_err_cls = "UnknownError"
    last_err_msg = ""
    try:
        meta = registry_client.get_metadata(name, as_of=as_of)
        versions_dict = meta.get("versions", {})
        available_versions = list(versions_dict.keys())
        target_version = resolve_highest_version(available_versions, spec)

        if target_version:
            logger.debug("Resolved %s@%s via live registry", name, target_version)
            tarball_path = registry_client.download_tarball(
                name=name,
                version=target_version,
                as_of=as_of,
                dest_dir=dest_dir,
            )
            dep_release = extract_release_in_memory(tarball_path, config=config)

            # Diff-mode eligibility (Stage 7a Part 0b):
            # Apply shared maturity rule and same-major baseline selection
            baseline_dep_release = None
            prev_version = select_baseline_for_added_package(name, target_version, meta, as_of)

            if prev_version:
                try:
                    prev_tarball = registry_client.download_tarball(
                        name=name,
                        version=prev_version,
                        as_of=as_of,
                        dest_dir=dest_dir,
                    )
                    baseline_dep_release = extract_release_in_memory(
                        prev_tarball, config=config
                    )
                    logger.debug(
                        "Analyzing added dependency %s in DIFF mode against %s",
                        name,
                        prev_version,
                    )
                except Exception as exc:
                    logger.debug(
                        "Failed to fetch baseline %s@%s for diff mode: %s; "
                        "falling back to full-scan",
                        name,
                        prev_version,
                        exc,
                    )
                    baseline_dep_release = None
            else:
                logger.debug(
                    "Added dependency %s not eligible for diff mode; running full-scan",
                    name,
                )

            # Analyze dependency: diff mode if baseline exists, full-scan if brand new
            # Pass registry_client=None to keep depth-1
            if analyze_fn is not None:
                evidence = analyze_fn(
                    new=dep_release,
                    baseline=baseline_dep_release,
                    policy=policy,
                    config=config,
                    as_of=as_of,
                    registry_client=None,
                )
            else:
                evidence = []
            labeled_evidence = _label_evidence(evidence, name, target_version, replayed=False)
            return target_version, labeled_evidence, "live"

    except (
        httpx.HTTPError,
        RegistryError,
        VersionNotFoundError,
        IntegrityError,
        ValueError,
        Exception,
    ) as exc:
        last_err_cls = exc.__class__.__name__
        last_err_msg = str(exc)
        logger.warning(
            "Live resolution failed for %s@%s [%s]: %s",
            name, spec, last_err_cls, last_err_msg
        )

    # 2. Try REPLAY Resolver in evaluation mode
    if samples_root is not None and samples_root.exists():
        replayed_res = _try_replay_resolver(
            name=name,
            spec=spec,
            samples_root=samples_root,
            config=config,
            policy=policy,
            analyze_fn=analyze_fn,
        )
        if replayed_res is not None:
            ver, ev = replayed_res
            return ver, ev, "replayed"

    # 3. Unresolvable (Fail-closed: MEDIUM in live mode, INFO in eval mode)
    sev = Severity.INFO if mode == "eval" else Severity.MEDIUM
    err_desc = f" [{last_err_cls}: {last_err_msg}]" if last_err_msg else ""
    unres_ev = Evidence(
        id="unresolvable_dependency",
        severity=sev,
        file=None,
        explanation=(
            f"Added dependency '{name}@{spec}' could not be resolved or analyzed from npm registry "
            f"or dataset as of {as_of.isoformat()}{err_desc}."
        ),
        legitimate_use_note=(
            "Private packages, unpublished packages, or registry network errors can "
            "prevent dependency retrieval."
        ),
    )
    return None, [unres_ev], "unresolvable"


def _label_evidence(
    evidence: list[Evidence],
    dep_name: str,
    version: str,
    replayed: bool = False,
) -> list[Evidence]:
    """Prefix evidence explanation and file path with dependency context."""
    tag = f"[dep: {dep_name}@{version}{' replayed_from_dataset' if replayed else ''}]"
    labeled: list[Evidence] = []
    for ev in evidence:
        new_file = f"node_modules/{dep_name}/{ev.file}" if ev.file else f"node_modules/{dep_name}"
        new_expl = f"{tag} {ev.explanation}"
        labeled.append(
            ev.model_copy(
                update={
                    "file": new_file,
                    "explanation": new_expl,
                }
            )
        )
    return labeled


def _try_replay_resolver(
    name: str,
    spec: str,
    samples_root: Path,
    config: ExtractionConfig | None,
    policy: Policy | None,
    analyze_fn: Callable[..., list[Evidence]] | None,
) -> tuple[str, list[Evidence]] | None:
    """Search Datadog npm samples for a matching encrypted zip release in memory."""
    safe_name = name.replace("/", "@")
    raw_name = name

    # Possible candidate paths under samples/npm/
    categories = ("malicious_intent", "compromised_lib")

    for cat in categories:
        for folder_candidate in (safe_name, raw_name):
            rel_folder = f"samples/npm/{cat}/{folder_candidate}"
            folder_path = samples_root / "samples" / "npm" / cat / folder_candidate

            # If folder doesn't exist on disk, attempt git sparse-checkout add
            if not folder_path.exists():
                try:
                    import shutil

                    git_bin = shutil.which("git") or "git"
                    subprocess.run(  # noqa: S603
                        [git_bin, "sparse-checkout", "add", rel_folder],
                        cwd=samples_root,
                        capture_output=True,
                        check=False,
                        timeout=15,
                    )
                except Exception as exc:
                    logger.debug("git sparse-checkout add failed: %s", exc)

            if folder_path.exists():
                zips = list(folder_path.glob("**/*.zip"))
                if not zips:
                    continue

                # Match version against spec
                zip_versions: dict[str, Path] = {}
                for zp in zips:
                    m = re.search(r"-v([0-9a-zA-Z._-]+)\.zip$", zp.name)
                    if m:
                        zip_versions[m.group(1)] = zp
                    else:
                        # Try parent directory name if named like a version
                        parent_ver = zp.parent.name
                        if nodesemver.valid(parent_ver, loose=True):
                            zip_versions[parent_ver] = zp

                matched_ver = resolve_highest_version(list(zip_versions.keys()), spec)
                target_zip: Path | None = None
                if matched_ver and matched_ver in zip_versions:
                    target_zip = zip_versions[matched_ver]
                elif zips:
                    # If semver matching yields none, take the single zip available
                    target_zip = zips[0]
                    matched_ver = matched_ver or "unknown"

                if target_zip and target_zip.exists():
                    logger.info(
                        "REPLAY resolver matched %s@%s to %s",
                        name,
                        matched_ver,
                        target_zip,
                    )
                    dep_release = load_zip_release(
                        target_zip,
                        password=b"infected",
                        config=config,
                    )
                    evidence = analyze_fn(
                        dep_release,
                        baseline=None,
                        policy=policy,
                        config=config,
                    )
                    labeled = _label_evidence(
                        evidence,
                        name,
                        matched_ver or "dataset",
                        replayed=True,
                    )
                    return matched_ver or "dataset", labeled

    return None
