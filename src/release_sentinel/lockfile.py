"""npm lockfile parser and differ for Release Sentinel.

Supports npm package-lock.json v1, v2, and v3.
Detects yarn.lock and pnpm-lock.yaml and raises UnsupportedLockfileError with clear messaging.

Rules enforced:
- Rule 1: Never execute downloaded package code.
- Rule 2: Safe in-memory tarball extraction.
- Rule 5: Writes only inside designated cache and project directory.
"""

from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import nodesemver

from release_sentinel.differ import analyze_release
from release_sentinel.engine import decide
from release_sentinel.extractor import ExtractionConfig, extract_release_in_memory
from release_sentinel.models import Decision, Severity
from release_sentinel.policy import Policy, load_policy
from release_sentinel.registry import (
    IntegrityError,
    NpmRegistryClient,
    verify_integrity,
)

logger = logging.getLogger(__name__)

DEFAULT_MAX_PACKAGES = 200
DEFAULT_CACHE_DIR = Path.home() / ".cache" / "release_sentinel"


class LockfileError(Exception):
    """Base error for lockfile operations."""


class UnsupportedLockfileError(LockfileError):
    """Raised when an unsupported lockfile format (yarn, pnpm) is provided."""


class LockfileParseError(LockfileError):
    """Raised when a lockfile cannot be parsed as valid JSON."""


class LockfileBudgetExceededError(LockfileError):
    """Raised when changed packages exceed the safety budget."""


@dataclass(frozen=True)
class LockfilePackage:
    """A package entry recorded in a lockfile."""

    name: str
    version: str
    resolved: str | None = None
    integrity: str | None = None


@dataclass(frozen=True)
class PackageChange:
    """A detected difference between two lockfiles for a package."""

    name: str
    old_version: str | None  # None if ADDED
    new_version: str | None  # None if REMOVED
    change_type: str  # 'added', 'upgraded', 'downgraded', 'removed'
    resolved: str | None = None
    integrity: str | None = None


@dataclass
class LockfileDiffReport:
    """Complete results of analyzing a lockfile diff."""

    base_source: str
    head_source: str
    total_packages_scanned: int
    decision: Decision
    package_results: list[dict[str, Any]]
    limitations: list[str]
    has_budget_exceeded: bool = False


def check_supported_lockfile_path(path: str | Path) -> None:
    """Verify that the given path is not a yarn or pnpm lockfile."""
    p_str = str(path).replace("\\", "/").lower()
    if p_str.endswith("yarn.lock"):
        raise UnsupportedLockfileError(
            "Yarn lockfile (yarn.lock) is not supported in this version. "
            "Release Sentinel currently supports npm package-lock.json (v1, v2, v3)."
        )
    if p_str.endswith("pnpm-lock.yaml") or p_str.endswith("pnpm-lock.yml"):
        raise UnsupportedLockfileError(
            "pnpm lockfile (pnpm-lock.yaml) is not supported in this version. "
            "Release Sentinel currently supports npm package-lock.json (v1, v2, v3)."
        )


def _extract_pkg_name_from_path(pkg_path: str) -> str | None:
    """Extract package name from node_modules key in lockfile v2/v3.

    Examples:
      'node_modules/lodash' -> 'lodash'
      'node_modules/@types/node' -> '@types/node'
      'node_modules/foo/node_modules/bar' -> 'bar'
    """
    if not pkg_path:
        return None  # Root package

    parts = pkg_path.replace("\\", "/").split("node_modules/")
    if len(parts) < 2 or not parts[-1]:
        return None

    candidate = parts[-1].rstrip("/")
    return candidate if candidate else None


def _walk_v1_dependencies(
    deps_dict: dict[str, Any],
    out: dict[str, LockfilePackage],
) -> None:
    """Recursively collect packages from a v1 dependencies tree."""
    for name, data in deps_dict.items():
        if not isinstance(data, dict):
            continue
        version = data.get("version")
        if version and isinstance(version, str):
            resolved = data.get("resolved")
            integrity = data.get("integrity")
            # Prefer top-level or first encountered
            if name not in out:
                out[name] = LockfilePackage(
                    name=name,
                    version=version,
                    resolved=resolved if isinstance(resolved, str) else None,
                    integrity=integrity if isinstance(integrity, str) else None,
                )
        nested = data.get("dependencies")
        if isinstance(nested, dict):
            _walk_v1_dependencies(nested, out)


def parse_lockfile_content(
    content: str | bytes,
    filename: str = "package-lock.json",
) -> dict[str, LockfilePackage]:
    """Parse a package-lock.json content into a dictionary of package name -> LockfilePackage."""
    check_supported_lockfile_path(filename)

    if isinstance(content, bytes):
        content = content.decode("utf-8", errors="replace")

    try:
        data = json.loads(content)
    except Exception as exc:
        raise LockfileParseError(f"Failed to parse lockfile JSON ({filename}): {exc}") from exc

    if not isinstance(data, dict):
        raise LockfileParseError(f"Lockfile root must be a JSON object ({filename})")

    packages: dict[str, LockfilePackage] = {}

    # v2 and v3 have 'packages'
    if "packages" in data and isinstance(data["packages"], dict):
        for pkg_key, pkg_info in data["packages"].items():
            if not isinstance(pkg_info, dict):
                continue
            if not pkg_key:  # Skip root package
                continue
            name = pkg_info.get("name")
            if not name:
                name = _extract_pkg_name_from_path(pkg_key)
            if not name:
                continue

            version = pkg_info.get("version")
            if not version or not isinstance(version, str):
                continue

            resolved = pkg_info.get("resolved")
            integrity = pkg_info.get("integrity")

            if name not in packages:
                packages[name] = LockfilePackage(
                    name=name,
                    version=version,
                    resolved=resolved if isinstance(resolved, str) else None,
                    integrity=integrity if isinstance(integrity, str) else None,
                )

    # v1 (or v2 fallback) has 'dependencies'
    if not packages and "dependencies" in data and isinstance(data["dependencies"], dict):
        _walk_v1_dependencies(data["dependencies"], packages)

    return packages


def diff_lockfiles(
    old_pkgs: dict[str, LockfilePackage],
    new_pkgs: dict[str, LockfilePackage],
    max_packages: int = DEFAULT_MAX_PACKAGES,
) -> list[PackageChange]:
    """Compute differences between two parsed lockfile maps."""
    all_names = sorted(set(old_pkgs.keys()) | set(new_pkgs.keys()))
    changes: list[PackageChange] = []

    for name in all_names:
        old_entry = old_pkgs.get(name)
        new_entry = new_pkgs.get(name)

        if old_entry is None and new_entry is not None:
            changes.append(
                PackageChange(
                    name=name,
                    old_version=None,
                    new_version=new_entry.version,
                    change_type="added",
                    resolved=new_entry.resolved,
                    integrity=new_entry.integrity,
                )
            )
        elif old_entry is not None and new_entry is None:
            changes.append(
                PackageChange(
                    name=name,
                    old_version=old_entry.version,
                    new_version=None,
                    change_type="removed",
                    resolved=old_entry.resolved,
                    integrity=old_entry.integrity,
                )
            )
        elif old_entry is not None and new_entry is not None:
            if old_entry.version != new_entry.version:
                change_type = "upgraded" if new_entry.version > old_entry.version else "downgraded"
                changes.append(
                    PackageChange(
                        name=name,
                        old_version=old_entry.version,
                        new_version=new_entry.version,
                        change_type=change_type,
                        resolved=new_entry.resolved,
                        integrity=new_entry.integrity,
                    )
                )

    scannable_count = sum(1 for c in changes if c.change_type != "removed")
    if scannable_count > max_packages:
        raise LockfileBudgetExceededError(
            f"Lockfile changes exceed max-packages limit ({scannable_count} > {max_packages}); "
            "analysis aborted to avoid unbounded execution."
        )

    return changes


def read_lockfile_from_git(ref: str, repo_dir: Path | None = None) -> str:
    """Read package-lock.json from a specific git ref."""
    cmd = ["git", "show", f"{ref}:package-lock.json"]
    try:
        proc = subprocess.run(  # noqa: S603
            cmd,
            cwd=str(repo_dir) if repo_dir else None,
            capture_output=True,
            text=True,
            check=True,
        )
        return proc.stdout
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip() if exc.stderr else ""
        msg = f"Could not read package-lock.json from git ref '{ref}': {stderr}"
        raise LockfileError(msg) from exc


def read_lockfile_from_path(path_or_dir: Path | str) -> tuple[str, str]:
    """Read lockfile content from a path or directory containing package-lock.json.

    Returns (content, resolved_filename).
    """
    p = Path(path_or_dir)
    if p.is_dir():
        # Check for yarn or pnpm first
        if (p / "yarn.lock").exists() and not (p / "package-lock.json").exists():
            check_supported_lockfile_path(p / "yarn.lock")
        if (p / "pnpm-lock.yaml").exists() and not (p / "package-lock.json").exists():
            check_supported_lockfile_path(p / "pnpm-lock.yaml")
        lock_file = p / "package-lock.json"
        if not lock_file.exists():
            raise FileNotFoundError(f"No package-lock.json found in directory '{p}'")
        return lock_file.read_text(encoding="utf-8"), lock_file.name

    check_supported_lockfile_path(p)
    if not p.exists():
        raise FileNotFoundError(f"Lockfile not found: '{p}'")
    return p.read_text(encoding="utf-8"), p.name


def scan_lockfile_diff(
    base_content: str,
    head_content: str,
    base_source: str = "base",
    head_source: str = "head",
    policy: Policy | None = None,
    max_packages: int = DEFAULT_MAX_PACKAGES,
    registry_client: NpmRegistryClient | None = None,
    experimental_hollow: bool = False,
    as_of: datetime | None = None,
    cache_dir: Path | None = None,
) -> LockfileDiffReport:
    """Analyze all changed packages between base and head lockfiles."""
    if policy is None:
        policy = load_policy()

    if as_of is None:
        as_of = datetime.now(UTC)
    elif as_of.tzinfo is None:
        as_of = as_of.replace(tzinfo=UTC)

    old_pkgs = parse_lockfile_content(base_content, filename=base_source)
    new_pkgs = parse_lockfile_content(head_content, filename=head_source)

    has_budget_exceeded = False
    skipped_count = 0
    try:
        changes = diff_lockfiles(old_pkgs, new_pkgs, max_packages=max_packages)
    except LockfileBudgetExceededError:
        # User requested: "Cap with --max-packages (default 200; report how many were skipped)"
        # Scan up to max_packages, skip remaining, fail closed to WARN
        changes = diff_lockfiles(old_pkgs, new_pkgs, max_packages=999_999)
        scannable = [c for c in changes if c.change_type != "removed"]
        skipped_count = len(scannable) - max_packages
        has_budget_exceeded = True

    scannable_changes = [c for c in changes if c.change_type != "removed"]
    if has_budget_exceeded:
        scannable_changes = scannable_changes[:max_packages]

    package_results: list[dict[str, Any]] = []
    overall_decision = Decision.WARN if has_budget_exceeded else Decision.ALLOW
    all_limitations: list[str] = []
    if has_budget_exceeded:
        all_limitations.append(
            f"Exceeded max-packages limit: scanned {max_packages}, skipped {skipped_count} "
            f"packages; analysis capped by safety budget."
        )

    client = registry_client or NpmRegistryClient(cache_dir=cache_dir or DEFAULT_CACHE_DIR)
    close_client = registry_client is None
    cfg = ExtractionConfig()

    try:
        for change in scannable_changes:
            pkg_name = change.name
            new_ver = change.new_version
            old_ver = change.old_version

            if not new_ver:
                continue

            try:
                # Download new tarball (using resolved URL if present)
                if change.resolved:
                    new_tarball = client.download_tarball_url(
                        name=pkg_name,
                        version=new_ver,
                        tarball_url=change.resolved,
                        integrity=change.integrity,
                    )
                else:
                    new_tarball = client.download_tarball(
                        name=pkg_name, version=new_ver, as_of=as_of
                    )
                    if change.integrity:
                        data = new_tarball.read_bytes()
                        verify_integrity(data, change.integrity)

                rc_new = extract_release_in_memory(new_tarball, config=cfg)

                # For added packages (Part 0a dependency-aware path):
                # resolve earlier version published before as_of if one exists.
                rc_old = None
                if old_ver is None:
                    try:
                        meta = client.get_metadata(pkg_name, as_of=as_of)
                        versions_dict = meta.get("versions", {})
                        time_map = {
                            k: v for k, v in meta.get("time", {}).items()
                            if k not in ("created", "modified")
                        }
                        target_time = time_map.get(new_ver, "")
                        earlier = [
                            v for v in versions_dict
                            if v != new_ver and (
                                (target_time and time_map.get(v, "") < target_time)
                                or (
                                not target_time
                                and nodesemver.valid(v)
                                and nodesemver.valid(new_ver)
                                and nodesemver.lt(v, new_ver)
                            )
                            )
                        ]
                        if earlier:
                            if target_time:
                                prev_ver = max(earlier, key=lambda v: time_map.get(v, ""))
                            else:
                                prev_ver = max(
                                    earlier,
                                    key=lambda v: nodesemver.parse(v) if nodesemver.valid(v) else (0, 0, 0),  # noqa: E501
                                )
                            old_ver = prev_ver
                            old_tarball = client.download_tarball(
                                name=pkg_name, version=old_ver, as_of=as_of
                            )
                            rc_old = extract_release_in_memory(old_tarball, config=cfg)
                    except Exception as e_dep:
                        logger.debug("Baseline lookup for added dep %s: %s", pkg_name, e_dep)
                        rc_old = None
                elif old_ver:
                    try:
                        old_tarball = client.download_tarball(
                            name=pkg_name, version=old_ver, as_of=as_of
                        )
                        rc_old = extract_release_in_memory(old_tarball, config=cfg)
                    except Exception as e_old:
                        logger.warning(
                            "Failed to fetch baseline %s@%s for lockfile diff: %s; using full-scan",
                            pkg_name,
                            old_ver,
                            e_old,
                        )
                        rc_old = None

                is_git = bool(
                    change.resolved
                    and (
                        change.resolved.startswith("git+")
                        or change.resolved.startswith("git://")
                        or (
                            "github.com" in change.resolved
                            and not change.resolved.endswith(".tgz")
                        )
                    )
                )
                is_file = bool(change.resolved and change.resolved.startswith("file:"))
                is_reg = not (is_git or is_file)

                evidence = analyze_release(
                    new=rc_new,
                    baseline=rc_old,
                    policy=policy,
                    config=cfg,
                    registry_client=client,
                    experimental_hollow=experimental_hollow,
                    is_registry_package=is_reg,
                )
                is_full = rc_old is None
                decision, lims = decide(evidence, policy=policy, is_full_scan=is_full)

                # Track highest overall severity decision
                if decision == Decision.BLOCK:
                    overall_decision = Decision.BLOCK
                elif decision == Decision.WARN and overall_decision != Decision.BLOCK:
                    overall_decision = Decision.WARN

                package_results.append({
                    "package": pkg_name,
                    "old_version": old_ver,
                    "new_version": new_ver,
                    "change_type": change.change_type,
                    "decision": decision.name,
                    "evidence": [e.id for e in evidence],
                    "evidence_details": [
                        {
                            "id": e.id,
                            "severity": e.severity.name,
                            "file": e.file,
                            "explanation": e.explanation,
                            "legitimate_use_note": e.legitimate_use_note,
                        }
                        for e in evidence
                    ],
                    "limitations": lims,
                    "status": "ok",
                })
                all_limitations.extend(lims)

            except IntegrityError as exc:
                logger.error("Tarball integrity mismatch for %s: %s", pkg_name, exc)
                package_results.append({
                    "package": pkg_name,
                    "old_version": old_ver,
                    "new_version": new_ver,
                    "change_type": change.change_type,
                    "decision": "BLOCK",
                    "evidence": ["integrity_mismatch"],
                    "evidence_details": [
                        {
                            "id": "integrity_mismatch",
                            "severity": Severity.HIGH.name,
                            "file": None,
                            "explanation": f"Tarball integrity mismatch for {pkg_name}@{new_ver}: {exc}",  # noqa: E501
                            "legitimate_use_note": "Registry CDN sync issue, corrupted download, or tampering.",  # noqa: E501,
                        }
                    ],
                    "limitations": [f"Tarball integrity check failed for {pkg_name}: {exc}"],
                    "status": f"integrity_error: {exc}",
                })
                overall_decision = Decision.BLOCK

            except Exception as exc:
                logger.error("Error analyzing package %s in lockfile diff: %s", pkg_name, exc)
                package_results.append({
                    "package": pkg_name,
                    "old_version": old_ver,
                    "new_version": new_ver,
                    "change_type": change.change_type,
                    "decision": "WARN",
                    "evidence": ["inspection_failed"],
                    "evidence_details": [
                        {
                            "id": "inspection_failed",
                            "severity": Severity.MEDIUM.name,
                            "file": None,
                            "explanation": f"Failed to inspect {pkg_name}@{new_ver}: {exc}",
                            "legitimate_use_note": "Corrupted archive, malformed package.json, or unsupported file.",  # noqa: E501,
                        }
                    ],
                    "limitations": [f"Inspection failed for {pkg_name}: {exc}"],
                    "status": f"error: {exc}",
                })
                if overall_decision != Decision.BLOCK:
                    overall_decision = Decision.WARN

    finally:
        if close_client:
            client.close()

    return LockfileDiffReport(
        base_source=base_source,
        head_source=head_source,
        total_packages_scanned=len(package_results),
        decision=overall_decision,
        package_results=package_results,
        limitations=sorted(set(all_limitations)),
        has_budget_exceeded=has_budget_exceeded,
    )
