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
import re
import subprocess
import urllib.parse
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import cmp_to_key
from pathlib import Path
from typing import Any

import nodesemver

from release_sentinel.dependency_resolver import select_baseline_for_added_package
from release_sentinel.differ import analyze_release
from release_sentinel.engine import decide
from release_sentinel.extractor import ExtractionConfig, extract_release_in_memory
from release_sentinel.models import Decision, Evidence, Severity
from release_sentinel.policy import Policy, load_policy
from release_sentinel.registry import (
    IntegrityError,
    NpmRegistryClient,
    redact_url_secrets,
    verify_integrity,
)

logger = logging.getLogger(__name__)

DEFAULT_MAX_PACKAGES = 300
DEFAULT_CACHE_DIR = Path.home() / ".cache" / "release_sentinel"


class LockfileError(Exception):
    """Base error for lockfile operations."""


class UnsupportedLockfileError(LockfileError):
    """Raised when an unsupported lockfile format (yarn, pnpm) is provided."""


class LockfileParseError(LockfileError):
    """Raised when a lockfile cannot be parsed as valid JSON."""


class LockfileBudgetExceededError(LockfileError):
    """Raised when changed packages exceed the safety budget."""


_SAFE_PKG_NAME_RE = re.compile(r"^(?:@[a-zA-Z0-9_.-]+/)?[a-zA-Z0-9_.-]+$")
_GIT_REF_PATTERN = re.compile(r"^[a-zA-Z0-9_./@^~][a-zA-Z0-9_\-./@^~{}*]*$")


def validate_git_ref(ref: str) -> str:
    """Validate a git ref to prevent argument injection or unsafe characters."""
    ref_clean = ref.strip()
    if not ref_clean:
        raise LockfileError("Git ref cannot be empty")
    if ref_clean.startswith("-"):
        raise LockfileError(f"Git ref cannot start with dash '-': {ref!r}")
    if not _GIT_REF_PATTERN.match(ref_clean):
        raise LockfileError(f"Invalid or unsafe characters in git ref: {ref!r}")
    return ref_clean


def validate_package_name(name: str) -> str:
    """Validate package name against path traversal and dangerous characters."""
    if not name or not isinstance(name, str):
        raise LockfileError(f"Invalid package name: {name!r}")
    clean = name.strip()
    if ".." in clean or "\\" in clean or "\x00" in clean:
        msg = f"Path traversal or illegal characters detected in package name: {name!r}"
        raise LockfileError(msg)
    if clean.startswith(("/", ".")):
        raise LockfileError(f"Package name cannot start with '/' or '.': {name!r}")
    if not _SAFE_PKG_NAME_RE.match(clean):
        raise LockfileError(f"Malformed package name: {name!r}")
    return clean


@dataclass(frozen=True)
class LockfilePackage:
    """A package entry recorded in a lockfile."""

    name: str
    version: str
    resolved: str | None = None
    integrity: str | None = None
    has_install_script: bool = False


@dataclass(frozen=True)
class PackageChange:
    """A detected difference between two lockfiles for a package."""

    name: str
    old_version: str | None  # None if ADDED
    new_version: str | None  # None if REMOVED
    change_type: str  # 'added', 'upgraded', 'downgraded', 'removed'
    resolved: str | None = None
    integrity: str | None = None
    has_install_script: bool = False


class LockfilePackages(dict[tuple[str, str], LockfilePackage]):
    """Mapping of (name, version) -> LockfilePackage with backwards-compatible string lookup."""

    def __contains__(self, key: object) -> bool:
        if isinstance(key, str):
            return any(k[0] == key for k in self.keys())
        return super().__contains__(key)

    def __getitem__(self, key: object) -> LockfilePackage:
        if isinstance(key, str):
            for (pkg_name, _), pkg in self.items():
                if pkg_name == key:
                    return pkg
            raise KeyError(key)
        if isinstance(key, tuple):
            return super().__getitem__(key)
        raise KeyError(key)

    def get(
        self,
        key: object,
        default: LockfilePackage | None = None,
    ) -> LockfilePackage | None:
        if isinstance(key, str):
            for (pkg_name, _), pkg in self.items():
                if pkg_name == key:
                    return pkg
            return default
        if isinstance(key, tuple):
            return super().get(key, default)
        return default


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
    """Extract package name from node_modules key in lockfile v2/v3."""
    if not pkg_path:
        return None  # Root package

    parts = pkg_path.replace("\\", "/").split("node_modules/")
    if len(parts) < 2 or not parts[-1]:
        return None

    candidate = parts[-1].rstrip("/")
    return candidate if candidate else None


def _walk_v1_dependencies(
    deps_dict: dict[str, Any],
    out: LockfilePackages,
) -> None:
    """Recursively collect packages from a v1 dependencies tree."""
    for name, data in deps_dict.items():
        if not isinstance(data, dict):
            continue
        version = data.get("version")
        if version and isinstance(version, str):
            resolved = data.get("resolved")
            integrity = data.get("integrity")
            has_install = bool(data.get("hasInstallScript"))
            try:
                valid_name = validate_package_name(name)
            except LockfileError as exc:
                raise LockfileParseError(f"Invalid dependency name in lockfile: {exc}") from exc

            key = (valid_name, version)
            if key not in out:
                out[key] = LockfilePackage(
                    name=valid_name,
                    version=version,
                    resolved=resolved if isinstance(resolved, str) else None,
                    integrity=integrity if isinstance(integrity, str) else None,
                    has_install_script=has_install,
                )
        nested = data.get("dependencies")
        if isinstance(nested, dict):
            _walk_v1_dependencies(nested, out)


def parse_lockfile_content(
    content: str | bytes,
    filename: str = "package-lock.json",
) -> LockfilePackages:
    """Parse a package-lock.json content into a dictionary of (name, version) -> LockfilePackage."""
    check_supported_lockfile_path(filename)

    if isinstance(content, bytes):
        content = content.decode("utf-8", errors="replace")

    try:
        data = json.loads(content)
    except Exception as exc:
        raise LockfileParseError(f"Failed to parse lockfile JSON ({filename}): {exc}") from exc

    if not isinstance(data, dict):
        raise LockfileParseError(f"Lockfile root must be a JSON object ({filename})")

    packages = LockfilePackages()

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

            try:
                valid_name = validate_package_name(name)
            except LockfileError as exc:
                raise LockfileParseError(f"Invalid package name in lockfile: {exc}") from exc

            resolved = pkg_info.get("resolved")
            integrity = pkg_info.get("integrity")
            has_install = bool(pkg_info.get("hasInstallScript"))

            key = (valid_name, version)
            if key not in packages:
                packages[key] = LockfilePackage(
                    name=valid_name,
                    version=version,
                    resolved=resolved if isinstance(resolved, str) else None,
                    integrity=integrity if isinstance(integrity, str) else None,
                    has_install_script=has_install,
                )

    # v1 (or v2 fallback) has 'dependencies'
    if not packages and "dependencies" in data and isinstance(data["dependencies"], dict):
        _walk_v1_dependencies(data["dependencies"], packages)

    return packages


def _is_semver_gt(v1: str, v2: str) -> bool:
    """Return True if v1 > v2 under semver rules."""
    try:
        if nodesemver.valid(v1, loose=True) and nodesemver.valid(v2, loose=True):
            return bool(nodesemver.gt(v1, v2, loose=True))
    except Exception as exc:
        logger.debug("Semver comparison error for %r vs %r: %s", v1, v2, exc)
    return v1 > v2


def _semver_cmp(a: str, b: str) -> int:
    try:
        return int(nodesemver.compare(a, b, loose=True))
    except Exception as exc:
        logger.debug("Semver compare error for %r vs %r: %s", a, b, exc)
        return (a > b) - (a < b)


_semver_sort_key = cmp_to_key(_semver_cmp)


def _normalize_pkg_map(
    pkgs: Mapping[object, LockfilePackage] | Iterable[LockfilePackage],
) -> dict[tuple[str, str], LockfilePackage]:
    result: dict[tuple[str, str], LockfilePackage] = {}
    if isinstance(pkgs, (set, list)):
        for p in pkgs:
            result[(p.name, p.version)] = p
    elif isinstance(pkgs, (dict, Mapping)):
        for k, v in pkgs.items():
            if isinstance(k, tuple):
                result[k] = v
            else:
                result[(v.name, v.version)] = v
    return result


def diff_lockfiles(
    old_pkgs: Mapping[object, LockfilePackage] | Iterable[LockfilePackage],
    new_pkgs: Mapping[object, LockfilePackage] | Iterable[LockfilePackage],
    max_packages: int = DEFAULT_MAX_PACKAGES,
) -> list[PackageChange]:
    """Compute differences between two parsed lockfile maps."""
    old_map = _normalize_pkg_map(old_pkgs)
    new_map = _normalize_pkg_map(new_pkgs)

    old_pairs = set(old_map.keys())
    new_pairs = set(new_map.keys())

    added_pairs = new_pairs - old_pairs
    removed_pairs = old_pairs - new_pairs

    all_names = sorted({n for n, _ in added_pairs} | {n for n, _ in removed_pairs})
    changes: list[PackageChange] = []

    for name in all_names:
        name_added = sorted([v for n, v in added_pairs if n == name], key=_semver_sort_key)
        name_removed = sorted([v for n, v in removed_pairs if n == name], key=_semver_sort_key)

        # Best-effort upgraded/downgraded pairing when name loses one version and gains one
        if len(name_removed) == 1 and len(name_added) == 1:
            old_v = name_removed[0]
            new_v = name_added[0]
            new_pkg = new_map[(name, new_v)]
            change_type = "upgraded" if _is_semver_gt(new_v, old_v) else "downgraded"
            changes.append(
                PackageChange(
                    name=name,
                    old_version=old_v,
                    new_version=new_v,
                    change_type=change_type,
                    resolved=new_pkg.resolved,
                    integrity=new_pkg.integrity,
                    has_install_script=new_pkg.has_install_script,
                )
            )
        elif len(name_removed) > 0 and len(name_added) > 0:
            paired_count = min(len(name_removed), len(name_added))
            for i in range(paired_count):
                old_v = name_removed[i]
                new_v = name_added[i]
                new_pkg = new_map[(name, new_v)]
                change_type = "upgraded" if _is_semver_gt(new_v, old_v) else "downgraded"
                changes.append(
                    PackageChange(
                        name=name,
                        old_version=old_v,
                        new_version=new_v,
                        change_type=change_type,
                        resolved=new_pkg.resolved,
                        integrity=new_pkg.integrity,
                        has_install_script=new_pkg.has_install_script,
                    )
                )
            for new_v in name_added[paired_count:]:
                new_pkg = new_map[(name, new_v)]
                changes.append(
                    PackageChange(
                        name=name,
                        old_version=None,
                        new_version=new_v,
                        change_type="added",
                        resolved=new_pkg.resolved,
                        integrity=new_pkg.integrity,
                        has_install_script=new_pkg.has_install_script,
                    )
                )
            for old_v in name_removed[paired_count:]:
                old_pkg = old_map[(name, old_v)]
                changes.append(
                    PackageChange(
                        name=name,
                        old_version=old_v,
                        new_version=None,
                        change_type="removed",
                        resolved=old_pkg.resolved,
                        integrity=old_pkg.integrity,
                        has_install_script=old_pkg.has_install_script,
                    )
                )
        elif len(name_added) > 0:
            for new_v in name_added:
                new_pkg = new_map[(name, new_v)]
                changes.append(
                    PackageChange(
                        name=name,
                        old_version=None,
                        new_version=new_v,
                        change_type="added",
                        resolved=new_pkg.resolved,
                        integrity=new_pkg.integrity,
                        has_install_script=new_pkg.has_install_script,
                    )
                )
        elif len(name_removed) > 0:
            for old_v in name_removed:
                old_pkg = old_map[(name, old_v)]
                changes.append(
                    PackageChange(
                        name=name,
                        old_version=old_v,
                        new_version=None,
                        change_type="removed",
                        resolved=old_pkg.resolved,
                        integrity=old_pkg.integrity,
                        has_install_script=old_pkg.has_install_script,
                    )
                )

    scannable_count = sum(1 for c in changes if c.change_type != "removed")
    if scannable_count > max_packages:
        raise LockfileBudgetExceededError(
            f"Lockfile changes exceed max-packages limit ({scannable_count} > {max_packages}); "
            "analysis aborted to avoid unbounded execution."
        )

    return changes


def _sort_changes_by_risk(
    changes: list[PackageChange],
    client: NpmRegistryClient | None = None,
    as_of: datetime | None = None,
) -> list[PackageChange]:
    """Sort scannable package changes by risk priority (Stage 7a Part 0c).

    Priority:
    1. Added packages first, then upgraded (and downgraded).
    2. Within each group: packages that declare preinstall/install/postinstall first.
    3. Within each group: newest published first.
    """
    def risk_tuple(c: PackageChange) -> tuple[int, int, float, str]:
        # Tier 1: Added first (0) vs upgraded/downgraded (1)
        tier1 = 0 if c.change_type == "added" else 1

        # Tier 2: Declares preinstall/install/postinstall
        has_hook = c.has_install_script
        pub_iso = ""

        if client and as_of and c.new_version:
            try:
                meta = client.get_metadata(c.name, as_of=as_of)
                if not has_hook:
                    scripts = (
                        meta.get("versions", {})
                        .get(c.new_version, {})
                        .get("scripts", {})
                    )
                    if isinstance(scripts, dict) and any(
                        h in scripts for h in ("preinstall", "install", "postinstall")
                    ):
                        has_hook = True
                pub_iso = meta.get("time", {}).get(c.new_version, "")
            except Exception as exc:
                logger.debug("Risk sort metadata lookup failed for %s: %s", c.name, exc)

        tier2 = 0 if has_hook else 1

        # Tier 3: Newest published first (negative epoch)
        epoch = 0.0
        if pub_iso:
            try:
                dt = datetime.fromisoformat(pub_iso.replace("Z", "+00:00"))
                epoch = dt.timestamp()
            except Exception as exc:
                logger.debug("Failed to parse pub_iso for %s: %s", c.name, exc)

        return (tier1, tier2, -epoch, c.name)

    return sorted(changes, key=risk_tuple)


def read_lockfile_from_git(ref: str, repo_dir: Path | None = None) -> str:
    """Read package-lock.json from a specific git ref."""
    safe_ref = validate_git_ref(ref)
    cmd = ["git", "show", f"{safe_ref}:package-lock.json", "--"]
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
        msg = f"Could not read package-lock.json from git ref '{safe_ref}': {stderr}"
        raise LockfileError(msg) from exc


def read_lockfile_from_path(path_or_dir: Path | str) -> tuple[str, str]:
    """Read lockfile content from a path or directory containing package-lock.json."""
    p = Path(path_or_dir)
    if p.is_dir():
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
    skipped_packages: list[PackageChange] = []
    try:
        changes = diff_lockfiles(old_pkgs, new_pkgs, max_packages=max_packages)
        scannable_changes = [c for c in changes if c.change_type != "removed"]
    except LockfileBudgetExceededError:
        changes = diff_lockfiles(old_pkgs, new_pkgs, max_packages=999_999)
        scannable = [c for c in changes if c.change_type != "removed"]
        has_budget_exceeded = True
        default_cache = cache_dir or DEFAULT_CACHE_DIR
        client_for_sort = registry_client or NpmRegistryClient(cache_dir=default_cache)
        prioritized = _sort_changes_by_risk(scannable, client=client_for_sort, as_of=as_of)
        scannable_changes = prioritized[:max_packages]
        skipped_packages = prioritized[max_packages:]
        skipped_count = len(skipped_packages)

    package_results: list[dict[str, Any]] = []
    overall_decision = Decision.WARN if has_budget_exceeded else Decision.ALLOW
    all_limitations: list[str] = []
    if has_budget_exceeded:
        skipped_names = [c.name for c in skipped_packages[:50]]
        names_str = ", ".join(skipped_names)
        all_limitations.append(
            f"Exceeded max-packages limit: scanned {max_packages}, skipped {skipped_count} "
            f"packages by risk priority. Skipped packages (first 50): {names_str}; "
            "analysis capped by safety budget."
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

            # Check for non-registry source (git, file, or non-registry URL)
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
            is_non_reg_url = False
            if change.resolved and not (is_git or is_file):
                try:
                    parsed_res = urllib.parse.urlparse(change.resolved)
                    if (
                        parsed_res.scheme.lower() != "https"
                        or not client.is_host_allowed(parsed_res.hostname or "")
                    ):
                        is_non_reg_url = True
                except Exception:
                    is_non_reg_url = True

            if is_git or is_file or is_non_reg_url:
                source_desc = (
                    "git repository"
                    if is_git
                    else ("local file" if is_file else "custom non-registry URL")
                )
                ev_unscanned = Evidence(
                    id="unscanned_non_registry_source",
                    severity=Severity.MEDIUM,
                    file="package-lock.json",
                    explanation=(
                        f"Package '{pkg_name}@{new_ver}' resolved from {source_desc}: "
                        f"{redact_url_secrets(change.resolved or '')}. "
                        "Non-registry sources are not scanned by the registry audit gate."
                    ),
                    legitimate_use_note=(
                        "Projects sometimes depend on forks, git branches, or local packages."
                    ),
                )
                if overall_decision != Decision.BLOCK:
                    overall_decision = Decision.WARN
                package_results.append({
                    "package": pkg_name,
                    "old_version": old_ver,
                    "new_version": new_ver,
                    "change_type": change.change_type,
                    "decision": "WARN",
                    "evidence": [ev_unscanned.id],
                    "evidence_details": [
                        {
                            "id": ev_unscanned.id,
                            "severity": ev_unscanned.severity.name,
                            "file": ev_unscanned.file,
                            "explanation": ev_unscanned.explanation,
                            "legitimate_use_note": ev_unscanned.legitimate_use_note,
                        }
                    ],
                    "limitations": [
                        f"Package {pkg_name}@{new_ver} from {source_desc} not scanned."
                    ],
                    "status": "unscanned_non_registry_source",
                })
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

                # For added packages (Stage 7a Part 0b):
                # Apply shared maturity rule and same-major baseline selection
                rc_old = None
                if old_ver is None:
                    try:
                        meta = client.get_metadata(pkg_name, as_of=as_of)
                        prev_ver = select_baseline_for_added_package(
                            pkg_name, new_ver, meta, as_of
                        )
                        if prev_ver:
                            old_ver = prev_ver
                            old_tarball = client.download_tarball(
                                name=pkg_name, version=old_ver, as_of=as_of
                            )
                            rc_old = extract_release_in_memory(old_tarball, config=cfg)
                    except Exception as e_dep:
                        logger.debug("Baseline lookup for added package %s: %s", pkg_name, e_dep)
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
                            "legitimate_use_note": "Registry CDN sync issue, corrupted download, or tampering.",  # noqa: E501
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
                            "legitimate_use_note": "Corrupted archive, malformed package.json, or unsupported file.",  # noqa: E501
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
