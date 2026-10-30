"""npm lockfile parser and differ for Release Sentinel.

Supports npm package-lock.json v1, v2, and v3.
Detects yarn.lock and pnpm-lock.yaml and raises UnsupportedLockfileError with clear messaging.

Rules enforced:
- Never execute downloaded package code.
- Safe in-memory tarball extraction.
- Writes only inside designated cache and project directory.
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
    all_integrities: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.all_integrities and self.integrity:
            object.__setattr__(self, "all_integrities", (self.integrity,))


@dataclass(frozen=True)
class PackageChange:
    """A detected difference between two lockfiles for a package."""

    name: str
    old_version: str | None  # None if ADDED
    new_version: str | None  # None if REMOVED
    change_type: str  # 'added', 'upgraded', 'downgraded', 'removed', 'modified'
    resolved: str | None = None
    integrity: str | None = None
    has_install_script: bool = False
    old_resolved: str | None = None
    old_integrity: str | None = None
    conflicting_integrities: tuple[str, ...] = ()


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


def is_report_notable(report: LockfileDiffReport | dict[str, Any]) -> bool:
    """Determine whether a lockfile diff report meets the 'notable' criterion for alerts.

    A report is notable if:
    - Overall decision is BLOCK, or
    - Overall decision is WARN and at least one finding meets:
      1) At least one HIGH or CRITICAL evidence item,
      2) An install-time hook change (install_script_added or install_script_changed),
      3) At least 2 distinct MEDIUM evidence types in a single package.
    """
    if isinstance(report, LockfileDiffReport):
        if report.decision == Decision.BLOCK:
            return True
        pkg_results = report.package_results
    else:
        dec = str(report.get("decision", "")).upper()
        if dec in ("BLOCK", Decision.BLOCK.value):
            return True
        pkg_results = report.get("package_results", [])

    for pkg in pkg_results:
        pkg_dec = str(pkg.get("decision", "")).upper()
        if pkg_dec in ("ALLOW", "DECISION.ALLOW"):
            continue

        details = pkg.get("evidence_details", [])
        has_high_crit = any(
            str(d.get("effective_severity", d.get("severity", ""))).upper() in ("HIGH", "CRITICAL")
            for d in details
        )
        ev_ids = [d.get("id") for d in details] if details else pkg.get("evidence", [])
        has_hook = any(hid in ev_ids for hid in ("install_script_added", "install_script_changed"))

        medium_ids = {
            d.get("id")
            for d in details
            if str(d.get("effective_severity", d.get("severity", ""))).upper() == "MEDIUM"
        }
        if has_high_crit or has_hook or len(medium_ids) >= 2:
            return True

    return False


def should_post_comment(
    report: LockfileDiffReport | dict[str, Any],
    comment_on: str,
) -> bool:
    """Determine whether to post/update a PR comment based on the comment-on setting.

    Settings:
    - 'block': only on BLOCK
    - 'notable': on BLOCK, or WARN meeting the notable criterion
    - 'warn': on BLOCK or any WARN
    - 'always': on all verdicts (BLOCK, WARN, ALLOW)
    """
    c_on = comment_on.strip().lower()
    if isinstance(report, LockfileDiffReport):
        dec = report.decision.value
    else:
        dec = str(report.get("decision", "")).upper()

    if c_on == "always":
        return True
    if c_on == "block":
        return dec == "BLOCK"
    if c_on in ("warn", "all_warn"):
        return dec in ("BLOCK", "WARN")
    if c_on == "notable":
        return dec == "BLOCK" or (dec == "WARN" and is_report_notable(report))
    return False


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
                    all_integrities=(integrity,)
                    if isinstance(integrity, str) and integrity
                    else (),
                )
            else:
                existing = out[key]
                if (
                    isinstance(integrity, str)
                    and integrity
                    and integrity not in existing.all_integrities
                ):
                    out[key] = LockfilePackage(
                        name=existing.name,
                        version=existing.version,
                        resolved=existing.resolved
                        or (resolved if isinstance(resolved, str) else None),
                        integrity=existing.integrity or integrity,
                        has_install_script=existing.has_install_script or has_install,
                        all_integrities=existing.all_integrities + (integrity,),
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
                    all_integrities=(integrity,)
                    if isinstance(integrity, str) and integrity
                    else (),
                )
            else:
                existing = packages[key]
                if (
                    isinstance(integrity, str)
                    and integrity
                    and integrity not in existing.all_integrities
                ):
                    packages[key] = LockfilePackage(
                        name=existing.name,
                        version=existing.version,
                        resolved=existing.resolved
                        or (resolved if isinstance(resolved, str) else None),
                        integrity=existing.integrity or integrity,
                        has_install_script=existing.has_install_script or has_install,
                        all_integrities=existing.all_integrities + (integrity,),
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
    items: Iterable[LockfilePackage]
    if isinstance(pkgs, Mapping):
        items = pkgs.values()
    else:
        items = pkgs
    for p in items:
        key = (p.name, p.version)
        if key not in result:
            result[key] = p
        else:
            existing = result[key]
            merged_integrities = existing.all_integrities
            for intg in p.all_integrities:
                if intg and intg not in merged_integrities:
                    merged_integrities = merged_integrities + (intg,)
            if merged_integrities != existing.all_integrities:
                result[key] = LockfilePackage(
                    name=existing.name,
                    version=existing.version,
                    resolved=existing.resolved or p.resolved,
                    integrity=existing.integrity or p.integrity,
                    has_install_script=existing.has_install_script or p.has_install_script,
                    all_integrities=merged_integrities,
                )
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
                        conflicting_integrities=new_pkg.all_integrities
                        if len(new_pkg.all_integrities) > 1
                        else (),
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

    # Compare entries whose (name, version) exist in BOTH base and head (Stage 7h)
    common_pairs = old_pairs & new_pairs
    for name, version in sorted(common_pairs):
        old_pkg = old_map[(name, version)]
        new_pkg = new_map[(name, version)]

        has_conflicting = len(new_pkg.all_integrities) > 1
        integrity_differs = False
        if old_pkg.integrity and new_pkg.integrity:
            if old_pkg.integrity.strip() != new_pkg.integrity.strip():
                integrity_differs = True

        lost_integrity = bool(old_pkg.integrity and not new_pkg.integrity)
        resolved_changed = bool(
            old_pkg.resolved != new_pkg.resolved
            and (
                old_pkg.integrity == new_pkg.integrity
                or (not old_pkg.integrity and not new_pkg.integrity)
            )
        )

        if has_conflicting or integrity_differs or lost_integrity or resolved_changed:
            changes.append(
                PackageChange(
                    name=name,
                    old_version=version,
                    new_version=version,
                    change_type="modified",
                    resolved=new_pkg.resolved,
                    integrity=new_pkg.integrity,
                    has_install_script=new_pkg.has_install_script,
                    old_resolved=old_pkg.resolved,
                    old_integrity=old_pkg.integrity,
                    conflicting_integrities=new_pkg.all_integrities if has_conflicting else (),
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
                    scripts = meta.get("versions", {}).get(c.new_version, {}).get("scripts", {})
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


def is_resolved_path_matching(pkg_name: str, version: str, resolved_url: str | None) -> bool:
    """Check if the resolved URL path matches the package name and version.

    Standard npm registry format:
    https://registry.npmjs.org/<name>/-/<basename>-<version>.tgz
    Handles scoped packages:
    https://registry.npmjs.org/@scope/pkg/-/pkg-version.tgz
    """
    if not resolved_url:
        return True
    try:
        parsed = urllib.parse.urlparse(resolved_url)
        path = urllib.parse.unquote(parsed.path)
        basename = pkg_name.split("/")[-1]
        expected_path = f"/{pkg_name}/-/{basename}-{version}.tgz"
        return path == expected_path
    except Exception:
        return False


def get_git_repo_root(cwd: Path | None = None) -> Path:
    """Return the absolute path to the git repository root."""
    try:
        proc = subprocess.run(  # noqa: S603
            ["git", "rev-parse", "--show-toplevel"],  # noqa: S607
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            check=True,
        )
        return Path(proc.stdout.strip()).resolve()
    except Exception as exc:
        raise LockfileError(f"Not inside a git repository: {exc}") from exc


def read_lockfile_from_git(
    ref: str,
    lockfile_rel_path: str = "package-lock.json",
    repo_dir: Path | None = None,
) -> str:
    """Read lockfile from a specific git ref at the repository-relative path."""
    safe_ref = validate_git_ref(ref)
    clean_path = lockfile_rel_path.replace("\\", "/").strip().lstrip("/")
    if not clean_path or clean_path.startswith("..") or "/../" in clean_path:
        raise LockfileError(f"Invalid repository-relative lockfile path: {lockfile_rel_path!r}")

    cmd = ["git", "show", f"{safe_ref}:{clean_path}", "--"]
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
        msg = f"Could not read {clean_path} from git ref '{safe_ref}': {stderr}"
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

            # Rule (d): Multiple paths in head with conflicting integrity values
            if len(change.conflicting_integrities) > 1:
                hashes_str = ", ".join(repr(h) for h in change.conflicting_integrities)
                ev_conflict = Evidence(
                    id="lockfile_integrity_changed",
                    severity=Severity.HIGH,
                    file="package-lock.json",
                    explanation=(
                        f"Lockfile contains multiple entries for '{pkg_name}@{new_ver}' "
                        f"with conflicting integrity hashes ({hashes_str}). A single package "
                        "version cannot legitimately have different tarball contents across "
                        "install locations."
                    ),
                    legitimate_use_note="Malformed or manually edited lockfile.",
                )
                package_results.append(
                    {
                        "package": pkg_name,
                        "old_version": old_ver,
                        "new_version": new_ver,
                        "change_type": change.change_type,
                        "decision": Decision.BLOCK.name,
                        "evidence": [ev_conflict.id],
                        "evidence_details": [
                            {
                                "id": ev_conflict.id,
                                "severity": ev_conflict.severity.name,
                                "raw_severity": ev_conflict.severity.name,
                                "effective_severity": ev_conflict.severity.name,
                                "file": ev_conflict.file,
                                "explanation": ev_conflict.explanation,
                                "legitimate_use_note": ev_conflict.legitimate_use_note,
                            }
                        ],
                        "limitations": [],
                        "status": "lockfile_integrity_changed",
                    }
                )
                overall_decision = Decision.BLOCK
                continue

            # Same-version lockfile changes (Stage 7h)
            if old_ver is not None and old_ver == new_ver:
                # Rule (a): Both have integrity and values differ
                if (
                    change.old_integrity
                    and change.integrity
                    and change.old_integrity.strip() != change.integrity.strip()
                ):
                    old_algo = change.old_integrity.split("-", 1)[0]
                    new_algo = change.integrity.split("-", 1)[0]
                    if old_algo == new_algo:
                        sev = Severity.HIGH
                        dec_name = Decision.BLOCK.name
                        overall_decision = Decision.BLOCK
                        note = (
                            "The npm registry never serves two different tarballs for the "
                            "same version; this indicates tarball tampering or a mirror issue."
                        )
                    else:
                        # Algorithm changed (e.g. sha1 to sha512 during lockfile upgrade)
                        sev = Severity.MEDIUM
                        dec_name = Decision.WARN.name
                        if overall_decision != Decision.BLOCK:
                            overall_decision = Decision.WARN
                        note = (
                            f"Integrity algorithm changed from '{old_algo}' to "
                            f"'{new_algo}'. This occurs during npm lockfile upgrades, "
                            "but tarball content cannot be verified without re-downloading."
                        )

                    ev_int = Evidence(
                        id="lockfile_integrity_changed",
                        severity=sev,
                        file="package-lock.json",
                        explanation=(
                            f"Lockfile entry for '{pkg_name}@{new_ver}' changed integrity from "
                            f"'{change.old_integrity}' to '{change.integrity}'. {note}"
                        ),
                        legitimate_use_note=(
                            "Lockfile re-generation after package unpublish/republish or upgrade."
                        ),
                    )
                    package_results.append(
                        {
                            "package": pkg_name,
                            "old_version": old_ver,
                            "new_version": new_ver,
                            "change_type": change.change_type,
                            "decision": dec_name,
                            "evidence": [ev_int.id],
                            "evidence_details": [
                                {
                                    "id": ev_int.id,
                                    "severity": ev_int.severity.name,
                                    "raw_severity": ev_int.severity.name,
                                    "effective_severity": ev_int.severity.name,
                                    "file": ev_int.file,
                                    "explanation": ev_int.explanation,
                                    "legitimate_use_note": ev_int.legitimate_use_note,
                                }
                            ],
                            "limitations": [],
                            "status": "lockfile_integrity_changed",
                        }
                    )
                    continue

                # Rule (b): Head lacks integrity while base had it
                if change.old_integrity and not change.integrity:
                    ev_lost = Evidence(
                        id="lockfile_missing_integrity",
                        severity=Severity.MEDIUM,
                        file="package-lock.json",
                        explanation=(
                            f"Lockfile entry for '{pkg_name}@{new_ver}' previously had integrity "
                            f"'{change.old_integrity}' in base, but is missing integrity in head. "
                            "Without an integrity hash, tarball tampering cannot be detected."
                        ),
                        legitimate_use_note=(
                            "Older npm lockfiles or local workspace entries may omit integrity."
                        ),
                    )
                    if overall_decision != Decision.BLOCK:
                        overall_decision = Decision.WARN
                    package_results.append(
                        {
                            "package": pkg_name,
                            "old_version": old_ver,
                            "new_version": new_ver,
                            "change_type": change.change_type,
                            "decision": Decision.WARN.name,
                            "evidence": [ev_lost.id],
                            "evidence_details": [
                                {
                                    "id": ev_lost.id,
                                    "severity": ev_lost.severity.name,
                                    "raw_severity": ev_lost.severity.name,
                                    "effective_severity": ev_lost.severity.name,
                                    "file": ev_lost.file,
                                    "explanation": ev_lost.explanation,
                                    "legitimate_use_note": ev_lost.legitimate_use_note,
                                }
                            ],
                            "limitations": [],
                            "status": "lockfile_missing_integrity",
                        }
                    )
                    continue

                # Rule (c): Resolved URL changed while integrity is equal
                if change.old_resolved != change.resolved:
                    ev_res = Evidence(
                        id="lockfile_resolved_changed",
                        severity=Severity.MEDIUM,
                        file="package-lock.json",
                        explanation=(
                            f"Lockfile entry for '{pkg_name}@{new_ver}' changed resolved URL "
                            f"from '{redact_url_secrets(change.old_resolved or '')}' to "
                            f"'{redact_url_secrets(change.resolved or '')}' while "
                            "maintaining the same integrity hash."
                        ),
                        legitimate_use_note=(
                            "Registry mirror switch, private proxy, or CDN domain migration."
                        ),
                    )
                    if overall_decision != Decision.BLOCK:
                        overall_decision = Decision.WARN
                    package_results.append(
                        {
                            "package": pkg_name,
                            "old_version": old_ver,
                            "new_version": new_ver,
                            "change_type": change.change_type,
                            "decision": Decision.WARN.name,
                            "evidence": [ev_res.id],
                            "evidence_details": [
                                {
                                    "id": ev_res.id,
                                    "severity": ev_res.severity.name,
                                    "raw_severity": ev_res.severity.name,
                                    "effective_severity": ev_res.severity.name,
                                    "file": ev_res.file,
                                    "explanation": ev_res.explanation,
                                    "legitimate_use_note": ev_res.legitimate_use_note,
                                }
                            ],
                            "limitations": [],
                            "status": "lockfile_resolved_changed",
                        }
                    )
                    continue

            # Check for non-registry source (git, file, or non-registry URL)
            is_git = bool(
                change.resolved
                and (
                    change.resolved.startswith("git+")
                    or change.resolved.startswith("git://")
                    or ("github.com" in change.resolved and not change.resolved.endswith(".tgz"))
                )
            )
            is_file = bool(change.resolved and change.resolved.startswith("file:"))
            is_non_reg_url = False
            if change.resolved and not (is_git or is_file):
                try:
                    parsed_res = urllib.parse.urlparse(change.resolved)
                    if parsed_res.scheme.lower() != "https" or not client.is_host_allowed(
                        parsed_res.hostname or ""
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
                package_results.append(
                    {
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
                                "raw_severity": ev_unscanned.severity.name,
                                "effective_severity": ev_unscanned.severity.name,
                                "file": ev_unscanned.file,
                                "explanation": ev_unscanned.explanation,
                                "legitimate_use_note": ev_unscanned.legitimate_use_note,
                            }
                        ],
                        "limitations": [
                            f"Package {pkg_name}@{new_ver} from {source_desc} not scanned."
                        ],
                        "status": "unscanned_non_registry_source",
                    }
                )
                continue

            if change.resolved and not is_resolved_path_matching(
                pkg_name, new_ver, change.resolved
            ):
                basename = pkg_name.split("/")[-1]
                expected_path = f"/{pkg_name}/-/{basename}-{new_ver}.tgz"
                ev_mismatch = Evidence(
                    id="lockfile_resolved_mismatch",
                    severity=Severity.HIGH,
                    file="package-lock.json",
                    explanation=(
                        f"Lockfile entry for '{pkg_name}@{new_ver}' resolves to unexpected URL "
                        f"'{redact_url_secrets(change.resolved)}' (expected path '{expected_path}'). "  # noqa: E501
                        "This indicates potential lockfile injection or package aliasing attack."
                    ),
                    legitimate_use_note=(
                        "Private registries or custom mirrors with non-standard URL path schemes."
                    ),
                )
                _, lims = decide([ev_mismatch], policy=policy, is_full_scan=False)
                package_results.append(
                    {
                        "package": pkg_name,
                        "old_version": old_ver,
                        "new_version": new_ver,
                        "change_type": change.change_type,
                        "decision": Decision.BLOCK.name,
                        "evidence": [ev_mismatch.id],
                        "evidence_details": [
                            {
                                "id": ev_mismatch.id,
                                "severity": ev_mismatch.severity.name,
                                "raw_severity": ev_mismatch.severity.name,
                                "effective_severity": ev_mismatch.severity.name,
                                "file": ev_mismatch.file,
                                "explanation": ev_mismatch.explanation,
                                "legitimate_use_note": ev_mismatch.legitimate_use_note,
                            }
                        ],
                        "limitations": lims,
                        "status": "lockfile_resolved_mismatch",
                    }
                )
                all_limitations.extend(lims)
                overall_decision = Decision.BLOCK
                continue

            extra_evidence: list[Evidence] = []
            if not change.integrity:
                extra_evidence.append(
                    Evidence(
                        id="lockfile_missing_integrity",
                        severity=Severity.MEDIUM,
                        file="package-lock.json",
                        explanation=(
                            f"Lockfile entry for '{pkg_name}@{new_ver}' is missing integrity hash. "
                            "Without an integrity hash, tarball tampering cannot be detected."
                        ),
                        legitimate_use_note=(
                            "Older npm lockfiles or local workspace entries may omit integrity."
                        ),
                    )
                )

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
                        prev_ver = select_baseline_for_added_package(pkg_name, new_ver, meta, as_of)
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
                            "github.com" in change.resolved and not change.resolved.endswith(".tgz")
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
                    follow_dependencies=False,
                )
                if extra_evidence:
                    evidence.extend(extra_evidence)
                is_full = rc_old is None
                decision, lims = decide(evidence, policy=policy, is_full_scan=is_full)
                pkg_overrides = (
                    {**policy.severity_overrides, **policy.full_scan_severity_overrides}
                    if is_full
                    else policy.severity_overrides
                )

                # Track highest overall severity decision
                if decision == Decision.BLOCK:
                    overall_decision = Decision.BLOCK
                elif decision == Decision.WARN and overall_decision != Decision.BLOCK:
                    overall_decision = Decision.WARN

                ev_details = []
                for e in evidence:
                    eff_s = pkg_overrides.get(e.id, e.severity)
                    eff_s_name = eff_s.name if hasattr(eff_s, "name") else str(eff_s)
                    ev_details.append(
                        {
                            "id": e.id,
                            "severity": eff_s_name,
                            "raw_severity": e.severity.name,
                            "effective_severity": eff_s_name,
                            "file": e.file,
                            "explanation": e.explanation,
                            "legitimate_use_note": e.legitimate_use_note,
                        }
                    )

                package_results.append(
                    {
                        "package": pkg_name,
                        "old_version": old_ver,
                        "new_version": new_ver,
                        "change_type": change.change_type,
                        "decision": decision.name,
                        "evidence": [e.id for e in evidence],
                        "evidence_details": ev_details,
                        "limitations": lims,
                        "status": "ok",
                    }
                )
                all_limitations.extend(lims)

            except IntegrityError as exc:
                logger.error("Tarball integrity mismatch for %s: %s", pkg_name, exc)
                package_results.append(
                    {
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
                                "raw_severity": Severity.HIGH.name,
                                "effective_severity": Severity.HIGH.name,
                                "file": None,
                                "explanation": f"Tarball integrity mismatch for {pkg_name}@{new_ver}: {exc}",  # noqa: E501
                                "legitimate_use_note": "Registry CDN sync issue, corrupted download, or tampering.",  # noqa: E501
                            }
                        ],
                        "limitations": [f"Tarball integrity check failed for {pkg_name}: {exc}"],
                        "status": f"integrity_error: {exc}",
                    }
                )
                overall_decision = Decision.BLOCK

            except Exception as exc:
                logger.error("Error analyzing package %s in lockfile diff: %s", pkg_name, exc)
                package_results.append(
                    {
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
                                "raw_severity": Severity.MEDIUM.name,
                                "effective_severity": Severity.MEDIUM.name,
                                "file": None,
                                "explanation": f"Failed to inspect {pkg_name}@{new_ver}: {exc}",
                                "legitimate_use_note": "Corrupted archive, malformed package.json, or unsupported file.",  # noqa: E501
                            }
                        ],
                        "limitations": [f"Inspection failed for {pkg_name}: {exc}"],
                        "status": f"error: {exc}",
                    }
                )
                if overall_decision != Decision.BLOCK:
                    overall_decision = Decision.WARN

    finally:
        if close_client:
            client.close()

    clean_limitations = [
        lim for lim in all_limitations if "Transitive (indirect) dependencies" not in lim
    ]
    clean_limitations.append(
        "Every changed lockfile entry (including transitive dependencies) is scanned."
    )
    if policy.replace_block_requires:
        clean_limitations.append(
            "Warning: Built-in multi-signal block_requires rules are overridden by custom policy."
        )

    return LockfileDiffReport(
        base_source=base_source,
        head_source=head_source,
        total_packages_scanned=len(package_results),
        decision=overall_decision,
        package_results=package_results,
        limitations=sorted(set(clean_limitations)),
        has_budget_exceeded=has_budget_exceeded,
    )


def find_matching_pr_comment_id(
    comments: list[dict[str, Any]] | str,
    marker: str = "<!-- release-sentinel-pr-comment -->",
    actor: str = "",
) -> str | None:
    """Find the existing PR comment ID matching marker and trusted author.

    Matches comments where body contains marker and the author is trusted:
    github-actions[bot], github-actions, or the specified workflow actor.
    Accepts either a parsed list of comment dicts or a raw JSON string.
    Returns the string ID of the first match, or None if not found.
    """
    if isinstance(comments, str):
        try:
            data = json.loads(comments)
        except Exception:
            return None
    elif isinstance(comments, list):
        data = comments
    else:
        return None

    trusted_authors = {"github-actions[bot]", "github-actions"}
    if actor:
        trusted_authors.add(actor.lower())

    for c in data:
        if not isinstance(c, dict):
            continue
        body = c.get("body") or ""
        author = (c.get("user") or {}).get("login") or ""
        if marker in body and author.lower() in trusted_authors:
            c_id = c.get("id")
            if c_id is not None:
                return str(c_id)

    return None
