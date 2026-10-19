"""Release differ for Release Sentinel (Stage 2).

Compares two extracted npm releases and returns a list of :class:`Evidence` items.
All checks are purely static — no code is executed (Rule 1).

Stage 2 changes
---------------
* Uses :mod:`file_classifier` to categorise files; ignores ASSET/DOCUMENT/SOURCE_MAP.
* Aggregates ``new_file_added`` into a single summary instead of per-file items.
* Notable new files (native binaries, executables, dotfiles, minified) get individual evidence.
* Only native binaries get ``native_binary_present`` MEDIUM evidence for non-readability;
  ignorable files are silent.
* Calls :mod:`content_scanner` for pattern-based detection on new/changed lines.
* Propagates ``ExtractionResult.capped`` as a limitation.
"""

from __future__ import annotations

import json
import logging
import re
from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING, Any

from release_sentinel.content_scanner import is_exempt_path, scan_full_release, scan_new_content
from release_sentinel.extractor import ExtractionConfig, ExtractionResult, ReleaseContents
from release_sentinel.file_classifier import FileCategory, classify, is_ignorable, is_notable
from release_sentinel.models import Evidence, Severity

if TYPE_CHECKING:
    from datetime import datetime

    from release_sentinel.policy import Policy
    from release_sentinel.registry import NpmRegistryClient

logger = logging.getLogger(__name__)

# Lifecycle script keys that run at install time
_INSTALL_SCRIPTS = {
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "prepublish",
    "prepublishOnly",
}

# Dependency manifest keys to compare
_DEP_KEYS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")

# Thresholds
_SIZE_RATIO_THRESHOLD = 2.0
_FILE_COUNT_JUMP_THRESHOLD = 50

_CI_WORKFLOW_FILE_RE = re.compile(
    r"^\.github/workflows/|^\.gitlab-ci\.ya?ml$|^\.circleci/|azure-pipelines"
)


def compare_releases(
    old: ExtractionResult | ReleaseContents,
    new: ExtractionResult | ReleaseContents,
) -> list[Evidence]:
    """Compare two extracted releases and return evidence items.

    Parameters
    ----------
    old:
        Extraction result or in-memory ReleaseContents for the *from* release.
    new:
        Extraction result or in-memory ReleaseContents for the *to* release.

    Returns
    -------
    list[Evidence]
        All findings, ordered by severity (highest first).
    """
    if isinstance(old, ExtractionResult):
        old = old.to_release_contents()
    if isinstance(new, ExtractionResult):
        new = new.to_release_contents()

    evidence: list[Evidence] = []

    old_pkg = old.package_json()
    new_pkg = new.package_json()

    if old_pkg is None:
        evidence.append(
            Evidence(
                id="inspection_failed",
                severity=Severity.MEDIUM,
                file="package.json",
                explanation=(
                    "Could not read or parse package.json from the old release. "
                    "Script, dependency, and bin comparisons are unavailable."
                ),
                legitimate_use_note=(
                    "This should never happen for a valid npm package. "
                    "May indicate a corrupted tarball."
                ),
            )
        )

    if new_pkg is None:
        evidence.append(
            Evidence(
                id="inspection_failed",
                severity=Severity.MEDIUM,
                file="package.json",
                explanation=(
                    "Could not read or parse package.json from the new release. "
                    "Script, dependency, and bin comparisons are unavailable."
                ),
                legitimate_use_note=(
                    "This should never happen for a valid npm package. "
                    "May indicate a corrupted tarball."
                ),
            )
        )

    # Determine install-script targets for content scanner escalation
    install_targets: set[str] = set()
    if new_pkg is not None:
        install_targets = _extract_install_script_targets(new_pkg)

    if old_pkg is not None and new_pkg is not None:
        evidence.extend(_diff_install_scripts(old_pkg, new_pkg))
        evidence.extend(_diff_dependencies(old_pkg, new_pkg))
        evidence.extend(_diff_bin_entries(old_pkg, new_pkg))

    evidence.extend(_diff_files(old, new, install_targets))
    evidence.extend(_diff_sizes(old, new))

    # Content scanner — only on text-like new/changed files
    evidence.extend(scan_new_content(old, new, install_targets))

    # Record soft-cap limitations inline as evidence
    for result, label in [(old, "old"), (new, "new")]:
        if result.capped and result.cap_reason:
            evidence.append(
                Evidence(
                    id="inspection_failed",
                    severity=Severity.MEDIUM,
                    file=None,
                    explanation=(
                        f"Extraction of the {label} release hit a soft cap: {result.cap_reason} "
                        "Some files were not inspected."
                    ),
                    legitimate_use_note=(
                        "Large packages (monorepos, bundled apps) may legitimately exceed "
                        "the extraction cap. Use --max-files / --max-size to raise it."
                    ),
                )
            )

    # Sort by severity descending
    _sev_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    evidence.sort(key=lambda e: _sev_order[e.severity])
    return evidence


def analyze_release(
    new: ExtractionResult | ReleaseContents,
    baseline: ExtractionResult | ReleaseContents | None = None,
    policy: Policy | None = None,
    config: ExtractionConfig | None = None,
    as_of: datetime | None = None,
    registry_client: NpmRegistryClient | None = None,
    samples_root: Path | None = None,
    dest_dir: Path | None = None,
    dep_stats: dict[str, int] | None = None,
) -> list[Evidence]:
    """Analyze a release either against a baseline (diff mode) or standalone (full-scan mode).

    Parameters
    ----------
    new:
        The target release to analyze (ExtractionResult or ReleaseContents).
    baseline:
        Optional baseline release. If None, full-scan mode is executed.
    policy:
        Optional Policy object.
    config:
        Optional ExtractionConfig object.
    as_of:
        Optional cut-off timestamp for time-bounding dependency resolution.
    registry_client:
        Optional NpmRegistryClient for resolving added dependencies.
    samples_root:
        Optional Datadog repo root for replay dependency resolution in evaluation mode.
    dest_dir:
        Optional directory for downloaded dependency tarballs.
    dep_stats:
        Optional dictionary to record dependency resolution counts
        (live, replayed, unresolvable, skipped).

    Returns
    -------
    list[Evidence]
        All findings, ordered by severity (highest first).
    """
    _sev_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }

    if baseline is not None:
        evidence = compare_releases(baseline, new)

        # Check added dependencies if registry_client and as_of are provided
        if registry_client is not None and as_of is not None:
            old_rc = (
                baseline.to_release_contents()
                if isinstance(baseline, ExtractionResult)
                else baseline
            )
            new_rc = (
                new.to_release_contents()
                if isinstance(new, ExtractionResult)
                else new
            )
            old_pkg = old_rc.package_json() or {}
            new_pkg = new_rc.package_json() or {}
            old_deps = set((old_pkg.get("dependencies") or {}).keys())
            new_deps = new_pkg.get("dependencies") or {}
            added_deps = [(k, str(v)) for k, v in new_deps.items() if k not in old_deps]

            if added_deps:
                from release_sentinel.dependency_resolver import resolve_added_dependency

                target_dir = dest_dir or (registry_client._cache_dir / "tarballs" / "eval_tmp")
                for dep_name, dep_spec in added_deps[:5]:
                    _, dep_evidence, status = resolve_added_dependency(
                        name=dep_name,
                        spec=dep_spec,
                        as_of=as_of,
                        registry_client=registry_client,
                        dest_dir=target_dir,
                        samples_root=samples_root,
                        config=config,
                        policy=policy,
                        analyze_fn=analyze_release,
                    )
                    evidence.extend(dep_evidence)
                    if dep_stats is not None:
                        dep_stats[status] = dep_stats.get(status, 0) + 1
                if dep_stats is not None and len(added_deps) > 5:
                    dep_stats["skipped"] = dep_stats.get("skipped", 0) + (len(added_deps) - 5)

        evidence.sort(key=lambda e: _sev_order[e.severity])
        return evidence

    # Full-scan (no-baseline) mode
    new_rc = new.to_release_contents() if isinstance(new, ExtractionResult) else new
    evidence = []
    new_pkg = new_rc.package_json()

    if new_pkg is None:
        evidence.append(
            Evidence(
                id="inspection_failed",
                severity=Severity.MEDIUM,
                file="package.json",
                explanation=(
                    "Could not read or parse package.json from the release. "
                    "Script and dependency comparisons are unavailable."
                ),
                legitimate_use_note=(
                    "This should never happen for a valid npm package. "
                    "May indicate a corrupted tarball."
                ),
            )
        )
        install_targets: set[str] = set()
    else:
        install_targets = _extract_install_script_targets(new_pkg)
        scripts: dict[str, str] = new_pkg.get("scripts", {}) or {}
        has_install_script = False

        for hook in _INSTALL_SCRIPTS:
            if hook in scripts:
                has_install_script = True
                cmd = str(scripts[hook])
                evidence.extend(_check_lifecycle_script_command(hook, cmd))
                parts = cmd.strip().split()
                if len(parts) >= 2 and parts[0] in {"node", "nodejs"}:
                    target = re.sub(r"^\./", "", parts[1])
                    if target not in new_rc.files:
                        evidence.append(
                            Evidence(
                                id="install_script_present",
                                severity=Severity.HIGH,
                                file="package.json",
                                explanation=(
                                    f"Lifecycle script '{hook}' references script target "
                                    f"'{target}' that is missing from the package."
                                ),
                                legitimate_use_note="Broken or incomplete package packaging.",
                            )
                        )

        # Check for CI workflow configuration files in full-scan mode
        for f_path in new_rc.files:
            f_norm = f_path.replace("\\", "/").lower()
            if _CI_WORKFLOW_FILE_RE.search(f_norm):
                evidence.append(
                    Evidence(
                        id="ci_write",
                        severity=Severity.MEDIUM,
                        file=f_path,
                        explanation=(
                            f"CI workflow configuration file present: {f_path!r}. "
                            "Modifying CI files can inject steps into automated build pipelines."
                        ),
                        legitimate_use_note=(
                            "Scaffolding tools and repositories legitimately include CI workflows."
                        ),
                    )
                )

        if has_install_script and not any(
            e.id in {"install_script_network", "install_script_executes", "install_script_present"}
            for e in evidence
        ):
            evidence.append(
                Evidence(
                    id="install_script_present",
                    severity=Severity.LOW,
                    file="package.json",
                    explanation="Package defines an install-time lifecycle script.",
                    legitimate_use_note="Many packages legitimately use install scripts.",
                )
            )

    evidence.extend(scan_full_release(new_rc, install_targets))

    if new_rc.capped and new_rc.cap_reason:
        evidence.append(
            Evidence(
                id="inspection_failed",
                severity=Severity.MEDIUM,
                file=None,
                explanation=f"Extraction of the release hit a soft cap: {new_rc.cap_reason}.",
                legitimate_use_note="Large packages may legitimately exceed extraction caps.",
            )
        )

    evidence.sort(key=lambda e: _sev_order[e.severity])
    return evidence


# ------------------------------------------------------------------
# Individual check functions
# ------------------------------------------------------------------


def _check_lifecycle_script_command(hook: str, cmd: str) -> list[Evidence]:
    """Inspect inline shell/lifecycle script commands for dangerous patterns."""
    evs: list[Evidence] = []
    # 1. Network download tools
    if re.search(
        r"\b(?:curl|wget|fetch|certutil|bitsadmin)\b|Invoke-WebRequest|\biwr\b|powershell.*download",
        cmd,
        re.I,
    ):
        evs.append(
            Evidence(
                id="install_script_network",
                severity=Severity.CRITICAL,
                file="package.json",
                explanation=(
                    f"Lifecycle script '{hook}' contains inline download command: "
                    f"{cmd!r}."
                ),
                legitimate_use_note=(
                    "Packages should not download arbitrary payloads during install."
                ),
            )
        )

    # 2. Piping to shells / interpreters or execution wrappers
    if re.search(
        r"\|\s*(?:sh|bash|zsh|dash|powershell|pwsh|cmd(?:\.exe)?)\b"
        r"|\b(?:bash|sh|powershell|cmd(?:\.exe)?|sudo)\b"
        r"|\bnode\s+(?:-e|--eval)\b|\bpython(?:\d)?\s+-c\b|rm\s+-rf\b",
        cmd,
        re.I,
    ):
        evs.append(
            Evidence(
                id="install_script_executes",
                severity=Severity.CRITICAL,
                file="package.json",
                explanation=(
                    f"Lifecycle script '{hook}' contains inline shell/process command: "
                    f"{cmd!r}."
                ),
                legitimate_use_note=(
                    "Lifecycle scripts should avoid arbitrary process invocation."
                ),
            )
        )

    # 3. Base64 decode pipes
    if re.search(
        r"base64\s+(?:-d|--decode)|certutil\s+-(?:decode|f|decodehex)"
        r"|\[System\.Convert\]::FromBase64String|\[Convert\]::FromBase64String|atob\(",
        cmd,
        re.I,
    ):
        if not any(e.id == "install_script_executes" for e in evs):
            evs.append(
                Evidence(
                    id="install_script_executes",
                    severity=Severity.CRITICAL,
                    file="package.json",
                    explanation=(
                        f"Lifecycle script '{hook}' contains base64 decode pipe / execution: "
                        f"{cmd!r}."
                    ),
                    legitimate_use_note=(
                        "Lifecycle scripts should not decode and execute base64 payloads."
                    ),
                )
            )
    return evs


def _diff_install_scripts(old_pkg: dict[str, Any], new_pkg: dict[str, Any]) -> list[Evidence]:
    """Detect added or changed install-time lifecycle scripts."""
    evidence: list[Evidence] = []
    old_scripts: dict[str, str] = old_pkg.get("scripts", {}) or {}
    new_scripts: dict[str, str] = new_pkg.get("scripts", {}) or {}

    for key in _INSTALL_SCRIPTS:
        old_val = old_scripts.get(key)
        new_val = new_scripts.get(key)

        if old_val is None and new_val is not None:
            evidence.append(
                Evidence(
                    id="install_script_added",
                    severity=Severity.HIGH,
                    file="package.json",
                    explanation=(
                        f"A new '{key}' lifecycle script was added: {new_val!r}. "
                        "Install-time scripts execute automatically during npm install "
                        "and are a common vector for supply-chain attacks."
                    ),
                    legitimate_use_note=(
                        "Many packages legitimately use install scripts to compile native "
                        "add-ons, build assets, or run post-install setup. "
                        "Review the script content carefully."
                    ),
                )
            )
            evidence.extend(_check_lifecycle_script_command(key, str(new_val)))
        elif old_val is not None and new_val is not None and old_val != new_val:
            evidence.append(
                Evidence(
                    id="install_script_changed",
                    severity=Severity.MEDIUM,
                    file="package.json",
                    explanation=(
                        f"The '{key}' lifecycle script changed.\n"
                        f"  Old: {old_val!r}\n"
                        f"  New: {new_val!r}"
                    ),
                    legitimate_use_note=(
                        "A changed install script may reflect a build-tool update or "
                        "a refactored setup step. Review what changed."
                    ),
                )
            )
            evidence.extend(_check_lifecycle_script_command(key, str(new_val)))

    return evidence


def _diff_dependencies(old_pkg: dict[str, Any], new_pkg: dict[str, Any]) -> list[Evidence]:
    """Detect added, removed, or version-changed dependencies."""
    evidence: list[Evidence] = []

    for dep_key in _DEP_KEYS:
        old_deps: dict[str, str] = old_pkg.get(dep_key, {}) or {}
        new_deps: dict[str, str] = new_pkg.get(dep_key, {}) or {}

        for pkg_name, new_ver in new_deps.items():
            if pkg_name not in old_deps:
                evidence.append(
                    Evidence(
                        id="dependency_added",
                        severity=Severity.LOW,
                        file="package.json",
                        explanation=(
                            f"New {dep_key} added: {pkg_name!r} @ {new_ver!r}. "
                            "This introduces a new transitive dependency tree."
                        ),
                        legitimate_use_note=(
                            "New dependencies are common in feature releases. "
                            "Check whether the added package is well-maintained."
                        ),
                    )
                )
            elif old_deps[pkg_name] != new_ver:
                evidence.append(
                    Evidence(
                        id="dependency_version_changed",
                        severity=Severity.INFO,
                        file="package.json",
                        explanation=(
                            f"{dep_key}[{pkg_name!r}] changed: "
                            f"{old_deps[pkg_name]!r} → {new_ver!r}"
                        ),
                        legitimate_use_note=(
                            "Version bumps are routine. Verify the new version of "
                            f"{pkg_name!r} is not itself compromised."
                        ),
                    )
                )

        for pkg_name in old_deps:
            if pkg_name not in new_deps:
                evidence.append(
                    Evidence(
                        id="dependency_removed",
                        severity=Severity.INFO,
                        file="package.json",
                        explanation=(
                            f"Dependency removed from {dep_key}: {pkg_name!r} "
                            f"(was {old_deps[pkg_name]!r})."
                        ),
                        legitimate_use_note=(
                            "Removing an unused dependency is good hygiene. "
                            "No security concern unless replaced by inline code."
                        ),
                    )
                )

    return evidence


def _diff_bin_entries(old_pkg: dict[str, Any], new_pkg: dict[str, Any]) -> list[Evidence]:
    """Detect added or changed bin entries."""
    evidence: list[Evidence] = []
    old_bin = _normalise_bin(old_pkg)
    new_bin = _normalise_bin(new_pkg)

    for bin_name, new_target in new_bin.items():
        if bin_name not in old_bin:
            evidence.append(
                Evidence(
                    id="bin_entry_added",
                    severity=Severity.MEDIUM,
                    file="package.json",
                    explanation=(
                        f"A new binary {bin_name!r} was registered pointing to "
                        f"{new_target!r}. Binaries are added to PATH and can be "
                        "invoked by other tools or lifecycle scripts."
                    ),
                    legitimate_use_note=(
                        "New CLIs are commonly added in minor releases. "
                        "Verify the target file is the expected script."
                    ),
                )
            )
        elif old_bin[bin_name] != new_target:
            evidence.append(
                Evidence(
                    id="bin_entry_changed",
                    severity=Severity.MEDIUM,
                    file="package.json",
                    explanation=(
                        f"Binary {bin_name!r} target changed: "
                        f"{old_bin[bin_name]!r} → {new_target!r}."
                    ),
                    legitimate_use_note=(
                        "May reflect a CLI refactor or entry-point rename. "
                        "Verify the new target file exists and is the expected script."
                    ),
                )
            )

    return evidence


def _diff_files(
    old: ReleaseContents,
    new: ReleaseContents,
    install_targets: set[str] | None = None,
) -> list[Evidence]:
    """Report new files using classification-aware logic.

    * Ignorable files (images, fonts, docs, source maps) → silent.
    * Notable new files (install-script targets, native binary, executable, dotfile, minified)
      → individual evidence.
    * All other new files → aggregated one-line summary (LOW).
    * Native binaries that are readable at the byte level → inspection limitation MEDIUM.
    """
    evidence: list[Evidence] = []
    old_file_map = set(old.files.keys())
    new_paths = sorted(p for p in new.files.keys() if p not in old_file_map)
    targets = install_targets or set()

    # Categorise new files
    category_counts: Counter[str] = Counter()
    for rel_path in new_paths:
        data = new.read_bytes(rel_path)
        cat = classify(data, rel_path)

        if rel_path in targets:
            evidence.append(
                Evidence(
                    id="notable_new_file",
                    severity=Severity.HIGH,
                    file=rel_path,
                    explanation=(
                        f"A new file referenced by an install script was added: {rel_path!r}. "
                        "Files executed during installation run automatically during npm install."
                    ),
                    legitimate_use_note=(
                        "Packages legitimately add install helper scripts. "
                        "Review the file content to verify it performs only expected setup."
                    ),
                )
            )
        # Check if the file itself is a CI workflow file
        rel_norm = rel_path.replace("\\", "/").lower()
        if _CI_WORKFLOW_FILE_RE.search(rel_norm):
            evidence.append(
                Evidence(
                    id="ci_write",
                    severity=Severity.MEDIUM,
                    file=rel_path,
                    explanation=(
                        f"A CI workflow configuration file was added: {rel_path!r}. "
                        "Modifying CI files can inject steps into automated build pipelines."
                    ),
                    legitimate_use_note=(
                        "Scaffolding tools and repositories legitimately include CI workflows."
                    ),
                )
            )
        elif is_ignorable(cat):
            category_counts[cat.value] += 1
            continue
        elif is_notable(cat):
            if cat == FileCategory.MINIFIED and is_exempt_path(rel_path, cat):
                category_counts[cat.value] += 1
            else:
                _emit_notable_file_evidence(evidence, rel_path, cat)
        else:
            category_counts[cat.value] += 1

        # Native binaries: report presence as a limitation (can't inspect internals)
        if cat == FileCategory.NATIVE_BINARY:
            evidence.append(
                Evidence(
                    id="native_binary_present",
                    severity=Severity.MEDIUM,
                    file=rel_path,
                    explanation=(
                        f"A new native binary was added: {rel_path!r}. "
                        "Native binaries (.node, .so, .dll, .dylib, .wasm) cannot be "
                        "inspected for malicious content by static analysis alone."
                    ),
                    legitimate_use_note=(
                        "Many packages include pre-built native add-ons for performance "
                        "(e.g. bcrypt, sharp, sqlite3). Verify the binary matches the "
                        "package's documented architecture and matches a trusted build."
                    ),
                )
            )

    # Aggregated summary of non-notable, non-ignorable new files
    non_notable_total = sum(category_counts.values())
    if non_notable_total > 0:
        summary_parts = [f"{v} {k}" for k, v in sorted(category_counts.items())]
        evidence.append(
            Evidence(
                id="new_files_summary",
                severity=Severity.LOW,
                file=None,
                explanation=(
                    f"{non_notable_total} new file(s) added: {', '.join(summary_parts)}. "
                    "Review the full file list if any additions seem unexpected."
                ),
                legitimate_use_note=(
                    "New source files, tests, and configuration are expected in most releases."
                ),
            )
        )

    return evidence


def _emit_notable_file_evidence(
    evidence: list[Evidence],
    rel_path: str,
    cat: FileCategory,
) -> None:
    """Append a MEDIUM evidence item for a single notable new file."""
    descriptions: dict[FileCategory, tuple[str, str]] = {
        FileCategory.NATIVE_BINARY: (
            "A new native binary file was added",
            "Pre-built native add-ons for performance (bcrypt, sharp, etc.)",
        ),
        FileCategory.EXECUTABLE: (
            "A new executable or shell script was added",
            "CLI tools and build helpers legitimately include shell scripts",
        ),
        FileCategory.DOTFILE: (
            "A new dotfile (hidden config) was added",
            "Config files like .eslintrc or .babelrc are common in packages",
        ),
        FileCategory.MINIFIED: (
            "A new minified JavaScript file was added",
            "Bundled packages routinely ship minified source for browser use",
        ),
    }
    desc, legit = descriptions.get(
        cat,
        (f"A new {cat.value} file was added", "May be a legitimate package file"),
    )
    evidence.append(
        Evidence(
            id="notable_new_file",
            severity=Severity.MEDIUM,
            file=rel_path,
            explanation=f"{desc}: {rel_path!r}.",
            legitimate_use_note=legit + ". Review the file content if unexpected.",
        )
    )


def _diff_sizes(old: ReleaseContents, new: ReleaseContents) -> list[Evidence]:
    """Report large size or file-count jumps."""
    evidence: list[Evidence] = []

    old_size = old.total_size or 1  # avoid division by zero
    new_size = new.total_size

    if new_size > 0 and (new_size / old_size) >= _SIZE_RATIO_THRESHOLD:
        evidence.append(
            Evidence(
                id="large_size_jump",
                severity=Severity.MEDIUM,
                file=None,
                explanation=(
                    f"Package size grew from {old_size / 1024:.1f} KB to "
                    f"{new_size / 1024:.1f} KB "
                    f"({new_size / old_size:.1f}× increase, threshold: {_SIZE_RATIO_THRESHOLD}×). "
                    "Large unexplained size increases may indicate bundled payloads."
                ),
                legitimate_use_note=(
                    "Large size jumps can occur when a package bundles its dependencies, "
                    "adds pre-built binaries, or includes new assets. "
                    "Check whether the increase is explained by the changelog."
                ),
            )
        )

    old_count = len(old.files)
    new_count = len(new.files)
    count_jump = new_count - old_count

    if count_jump > _FILE_COUNT_JUMP_THRESHOLD:
        evidence.append(
            Evidence(
                id="large_file_count_jump",
                severity=Severity.LOW,
                file=None,
                explanation=(
                    f"File count grew from {old_count} to {new_count} "
                    f"(+{count_jump} files, threshold: +{_FILE_COUNT_JUMP_THRESHOLD}). "
                    "A large number of new files may warrant review."
                ),
                legitimate_use_note=(
                    "New files are often added for new features, test fixtures, or "
                    "documentation. Check the new files list for unexpected content."
                ),
            )
        )

    return evidence


# ------------------------------------------------------------------
# Utilities
# ------------------------------------------------------------------


def _read_package_json(target: Path | ReleaseContents | None) -> dict[str, Any] | None:
    """Read and parse package.json from target.  Returns None on failure."""
    if target is None:
        return None
    if isinstance(target, ReleaseContents):
        return target.package_json()
    pkg_path = target / "package.json"
    try:
        text = pkg_path.read_text(encoding="utf-8")
        return json.loads(text)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Could not read package.json at %s: %s", pkg_path, exc)
        return None


def _normalise_bin(pkg: dict[str, Any]) -> dict[str, str]:
    """Normalise the ``bin`` field to always be a ``{name: path}`` dict."""
    raw = pkg.get("bin")
    if raw is None:
        return {}
    if isinstance(raw, str):
        pkg_name: str = pkg.get("name", "")
        return {pkg_name: raw}
    if isinstance(raw, dict):
        return {k: v for k, v in raw.items() if isinstance(v, str)}
    return {}


def _extract_install_script_targets(pkg: dict[str, Any]) -> set[str]:
    """Return the set of package-relative paths referenced by install scripts."""
    scripts: dict[str, str] = pkg.get("scripts", {}) or {}
    targets: set[str] = set()

    for hook in _INSTALL_SCRIPTS:
        cmd = scripts.get(hook, "")
        if not cmd:
            continue
        # Extract the first file argument from simple "node file.js" commands
        parts = cmd.strip().split()
        if len(parts) >= 2 and parts[0] in {"node", "nodejs"}:
            target = parts[1]
            # Normalise: strip leading ./
            target = re.sub(r"^\./", "", target)
            targets.add(target)

    return targets
