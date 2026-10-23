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
import shlex
from collections import Counter
from importlib import resources
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
_REGISTRY_INSTALL_SCRIPTS = {
    "preinstall",
    "install",
    "postinstall",
}

_ALL_INSTALL_SCRIPTS = {
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "prepublish",
}

# Backward compatibility
_INSTALL_SCRIPTS = _REGISTRY_INSTALL_SCRIPTS

# Dependency manifest keys to compare
_DEP_KEYS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")

# Thresholds
_SIZE_RATIO_THRESHOLD = 2.0
_FILE_COUNT_JUMP_THRESHOLD = 50

_CI_WORKFLOW_FILE_RE = re.compile(
    r"^\.github/workflows/|^\.gitlab-ci\.ya?ml$|^\.circleci/|^\.?azure-pipelines(?:/|.*\.ya?ml$)"
)


def compare_releases(
    old: ExtractionResult | ReleaseContents,
    new: ExtractionResult | ReleaseContents,
    experimental_hollow: bool = False,
    is_registry_package: bool = True,
) -> list[Evidence]:
    """Compare two extracted releases and return evidence items.

    Parameters
    ----------
    old:
        Extraction result or in-memory ReleaseContents for the *from* release.
    new:
        Extraction result or in-memory ReleaseContents for the *to* release.
    experimental_hollow:
        Whether to evaluate experimental hollow package heuristics.
    is_registry_package:
        Whether this is a dependency installed from the public registry.
        If True (default), npm only runs preinstall, install, postinstall.
        If False (root project or git/file dependency), prepare and prepublish are included.

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
    active_install_scripts = (
        _REGISTRY_INSTALL_SCRIPTS if is_registry_package else _ALL_INSTALL_SCRIPTS
    )
    install_targets: set[str] = set()
    if new_pkg is not None:
        install_targets = _extract_install_script_targets(new_pkg, active_install_scripts)

    if old_pkg is not None and new_pkg is not None:
        evidence.extend(_diff_install_scripts(old_pkg, new_pkg, active_install_scripts))
        evidence.extend(_diff_dependencies(old_pkg, new_pkg))
        evidence.extend(_diff_bin_entries(old_pkg, new_pkg))
        if experimental_hollow:
            evidence.extend(_check_hollow_and_lookalike(old, new, old_pkg, new_pkg))

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
    experimental_hollow: bool = False,
    is_registry_package: bool = True,
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
    experimental_hollow:
        Whether to evaluate experimental hollow package heuristics.
    is_registry_package:
        Whether this is a dependency installed from the public registry.
        If True (default), npm only runs preinstall, install, postinstall.
        If False (root project or git/file dependency), prepare and prepublish are included.

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

    active_install_scripts = (
        _REGISTRY_INSTALL_SCRIPTS if is_registry_package else _ALL_INSTALL_SCRIPTS
    )

    if baseline is not None:
        pol_hollow = policy.experimental_hollow if policy is not None else False
        use_exp_hollow = experimental_hollow or pol_hollow
        evidence = compare_releases(
            baseline,
            new,
            experimental_hollow=use_exp_hollow,
            is_registry_package=is_registry_package,
        )

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

            # Outside lockfile mode, treat peerDependencies and optionalDependencies as installed
            old_deps = set((old_pkg.get("dependencies") or {}).keys())
            old_deps.update((old_pkg.get("optionalDependencies") or {}).keys())
            old_deps.update((old_pkg.get("peerDependencies") or {}).keys())

            new_deps_dict: dict[str, Any] = {}
            new_deps_dict.update(new_pkg.get("dependencies") or {})
            new_deps_dict.update(new_pkg.get("optionalDependencies") or {})
            new_deps_dict.update(new_pkg.get("peerDependencies") or {})

            added_deps = [(k, str(v)) for k, v in new_deps_dict.items() if k not in old_deps]

            if added_deps:
                from release_sentinel.dependency_resolver import resolve_added_dependency

                target_dir = dest_dir or (registry_client.cache_dir / "tarballs" / "deps")
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
        install_targets = _extract_install_script_targets(new_pkg, active_install_scripts)
        scripts: dict[str, str] = new_pkg.get("scripts", {}) or {}
        has_install_script = False

        for hook in active_install_scripts:
            if hook in scripts:
                has_install_script = True
                cmd = str(scripts[hook])
                evidence.extend(_check_lifecycle_script_command(hook, cmd))
                # Validate that targets referenced by install scripts exist in package
                hook_targets = _parse_command_targets(cmd, scripts)
                for target in hook_targets:
                    base_t = (
                        target[:-3]
                        if target.endswith(".js")
                        else (
                            target[:-4]
                            if target.endswith((".cjs", ".mjs"))
                            else target
                        )
                    )
                    exists = any(
                        cand in new_rc.files
                        for cand in (
                            target,
                            base_t,
                            f"{base_t}.js",
                            f"{base_t}.cjs",
                            f"{base_t}.mjs",
                        )
                    )
                    if (
                        not exists
                        and not target.startswith("-")
                        and target
                        not in {"node", "nodejs", "npm", "yarn", "pnpm", "sh", "bash", "zsh"}
                    ):
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
                        break

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
    # 1. Network download tools (narrowed fetch to URL/function call to avoid
    # false alarms on git fetch or fetch-assets)
    if re.search(
        r"\b(?:curl|wget|certutil|bitsadmin)\b|\bfetch\s*(?:\(|\s+https?://)|Invoke-WebRequest|\biwr\b|powershell.*download",
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
    # rm -rf is narrowed to dangerous targets (/, ~, $HOME, %USERPROFILE%, .., bare *, or absolute)
    # sudo is narrowed to explicit command invocations
    if re.search(
        r"\|\s*(?:sh|bash|zsh|dash|powershell|pwsh|cmd(?:\.exe)?)\b"
        r"|\b(?:bash|sh|zsh|dash)\s+-c\b"
        r"|\bpowershell(?:\.exe)?\s+(?:-e|-enc|-encodedcommand)\b"
        r"|\bcmd(?:\.exe)?\s+/c\b"
        r"|\bsudo\s+[a-zA-Z0-9_\-\./]"
        r"|\bnode\s+(?:-e|--eval)\b|\bpython(?:\d)?\s+-c\b"
        r"|rm\s+(?:-[a-zA-Z]*\s+)*(?:--no-preserve-root\b|-(?:rf|fr)\s+(?:--no-preserve-root\s+)?(?:/|~|\$HOME|\$\{HOME\}|%USERPROFILE%|%HOMEPATH%|\.\.|\*(?:\s|$|;)|[a-zA-Z]:[\\/]|/[a-zA-Z0-9_]))",
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


def _diff_install_scripts(
    old_pkg: dict[str, Any],
    new_pkg: dict[str, Any],
    install_scripts: set[str] | None = None,
) -> list[Evidence]:
    """Detect added or changed install-time lifecycle scripts."""
    if install_scripts is None:
        install_scripts = _REGISTRY_INSTALL_SCRIPTS
    evidence: list[Evidence] = []
    old_scripts: dict[str, str] = old_pkg.get("scripts", {}) or {}
    new_scripts: dict[str, str] = new_pkg.get("scripts", {}) or {}

    for key in install_scripts:
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
                if dep_key in ("dependencies", "optionalDependencies"):
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
                elif dep_key == "devDependencies":
                    evidence.append(
                        Evidence(
                            id="dev_dependency_added",
                            severity=Severity.INFO,
                            file="package.json",
                            explanation=(
                                f"New devDependency added: {pkg_name!r} @ {new_ver!r}."
                            ),
                            legitimate_use_note=(
                                "New devDependencies are common in development updates."
                            ),
                        )
                    )
                elif dep_key == "peerDependencies":
                    evidence.append(
                        Evidence(
                            id="peer_dependency_added",
                            severity=Severity.INFO,
                            file="package.json",
                            explanation=(
                                f"New peerDependency added: {pkg_name!r} @ {new_ver!r}."
                            ),
                            legitimate_use_note=(
                                "Peer dependencies declare host environment requirements."
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


_METADATA_BASENAME_RE = re.compile(
    r"^(package\.json|(?:readme|changelog|license|licence|\.npmignore|\.gitignore)(?:\.[\w.-]+)?)$",
    re.I,
)

_LOOKALIKE_PREFIXES = ("node-",)
_LOOKALIKE_SUFFIXES = ("-cli", "-core", "-node", "-js", "-ts")
_HOMOGLYPH_MAP = {"0": "o", "1": "l", "vv": "w", "rn": "m"}

_TOP_PACKAGES_CACHE: set[str] | None = None


def _get_top_packages() -> set[str]:
    global _TOP_PACKAGES_CACHE
    if _TOP_PACKAGES_CACHE is None:
        try:
            ref = resources.files("release_sentinel.data").joinpath("top_npm_packages.json")
            content = ref.read_text(encoding="utf-8")
            _TOP_PACKAGES_CACHE = set(json.loads(content))
        except Exception as exc:
            raise RuntimeError(f"Failed to load bundled top_npm_packages.json: {exc}") from exc
    return _TOP_PACKAGES_CACHE


def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def is_lookalike_dependency(
    name: str,
    top_set: set[str] | None = None,
    pkg_name: str = "",
) -> tuple[bool, str | None, str | None]:
    """Check if dependency name is a lookalike/typosquat of a popular package."""
    top_packages = top_set if top_set is not None else _get_top_packages()
    name_clean = name.lower().strip()
    if name_clean in top_packages:
        return False, None, None

    # Exemption: package depending on itself or related sub-packages in same scope
    if pkg_name:
        p_clean = pkg_name.lower().strip()
        if name_clean == p_clean:
            return False, None, None
        if name_clean.startswith("@") and p_clean.startswith("@"):
            if name_clean.split("/")[0] == p_clean.split("/")[0]:
                return False, None, None

    # Exemption: standard @types/ definitions for legitimate packages
    if name_clean.startswith("@types/"):
        base = name_clean[len("@types/") :]
        if base in top_packages:
            return False, None, None

    norm = re.sub(r"[-_.]", "", name_clean)

    # General npm convention affixes (e.g. "node-", "-cli", "-core", "-js", "-ts")
    candidates = {name_clean}
    for pfx in _LOOKALIKE_PREFIXES:
        if name_clean.startswith(pfx):
            candidates.add(name_clean[len(pfx) :])
    for sfx in _LOOKALIKE_SUFFIXES:
        if name_clean.endswith(sfx):
            candidates.add(name_clean[: -len(sfx)])
    for pfx in _LOOKALIKE_PREFIXES:
        for sfx in _LOOKALIKE_SUFFIXES:
            if name_clean.startswith(pfx) and name_clean.endswith(sfx):
                candidates.add(name_clean[len(pfx) : -len(sfx)])

    for cand in candidates:
        if cand != name_clean and cand in top_packages:
            return True, cand, f"npm_convention_affix_of_{cand}"

    # Homoglyphs
    homo = name_clean
    for k, v in _HOMOGLYPH_MAP.items():
        homo = homo.replace(k, v)
    if homo != name_clean and homo in top_packages:
        return True, homo, f"homoglyph_of_{homo}"

    # Single edit distance only (levenshtein <= 1)
    for pop in top_packages:
        pop_clean = pop.lower()
        pop_norm = re.sub(r"[-_.]", "", pop_clean)

        if norm == pop_norm and len(norm) >= 4:
            return True, pop, f"separator_variant_of_{pop}"

        if abs(len(name_clean) - len(pop_clean)) <= 1:
            dist = _levenshtein(name_clean, pop_clean)
            if dist == 1 and len(pop_clean) >= 4:
                return True, pop, f"edit_distance_1_of_{pop}"

    return False, None, None


def _check_hollow_and_lookalike(
    old: ReleaseContents,
    new: ReleaseContents,
    old_pkg: dict[str, Any],
    new_pkg: dict[str, Any],
) -> list[Evidence]:
    """Detect hollow releases adding dependencies and lookalike dependency names."""
    evidence: list[Evidence] = []
    old_deps = set((old_pkg.get("dependencies") or {}).keys())
    new_deps = set((new_pkg.get("dependencies") or {}).keys())
    added_direct = new_deps - old_deps

    if not added_direct:
        return evidence

    pkg_name = str(new_pkg.get("name") or "")

    # Check for lookalike dependency name
    top_packages = _get_top_packages()
    for dep_name in sorted(added_direct):
        matched, target_pkg, reason = is_lookalike_dependency(
            dep_name, top_packages, pkg_name=pkg_name
        )
        if matched:
            evidence.append(
                Evidence(
                    id="lookalike_dependency_name",
                    severity=Severity.MEDIUM,
                    file="package.json",
                    explanation=(
                        f"Added direct runtime dependency {dep_name!r} is a lookalike / variant of "
                        f"popular package {target_pkg!r} ({reason})."
                    ),
                    legitimate_use_note=(
                        "Verify whether this is an intended new package or an accidental typosquat."
                    ),
                )
            )

    # Check if this release is hollow (metadata-only update: zero code files changed)
    has_non_meta_diff = False
    for fn, new_bytes in new.files.items():
        base = Path(fn).name
        if not _METADATA_BASENAME_RE.match(base):
            if fn not in old.files or old.files[fn] != new_bytes:
                has_non_meta_diff = True
                break

    if not has_non_meta_diff:
        deps_sample = ", ".join(sorted(added_direct)[:3])
        evidence.append(
            Evidence(
                id="hollow_dependency_injection",
                severity=Severity.MEDIUM,
                file="package.json",
                explanation=(
                    "Release is hollow: zero non-metadata files were added or modified, but "
                    f"{len(added_direct)} direct runtime dependency(ies) added ({deps_sample}). "
                    "This pattern delivers payloads through transitive dependencies while "
                    "keeping the package diff clean."
                ),
                legitimate_use_note=(
                    "Packages rarely add new runtime dependencies without writing code using them."
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
        rel_norm = rel_path.replace("\\", "/").lower()

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
        elif _CI_WORKFLOW_FILE_RE.search(rel_norm):
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


def _parse_command_targets(
    cmd: str,
    scripts: dict[str, Any],
    depth: int = 0,
    visited: set[str] | None = None,
) -> set[str]:
    """Extract file targets referenced by a shell command or package script.

    Handles:
    - Script indirection (npm run x, yarn x, pnpm run x) up to depth 3 with cycle protection.
    - node / nodejs with leading flags (--no-warnings, -r/--require <file>, etc.).
    - shell invocations (sh/bash/zsh/dash <file>).
    - direct executable invocation (./script.sh).
    - python invocations (python/python3/py <file>).
    - extensionless targets (generates candidate .js, .cjs, .mjs paths).
    """
    if depth > 3 or not cmd:
        return set()
    if visited is None:
        visited = set()

    targets: set[str] = set()

    # Split on command chaining delimiters (&&, ||, ;, |, &)
    subcmds = re.split(r"(?:&&|\|\||;|\||&)", cmd)
    for sub in subcmds:
        sub = sub.strip()
        if not sub:
            continue
        try:
            tokens = shlex.split(sub)
        except Exception:
            tokens = sub.split()
        if not tokens:
            continue

        cmd_name = tokens[0]

        # Script indirection: npm run x, yarn x, pnpm run x
        if cmd_name in {"npm", "pnpm", "yarn"}:
            script_name = None
            if len(tokens) >= 3 and tokens[1] in {"run", "run-script"}:
                script_name = tokens[2]
            elif len(tokens) >= 2 and tokens[1] not in {
                "run",
                "run-script",
                "install",
                "test",
            }:
                script_name = tokens[1]
            if (
                script_name
                and script_name in scripts
                and script_name not in visited
                and isinstance(scripts[script_name], str)
            ):
                targets |= _parse_command_targets(
                    scripts[script_name],
                    scripts,
                    depth + 1,
                    visited | {script_name},
                )
            continue

        # Direct executable ./script.sh
        if cmd_name.startswith("./"):
            t = re.sub(r"^\./", "", cmd_name)
            if t:
                targets.add(t)
            continue

        # Shell invocations: sh/bash/zsh/dash <file>
        if cmd_name in {"sh", "bash", "zsh", "dash"}:
            for tok in tokens[1:]:
                if not tok.startswith("-"):
                    t = re.sub(r"^\./", "", tok)
                    if t:
                        targets.add(t)
                    break
            continue

        # Python invocations: python <file>
        if re.match(r"^python[23]?$", cmd_name) or cmd_name == "py":
            for tok in tokens[1:]:
                if not tok.startswith("-"):
                    t = re.sub(r"^\./", "", tok)
                    if t:
                        targets.add(t)
                    break
            continue

        # Node invocations: node with leading flags
        if cmd_name in {"node", "nodejs"}:
            idx = 1
            while idx < len(tokens):
                tok = tokens[idx]
                if tok in {"-r", "--require", "--loader", "--import"}:
                    if idx + 1 < len(tokens):
                        req_tok = tokens[idx + 1]
                        if not req_tok.startswith("-"):
                            t = re.sub(r"^\./", "", req_tok)
                            if t:
                                targets.add(t)
                        idx += 2
                        continue
                elif tok.startswith(("-r=", "--require=", "--loader=", "--import=")):
                    req_tok = tok.split("=", 1)[1]
                    t = re.sub(r"^\./", "", req_tok)
                    if t:
                        targets.add(t)
                elif tok.startswith("-"):
                    pass
                else:
                    # First non-flag token is the target
                    t = re.sub(r"^\./", "", tok)
                    if t:
                        targets.add(t)
                    break
                idx += 1

    # Expand extensionless targets to candidate extensions (.js, .cjs, .mjs)
    expanded: set[str] = set()
    for t in targets:
        expanded.add(t)
        if "." not in Path(t).name:
            expanded.add(f"{t}.js")
            expanded.add(f"{t}.cjs")
            expanded.add(f"{t}.mjs")

    return expanded


def _extract_install_script_targets(
    pkg: dict[str, Any],
    install_scripts: set[str] | None = None,
) -> set[str]:
    """Return the set of package-relative paths referenced by install scripts."""
    scripts: dict[str, str] = pkg.get("scripts", {}) or {}
    if not isinstance(scripts, dict):
        return set()

    if install_scripts is None:
        install_scripts = _REGISTRY_INSTALL_SCRIPTS

    targets: set[str] = set()
    for hook in install_scripts:
        cmd = scripts.get(hook)
        if cmd and isinstance(cmd, str):
            targets |= _parse_command_targets(cmd, scripts)
    return targets
