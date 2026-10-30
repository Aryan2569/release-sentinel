# Changelog

All notable changes to Release Sentinel are documented in this file.
This project adheres to [Semantic Versioning](https://semver.org/).

---

## [0.5.0] / [v1.6] - 2026-10-24

### Added
- **Public Alpha Release**: Packaged for distribution via PyPI (`release-sentinel`) and GitHub Marketplace.
- **Lockfile Duplicate Handling**: Support for multi-version duplicates in npm `package-lock.json` v1/v2/v3, diffing nested package trees using semantic version ordering.
- **Baseline Selection & Maturity Rule**: Automated selection of clean baseline packages within the same major line, requiring $\ge 90$ days age and $\ge 5$ releases before diff-mode scanning.
- **Risk-Prioritized Package Scanning**: Scans added packages and install-hook modifications first; raised default package scan budget to 300 packages with fail-closed limitations on caps.
- **Noise Control (`comment-on`)**: Added PR commenting gate (`block`, `notable`, `warn`, `always`) cutting visible noise on pull requests by 31.7% while preserving all critical warnings.
- **GitHub Action Caching**: Composite action cache step for `~/.cache/release_sentinel` keyed on lockfile hash, dropping cached scan times from ~30s to ~2s.
- **Same-Version Lockfile Tampering Defenses**: Audits lockfile diffs for in-place metadata tampering on existing packages without version bumps (`lockfile_integrity_changed`, `lockfile_missing_integrity`, `lockfile_resolved_changed`).
- **Audit & Documentation**: Added `SECURITY.md`, `CONTRIBUTING.md`, reproducible benchmark instructions, and complete public documentation.

---

## [v1.5.1] - 2026-10-24

### Security & Hardening
- Implemented strict SSRF protection for resolved tarball URLs (HTTP scheme rejection, private IP rejection, allowlisted hosts).
- Implemented secret redaction for URLs containing embedded tokens or basic authentication credentials.
- Added git ref validation against dash-prefix flag injection and shell metacharacters.
- Added fail-closed WARN for non-registry tarball sources (git, file URLs).

---

## [v1.5] - 2026-10-24

### Added
- **Dual Policy Profiles**: Introduced low-noise `default` profile alongside the frozen research `strict` profile.
- Restructured install hooks to ignore `prepare` and `prepublish` for registry dependencies (executing only for repo roots / git dependencies).
- Refined `decode_and_execute` and dynamic code heuristics to avoid false positives on standard bundled libraries.

---

## [v1.4] - 2026-10-24

### Added
- **Diff-Mode Dependency Scanning**: Added dependencies resolved and diffed against previous version when available; full-scan reserved for brand-new single-version packages.
- Tightened brand-new package full-scan policy to require multiple corroborating heuristics for BLOCK verdicts.
- **Chunked Scanning**: Overlapping window chunking for files up to 25 MB hard ceiling, preventing evasion past initial file prefixes.
- **Frozen Research Baseline**: Malicious recall evaluated across 1,349 pairs and frozen as benchmark.

---

## [v1.3.1] - 2026-10-24

### Changed
- Refined install-script target parsing and bounded scan buffer limits.
- Demoted peer and development dependency changes to INFO level.

---

## [v1.3] - 2026-10-24

### Added
- Dependency-aware scanning: recursive scanning of newly introduced runtime dependencies.
- Added download and memory inspection budgets for transitive dependencies.

---

## [v1.2.1] - 2026-10-24

### Fixed
- Fixed regex backtracking in obfuscation scanners.
- Corrected baseline pairing for rapid patch releases.

---

## [v1.2] - 2026-10-24

### Added
- High-entropy string and encoded blob detection.
- Heuristics for process execution (`child_process`), network access, and credential harvesting (`.npmrc`, `.ssh`).

---

## [v1.1] - 2026-10-24

### Added
- Added package diffing engine comparing old vs new versions.
- Added detection for install-time script additions (`preinstall`, `install`, `postinstall`).

---

## [v1.0] - 2026-10-24

### Initial Release
- Initial implementation of in-memory safe tarball extraction (Rule 1, 2, 5, 7).
- Core policy engine and decision rules (`ALLOW`, `WARN`, `BLOCK`).
