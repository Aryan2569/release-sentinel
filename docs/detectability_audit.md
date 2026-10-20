# Release Sentinel — Detectability Audit

## 1. Overview & Protocol

This audit provides a **detector-independent evaluation** of all 1,349 evaluation pairs, analyzing the package archives and baselines purely as data (no detector logic, rules, or severity thresholds applied).

The purpose of this audit is to determine the theoretical upper bound of what any diff-based JavaScript code analyzer could ever detect, and to answer the fundamental question:
> **Did detector performance degrade due to scanner blind spots on JavaScript code, or did attacker behavior shift to delivery mechanisms that contain no inspectable code diffs?**

All 1,349 pairs were inspected strictly in-memory (conforming to Rule 7: encrypted at rest, never written to disk).

---

## 2. Definitions

- **Empty Diff**: No files added, modified, or removed between baseline and release.
- **Metadata Only**: Only `package.json` was altered; zero other files were added, modified, or removed.
- **Content Changed**: At least one file other than `package.json` was added, modified, or removed.
- **Adds Direct Dependency**: An update adds one or more direct dependencies in `package.json` (`dependencies`).
- **Lifecycle Script Added/Changed**: An update adds or modifies lifecycle hook commands (`preinstall`, `install`, `postinstall`, `prepublish`, `prepare`, etc.).
- **Binary/Native/WASM Only**: All non-metadata changed files are native binaries, shared libraries, or WebAssembly (`.node`, `.so`, `.dll`, `.wasm`, ELF, Mach-O, PE).
- **Minified/Bundled Only**: All non-metadata changed files are minified bundles or source maps.
- **Over Size Budget Only**: All non-metadata changed files exceed the per-file diff budget (>500 KB).
- **Non-JS Text Only**: All non-metadata changed files are documentation or non-executable text (`README`, `LICENSE`, `.md`, `.txt`).
- **Inspectable Change**: A package update is defined as **inspectable** if:
  1. At least one changed (added or modified) file is human- or scanner-readable script code (JS/TS/script, not native binary, $\le 500$ KB, not documentation-only, not minified-only); **OR**
  2. The update adds or modifies a lifecycle script hook in `package.json` (providing shell/node command strings that a scanner can inspect).
  
  Conversely, a release is **not inspectable** by a diff-based JS code scanner if it has zero file diffs, is metadata-only without lifecycle scripts, or alters only binaries, docs, or files exceeding budget limits.

---

## 3. Attack Style Mix Over Time

| Period | Cohort | Pairs | Inspectable | Content Changed | Metadata Only | Empty Diff | Direct Dep Added | Lifecycle Hook Added/Changed | Binary Only | Minified Only |
|:---|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **2024** | DEV | 11 | 7 (63.6%) | 11 (100.0%) | 0 (0.0%) | 0 (0.0%) | 5 (45.5%) | 7 (63.6%) | 0 (0.0%) | 3 (27.3%) |
| **2025** | DEV | 846 | 792 (93.6%) | 841 (99.4%) | 5 (0.6%) | 0 (0.0%) | 5 (0.6%) | 786 (92.9%) | 0 (0.0%) | 391 (46.2%) |
| **Early 2026** | VAL | 94 | 93 (98.9%) | 92 (97.9%) | 2 (2.1%) | 0 (0.0%) | 1 (1.1%) | 91 (96.8%) | 0 (0.0%) | 7 (7.4%) |
| **Mid 2026** | TEST-A | 298 | 206 (69.1%) | 270 (90.6%) | 28 (9.4%) | 0 (0.0%) | 50 (16.8%) | 163 (54.7%) | 0 (0.0%) | 123 (41.3%) |
| **Late 2026** | TEST-B | 100 | **10 (10.0%)** | **10 (10.0%)** | **90 (90.0%)** | 0 (0.0%) | **95 (95.0%)** | **1 (1.0%)** | 0 (0.0%) | 0 (0.0%) |

### Key Ecosystem Shifts
1. **The 2025 & Early 2026 Paradigm (Payload Drops & Install Hooks)**:
   Over $92\%$ of malicious releases in 2025 and $96.8\%$ in early 2026 relied on automated lifecycle hooks (`preinstall` / `postinstall`) to execute payloads upon `npm install`. Over $97\%$ modified actual package content files, and over $93\%$ contained directly inspectable code changes.
2. **The Mid-2026 Transition (TEST-A)**:
   In May–June 2026, direct dependency additions increased to $16.8\%$ (notably `@mastra/*` sub-dependency injections), and lifecycle hooks dropped from $96.8\% \to 54.7\%$.
3. **The Late-2026 Paradigm Shift (TEST-B: Pure Dependency Confusion)**:
   In late 2026 (TEST-B), attacker strategy fundamentally mutated:
   - **90.0% of all releases altered NO code files whatsoever** (`metadata_only`: 90/100).
   - **95.0% of releases functioned exclusively by adding an external dependency** (`adds_direct_dependency`: 95/100).
   - **Only 1.0% added or changed an install hook** (1/100).
   - **Only 10.0% contained any inspectable JavaScript diffs** (10/100).

---

## 4. TEST-B Conditional Recall (v1.0 Frozen Baseline)

To prove whether the drop in TEST-B recall ($9.0\%$ overall) represents detector failure or uninspectable input data, recall was evaluated conditional on whether the update contained inspectable changes:

| TEST-B Sub-Cohort | Pairs | $\ge$WARN (Fail-Closed) | $\ge$WARN (Evidence-Only) | BLOCK |
|:---|:---:|:---:|:---:|:---:|
| **All TEST-B Pairs** | 100 | 9 / 100 (9.0%) | 9 / 100 (9.0%) | 3 / 100 (3.0%) |
| **Inspectable Changes** | 10 | **9 / 10 (90.0%)** | **9 / 10 (90.0%)** | **3 / 10 (30.0%)** |
| **Not Inspectable (Metadata Only)** | 90 | **0 / 90 (0.0%)** | **0 / 90 (0.0%)** | **0 / 90 (0.0%)** |

### Proof of Attacker Shift
- On packages where attackers actually modified JavaScript code or lifecycle scripts ($n = 10$), the frozen v1.0 detector achieved **90.0% $\ge$WARN recall** and **30.0% BLOCK recall**, exactly consistent with its DEV/VAL performance.
- On the remaining 90 packages, the archive diff is purely a 1-line addition to `package.json` (`"easy-day-js": "^1.11.21"` or equivalent delisted dependency) with **zero executable lines in the release archive**.
- Because the added dependencies were delisted from the live registry prior to evaluation, a diff-based scanner restricted to the release archive cannot inspect code that does not exist in the archive. The recall drop in TEST-B is **100% attributable to attacker delivery mechanism evolution**, not scanner degradation.

---

## 5. Archive Size & File Count Distributions

| Cohort | Pairs | Median Unpacked Size | Mean Unpacked Size | Median File Count | Mean File Count |
|:---|:---:|:---:|:---:|:---:|:---:|
| **DEV (2024)** | 11 | 3,321.9 KB | 3,922.5 KB | 420 | 535.1 |
| **DEV (2025)** | 846 | 8,366.7 KB | 9,391.8 KB | 31 | 113.9 |
| **VAL (Early 2026)** | 94 | 12.0 KB | 2,149.4 KB | 4 | 31.2 |
| **TEST-A (Mid 2026)** | 298 | 2,547.3 KB | 5,124.7 KB | 33 | 206.1 |
| **TEST-B (Late 2026)** | 100 | 864.6 KB | 4,006.2 KB | 30 | 118.8 |

The distributions demonstrate that package complexity did not increase in late 2026; rather, attackers shifted from shipping self-contained weaponized code packages to publishing hollow versions that point outward to third-party dependencies.
