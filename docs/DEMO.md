# Release Sentinel: Interactive Demo Guide

This guide describes how to run the interactive demonstration of Release Sentinel on the real-world compromised release of **`axios` (1.14.0 → 1.14.1)** from the Datadog malicious software dataset.

---

## 1. Safety Guarantees During Demo

- **Never Executes Package Code (Rule 1):** The demo operates entirely via static AST/regex analysis and structural inspection. No scripts or modules are imported or run.
- **In-Memory Decryption (Rule 2 & 7):** The encrypted sample archive is decrypted with password `infected` directly into memory buffers. The malicious payload is **never written to disk**.

---

## 2. Prerequisites

The demo requires access to the encrypted sample corpus:
- By default, Release Sentinel looks in `C:\rs-data\datadog` on this system.
- Or set the environment variable:
  ```powershell
  $env:RS_SAMPLES_ROOT = "C:\rs-data\datadog"
  ```

---

## 3. Exact Demo Command

Run either via the installed CLI entry point `sentinel`:

```bash
sentinel demo --pair axios 1.14.0 1.14.1
```

Or via python module execution:

```bash
python -m release_sentinel demo --pair axios 1.14.0 1.14.1
```

To output rich terminal formatting instead of markdown:

```bash
sentinel demo --pair axios 1.14.0 1.14.1 --format text
```

To output raw machine-readable JSON:

```bash
sentinel demo --pair axios 1.14.0 1.14.1 --format json
```

---

## 4. Expected Output (Markdown)

```markdown
## ⚠️ Release Sentinel: WARN

> **Summary**: WARN: 2 evidence item(s) (1 high, 1 low) for axios (1.14.0 -> 1.14.1)

| Detail | Value |
|---|---|
| **Package** | `axios` |
| **Old Version** | `1.14.0` (2026-10-22) |
| **New Version** | `1.14.1` (2026-10-22) |
| **Decision** | **WARN** |
| **As-Of** | `2026-10-22T21:43:03.072841+00:00` |

### Dependencies & Binaries Config
| Severity | ID | File | Explanation |
|---|---|---|---|
| **LOW** | `dependency_added` | `package.json` | New dependencies added: 'plain-crypto-js' @ '^4.2.1'. This introduces a new transitive dependency tree. |

### Other Findings
| Severity | ID | File | Explanation |
|---|---|---|---|
| **HIGH** | `install_script_present` | `node_modules/plain-crypto-js/package.json` | [dep: plain-crypto-js@4.2.1 replayed_from_dataset] Lifecycle script 'postinstall' references script target 'setup.js' that is missing from the package. |

<details>
<summary><strong>Limitations & Scope</strong></summary>

- JavaScript/TypeScript source is scanned with regex heuristics, not fully parsed — obfuscated code may evade detection.
- Transitive (indirect) dependencies are not analysed.
- Known vulnerability databases (OSV, NVD, npm advisory) are not consulted.
- Binary files (.node, .wasm, compiled extensions) cannot be inspected for malicious content.
- 'No evidence found' does not mean 'safe' — it means nothing suspicious was detected by these specific checks at this point in time.
</details>
```

---

## 5. Screen Recording Script & Narration

When recording a demo or walkthrough:

1. **Introduction (0:00 - 0:15):**
   > *"Release Sentinel is a time-aware static security gate for npm dependency updates. Here we demonstrate analyzing a known compromised release: axios 1.14.0 upgrading to 1.14.1."*

2. **Run Command (0:15 - 0:30):**
   > Run: `sentinel demo --pair axios 1.14.0 1.14.1`
   > *"Release Sentinel decrypts the sample directly in memory without writing it to disk and diffs it against the clean 1.14.0 baseline."*

3. **Explain Decision (0:30 - 0:50):**
   > Highlight the `WARN` verdict and evidence:
   > - `dependency_added`: Axios added a new runtime dependency `plain-crypto-js`.
   > - `install_script_present`: The dependency contains a suspicious `postinstall` script pointing to a missing script target (`setup.js`).
   > *"Notice that Release Sentinel flagged this attack immediately without executing a single line of untrusted JavaScript code."*

4. **Lockfile Gate (0:50 - 1:10):**
   > *"In CI, `sentinel check` performs this same inspection across entire lockfile diffs in pull requests, posting automated markdown summaries directly into GitHub PR comments."*
