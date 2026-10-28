<!-- release-sentinel-pr-comment -->
## Release Sentinel Security Gate

**Verdict:** ⚠️ **WARN** — 1 package(s) flagged with warnings out of 1 scanned.

### Flagged Packages

| Package | Version Change | Decision | Top Evidence | Why It Matters | Legitimate Explanation |
| :--- | :--- | :---: | :--- | :--- | :--- |
| `axios` | `1.14.0` → `1.14.1` | ⚠️ WARN | `install_script_present` | [dep: plain-crypto-js@​4.2.1] Lifecycle script 'postinstall' references script target 'setup.js' that is missing from the package. | Broken or incomplete package packaging. |

### Limitations & Scope

- JavaScript/TypeScript source scanned with static heuristics; dynamic evasion is possible.
- Every changed lockfile entry (including transitive dependencies) is scanned.

