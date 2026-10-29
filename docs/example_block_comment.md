<!-- release-sentinel-pr-comment -->
## Release Sentinel Security Gate

**Verdict:** 🛑 **BLOCK** — 1 package(s) blocked out of 1 scanned.

### Flagged Packages

| Package | Version Change | Decision | Top Evidence | Why It Matters | Legitimate Explanation |
| :--- | :--- | :---: | :--- | :--- | :--- |
| `@​ahmedhfarag/ngx-perfect-scrollbar` | `20.0.19` → `20.0.20` | 🛑 BLOCK | `install_script_network` | Added lifecycle hook 'preinstall' downloads executable content from external network endpoints. | Precompiled platform binary downloads during installation. |

### Limitations & Scope

- JavaScript/TypeScript source scanned with static heuristics; dynamic evasion is possible.
- Every changed lockfile entry \(including transitive dependencies\) is scanned.

