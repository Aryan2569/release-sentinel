# Release Sentinel -- Benign Smoke Test Results

## 1. Decision Distribution

- **Total Pairs Evaluated**: 200
- **ALLOW**: 187 (93.5%)
- **WARN**: 13 (6.5%)
- **BLOCK**: 0 (0.0%)
- **Skipped (Large Tarball)**: 0 (0.0%)
- **Alert Burden (WARN + BLOCK)**: **6.5 alerts per 100 updates**

## 2. Top 10 Evidence Types

| Evidence Type | Total Frequency | Sole Evidence for WARN/BLOCK |
|:---|:---:|:---:|
| `dependency_version_changed` | 85 | 0 |
| `dependency_added` | 32 | 0 |
| `dependency_removed` | 21 | 0 |
| `new_files_summary` | 19 | 0 |
| `high_entropy_string` | 6 | 1 |
| `hardcoded_url` | 4 | 0 |
| `install_script_changed` | 4 | 1 |
| `long_encoded_blob` | 3 | 1 |
| `notable_new_file` | 2 | 0 |
| `install_script_present` | 1 | 0 |

## 3. Every BLOCK Decision

*(No releases were blocked.)*

## 4. The 3 Noisiest Packages

| Package | Alerts (WARN/BLOCK) | Total Evidence Items | Most Common Signals |
|:---|:---:|:---:|:---|
| `sharp` | 5 | 31 | `dependency_version_changed` (10), `dependency_added` (7), `dependency_removed` (5) |
| `rxjs` | 2 | 7 | `new_files_summary` (2), `dependency_added` (1), `dependency_version_changed` (1) |
| `cheerio` | 1 | 28 | `dependency_version_changed` (10), `dependency_added` (7), `dependency_removed` (4) |

## 5. Suggested Rule & Policy Changes (Measurement Only)

1. **Allowlist Known Bundled / Minified Assets**:
   - `long_encoded_blob` and `high_entropy_string` fire frequently on source maps, base64 fixtures, or bundled/minified JS. Tuning entropy thresholds or exempting known test fixture directories would significantly cut noise.
2. **Refine `process_exec` and `network_access` Patterns**:
   - In utility packages like `lodash`, `yargs`, or `commander`, static references to `child_process` in helper/debug scripts trigger WARN. Require corroboration with lifecycle scripts (`install_script_added`) before escalating.
3. **De-duplicate / Aggregate Informational Signals**:
   - `dependency_added`, `dependency_version_changed`, and `new_files_summary` should remain LOW and never by themselves trigger a warning.
4. **Install Hook Specificity**:
   - Packages like `bcrypt` legitimately use `install` for node-pre-gyp. Differentiate standard build tools (`node-pre-gyp`, `node-gyp rebuild`) from arbitrary curl/bash commands.

## 6. Items of Uncertainty

- **Concurrency in Package Release Cadences**: Some packages (e.g. `react`, `express`) backport patches across minor lines simultaneously. The time-filtered `as_of` ensures reproducibility, but release pairs must track within-major branches.
- **Tarball Unpacked Size vs Gzip Size**: Content-Length is not always sent by npm registry on HEAD requests; streaming tarball size validation safely bounds memory usage.
