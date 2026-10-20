# Release Sentinel -- Benign Smoke Test Results

## 1. Decision Distribution

- **Total Pairs Evaluated**: 100
- **ALLOW**: 96 (96.0%)
- **WARN**: 4 (4.0%)
- **BLOCK**: 0 (0.0%)
- **Skipped (Large Tarball)**: 0 (0.0%)
- **Alert Burden (WARN + BLOCK)**: **4.0 alerts per 100 updates**

## 2. Top 10 Evidence Types

| Evidence Type | Total Frequency | Sole Evidence for WARN/BLOCK |
|:---|:---:|:---:|
| `dependency_version_changed` | 48 | 0 |
| `dependency_added` | 14 | 0 |
| `dependency_removed` | 11 | 0 |
| `new_files_summary` | 8 | 0 |
| `hardcoded_url` | 3 | 0 |
| `high_entropy_string` | 2 | 1 |
| `install_script_present` | 1 | 0 |
| `install_script_added` | 1 | 0 |
| `long_encoded_blob` | 1 | 1 |

## 3. Every BLOCK Decision

*(No releases were blocked.)*

## 4. The 3 Noisiest Packages

| Package | Alerts (WARN/BLOCK) | Total Evidence Items | Most Common Signals |
|:---|:---:|:---:|:---|
| `sharp` | 1 | 10 | `dependency_version_changed` (5), `dependency_added` (2), `new_files_summary` (1) |
| `superagent` | 1 | 4 | `dependency_version_changed` (3), `install_script_added` (1) |
| `nanoid` | 1 | 2 | `new_files_summary` (1), `high_entropy_string` (1) |

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
