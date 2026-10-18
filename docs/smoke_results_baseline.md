# Release Sentinel -- Benign Smoke Test Results

## 1. Decision Distribution

- **Total Pairs Evaluated**: 100
- **ALLOW**: 33 (33.0%)
- **WARN**: 61 (61.0%)
- **BLOCK**: 6 (6.0%)
- **Skipped (Large Tarball)**: 0 (0.0%)
- **Alert Burden (WARN + BLOCK)**: **67.0 alerts per 100 updates**

## 2. Top 10 Evidence Types

| Evidence Type | Total Frequency | Sole Evidence for WARN/BLOCK |
|:---|:---:|:---:|
| `dependency_version_changed` | 38 | 14 |
| `high_entropy_string` | 32 | 0 |
| `long_encoded_blob` | 32 | 0 |
| `process_exec` | 23 | 1 |
| `new_files_summary` | 19 | 0 |
| `hardcoded_url` | 18 | 0 |
| `dependency_added` | 17 | 1 |
| `network_access` | 12 | 0 |
| `dependency_removed` | 11 | 1 |
| `hardcoded_ip` | 6 | 0 |

## 3. Every BLOCK Decision

| Package | Upgrade | Evidence Types Driving Block |
|:---|:---|:---|
| `axios` | `1.17.0` -> `1.18.0` | `credential_file_read;high_entropy_string;long_encoded_blob;network_access;process_exec` |
| `axios` | `1.18.0` -> `1.18.1` | `credential_file_read;high_entropy_string;long_encoded_blob;network_access;process_exec` |
| `axios` | `1.18.1` -> `1.19.0` | `credential_file_read;dependency_version_changed;hardcoded_ip;high_entropy_string;long_encoded_blob;network_access;new_files_summary;process_exec` |
| `axios` | `1.19.0` -> `1.20.0` | `credential_file_read;hardcoded_url;high_entropy_string;long_encoded_blob;network_access;new_files_summary;process_exec` |
| `webpack` | `5.110.1` -> `5.110.2` | `dynamic_code;long_encoded_blob;network_access` |
| `webpack` | `5.111.1` -> `5.112.0` | `dependency_added;dependency_removed;dependency_version_changed;dynamic_code;env_enumeration;hardcoded_ip;hardcoded_url;high_entropy_string;long_encoded_blob;network_access;new_files_summary;notable_new_file;process_exec` |

## 4. The 3 Noisiest Packages

| Package | Alerts (WARN/BLOCK) | Total Evidence Items | Most Common Signals |
|:---|:---:|:---:|:---|
| `webpack` | 5 | 41 | `long_encoded_blob` (5), `hardcoded_ip` (4), `hardcoded_url` (4) |
| `axios` | 5 | 31 | `high_entropy_string` (5), `long_encoded_blob` (5), `network_access` (5) |
| `glob` | 5 | 22 | `high_entropy_string` (5), `long_encoded_blob` (5), `network_access` (4) |

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
