# Release Sentinel — Benign Smoke Test Results (Stage 2.6)

Evaluation of false-alarm burden across benign npm release updates following Stage 2.5/2.6 capability-level diffing, signal precision redefinitions, and JS comment stripping.

All evaluations adhere strictly to `docs/PROJECT_RULES.md`:
- **Rule 1**: Zero code execution (static AST/regex inspection only; no `node`, `npm`, or build scripts run).
- **Rule 2**: Safe extraction with path traversal protection, file-count caps, and size limits.
- **Rule 3**: Strict time-filtering via `as_of` metadata matching the release timestamp.
- **Rule 5**: Clean workspace boundaries; outputs restricted to `data/` and `docs/`.
- **Rule 6**: Harmless synthetic test fixtures only; zero real malware signatures.

---

## 1. Before / After Comparison Table

| Metric | Baseline (`smoke_results_baseline.md`) | Tuning Set v2 (`smoke_results_v2.csv`) | Validation Set v2 (`smoke_validation_v2.csv`) |
|:---|:---:|:---:|:---:|
| **Total Update Pairs Evaluated** | 100 | 100 | 100 |
| **ALLOW Decisions** | 33 (33.0%) | 89 (89.0%) | 96 (96.0%) |
| **WARN Decisions** | 61 (61.0%) | 11 (11.0%) | 4 (4.0%) |
| **BLOCK Decisions** | 6 (6.0%) | 0 (0.0%) | 0 (0.0%) |
| **Alert Burden (WARN + BLOCK)** | **67.0 per 100 updates** | **11.0 per 100 updates** | **4.0 per 100 updates** |
| **False-Positive Block Rate** | 6.0% | **0.0%** | **0.0%** |

*Note*: The tuning set consists of 20 popular npm packages (`axios`, `webpack`, `react`, `lodash`, etc.) evaluated across 5 consecutive stable same-major pairs each (100 total pairs). The validation set consists of 20 *completely different* popular, actively maintained packages (`body-parser`, `cors`, `sharp`, `rxjs`, `winston`, `mocha`, etc.) with zero overlap.

---

## 2. Top 10 Evidence Types by Dataset

### A. Baseline (Pre-Stage 2.5/2.6)
| Rank | Evidence Type | Total Frequency | Sole Evidence for Alert |
|:---:|:---|:---:|:---:|
| 1 | `dependency_version_changed` | 38 | 14 |
| 2 | `high_entropy_string` | 32 | 0 |
| 3 | `long_encoded_blob` | 32 | 0 |
| 4 | `process_exec` | 23 | 1 |
| 5 | `new_files_summary` | 19 | 0 |
| 6 | `hardcoded_url` | 18 | 0 |
| 7 | `dependency_added` | 17 | 1 |
| 8 | `network_access` | 12 | 0 |
| 9 | `dependency_removed` | 11 | 1 |
| 10 | `hardcoded_ip` | 6 | 0 |

### B. Tuning Set (Stage 2.6 v2)
| Rank | Evidence Type | Total Frequency | Sole Evidence for Alert |
|:---:|:---|:---:|:---:|
| 1 | `dependency_version_changed` | 38 | 0 (INFO) |
| 2 | `new_files_summary` | 19 | 0 (LOW) |
| 3 | `dependency_added` | 17 | 0 (LOW) |
| 4 | `dependency_removed` | 11 | 0 (INFO) |
| 5 | `high_entropy_string` | 6 | 0 |
| 6 | `notable_new_file` | 6 | 1 |
| 7 | `long_encoded_blob` | 4 | 1 |
| 8 | `install_script_changed` | 3 | 0 |
| 9 | `hardcoded_url` | 1 | 0 |
| 10 | `large_size_jump` | 1 | 0 |

### C. Validation Set (Stage 2.6 v2)
| Rank | Evidence Type | Total Frequency | Sole Evidence for Alert |
|:---:|:---|:---:|:---:|
| 1 | `dependency_version_changed` | 48 | 0 (INFO) |
| 2 | `dependency_added` | 14 | 0 (LOW) |
| 3 | `dependency_removed` | 11 | 0 (INFO) |
| 4 | `new_files_summary` | 8 | 0 (LOW) |
| 5 | `hardcoded_url` | 3 | 0 |
| 6 | `high_entropy_string` | 2 | 1 |
| 7 | `install_script_added` | 1 | 0 |
| 8 | `long_encoded_blob` | 1 | 1 |
| 9 | *(none)* | 0 | 0 |
| 10 | *(none)* | 0 | 0 |

---

## 3. Every BLOCK Decision

### Baseline (6 BLOCKs)
| Package | Upgrade Pair | Evidence Types Driving BLOCK |
|:---|:---|:---|
| `axios` | `1.17.0` -> `1.18.0` | `credential_file_read; high_entropy_string; long_encoded_blob; network_access; process_exec` |
| `axios` | `1.18.0` -> `1.18.1` | `credential_file_read; high_entropy_string; long_encoded_blob; network_access; process_exec` |
| `axios` | `1.18.1` -> `1.19.0` | `credential_file_read; dependency_version_changed; hardcoded_ip; high_entropy_string; long_encoded_blob; network_access; new_files_summary; process_exec` |
| `axios` | `1.19.0` -> `1.20.0` | `credential_file_read; hardcoded_url; high_entropy_string; long_encoded_blob; network_access; new_files_summary; process_exec` |
| `webpack` | `5.110.1` -> `5.110.2` | `dynamic_code; long_encoded_blob; network_access` |
| `webpack` | `5.111.1` -> `5.112.0` | `dependency_added; dependency_removed; dependency_version_changed; dynamic_code; env_enumeration; hardcoded_ip; hardcoded_url; high_entropy_string; long_encoded_blob; network_access; new_files_summary; notable_new_file; process_exec` |

### Tuning Set v2 (0 BLOCKs)
*(None. Zero false-positive blocks across all 100 tuning updates.)*

### Validation Set v2 (0 BLOCKs)
*(None. Zero false-positive blocks across all 100 validation updates.)*

---

## 4. Every Release Pair with 3+ Evidence Items

### A. Tuning Set v2 (13 pairs)
| Package | Upgrade Pair | Decision | Max Severity | Evidence Types |
|:---|:---|:---:|:---:|:---|
| `axios` | `1.18.1` -> `1.19.0` | **WARN** | MEDIUM | `dependency_version_changed`, `high_entropy_string`, `new_files_summary` |
| `typescript` | `5.8.3` -> `5.9.2` | **ALLOW** | LOW | `dependency_added`, `dependency_removed`, `dependency_version_changed`, `new_files_summary` |
| `webpack` | `5.110.3` -> `5.111.0` | **WARN** | MEDIUM | `dependency_added`, `dependency_removed`, `dependency_version_changed`, `high_entropy_string`, `long_encoded_blob`, `new_files_summary`, `notable_new_file` |
| `webpack` | `5.111.0` -> `5.111.1` | **ALLOW** | LOW | `dependency_added`, `dependency_removed`, `dependency_version_changed`, `new_files_summary` |
| `webpack` | `5.111.1` -> `5.112.0` | **WARN** | MEDIUM | `dependency_added`, `dependency_removed`, `dependency_version_changed`, `hardcoded_url`, `high_entropy_string`, `long_encoded_blob`, `new_files_summary`, `notable_new_file` |
| `commander` | `12.0.0` -> `12.1.0` | **ALLOW** | LOW | `dependency_added`, `dependency_removed`, `dependency_version_changed` |
| `yargs` | `16.2.0` -> `16.2.2` | **ALLOW** | LOW | `dependency_added`, `dependency_removed`, `dependency_version_changed`, `new_files_summary` |
| `yargs` | `17.7.2` -> `17.7.3` | **ALLOW** | LOW | `dependency_added`, `dependency_version_changed`, `new_files_summary` |
| `uuid` | `14.0.0` -> `14.0.1` | **WARN** | MEDIUM | `dependency_added`, `dependency_removed`, `dependency_version_changed`, `install_script_changed` |
| `glob` | `13.0.1` -> `13.0.2` | **WARN** | MEDIUM | `dependency_added`, `high_entropy_string`, `install_script_changed`, `large_size_jump`, `long_encoded_blob`, `network_access`, `new_files_summary`, `notable_new_file` |
| `mime` | `4.0.4` -> `4.0.5` | **ALLOW** | LOW | `dependency_added`, `dependency_removed`, `dependency_version_changed` |
| `bcrypt` | `5.0.0` -> `5.0.1` | **ALLOW** | LOW | `dependency_added`, `dependency_removed`, `dependency_version_changed`, `new_files_summary` |
| `bcrypt` | `5.0.1` -> `5.1.0` | **WARN** | MEDIUM | `dependency_added`, `dependency_removed`, `dependency_version_changed`, `high_entropy_string`, `new_files_summary`, `notable_new_file` |

### B. Validation Set v2 (8 pairs)
| Package | Upgrade Pair | Decision | Max Severity | Evidence Types |
|:---|:---|:---:|:---:|:---|
| `cors` | `2.8.4` -> `2.8.5` | **ALLOW** | LOW | `dependency_added`, `dependency_removed`, `dependency_version_changed` |
| `winston` | `3.18.3` -> `3.19.0` | **ALLOW** | LOW | `dependency_added`, `dependency_removed`, `dependency_version_changed` |
| `fast-glob` | `3.2.11` -> `3.2.12` | **ALLOW** | LOW | `dependency_added`, `dependency_removed`, `dependency_version_changed` |
| `mocha` | `12.0.1` -> `12.0.2` | **ALLOW** | LOW | `dependency_added`, `dependency_removed`, `new_files_summary` |
| `cheerio` | `0.20.0` -> `0.22.0` | **ALLOW** | LOW | `dependency_added`, `dependency_removed`, `dependency_version_changed` |
| `cheerio` | `1.0.0` -> `1.1.0` | **ALLOW** | LOW | `dependency_added`, `dependency_removed`, `dependency_version_changed` |
| `sharp` | `0.35.0` -> `0.35.1` | **ALLOW** | LOW | `dependency_added`, `dependency_version_changed`, `new_files_summary` |
| `sharp` | `0.35.3` -> `0.35.4` | **ALLOW** | LOW | `dependency_added`, `dependency_removed`, `dependency_version_changed` |

*Note*: In the validation set, **100% of pairs with 3+ evidence items were evaluated as ALLOW** because the signals were exclusively routine dependency updates (`dependency_added`, `dependency_removed`, `dependency_version_changed`) and package file count changes (`new_files_summary`). Under Stage 2.5/2.6 policy, these informational and low-severity signals list transparently in the audit report without triggering unnecessary alert noise.

---

## 5. The 3 Noisiest Packages in the Validation Set

| Package | Alerts (WARN/BLOCK) | Total Evidence Items | Most Common Signals | Analysis of Driving Evidence |
|:---|:---:|:---:|:---|:---|
| `sharp` | **1** | 10 | `dependency_version_changed` (5), `dependency_added` (2), `high_entropy_string` (1) | Alert triggered on `0.35.2` -> `0.35.3` (WARN) due to `high_entropy_string` in newly vendored binary prebuild mappings. |
| `superagent` | **1** | 4 | `dependency_version_changed` (3), `install_script_added` (1) | Alert triggered on `10.2.1` -> `10.2.2` (WARN) because an `install_script_added` was introduced for a post-install funding notice. |
| `nanoid` | **1** | 2 | `new_files_summary` (1), `high_entropy_string` (1) | Alert triggered on `6.0.1` -> `6.0.2` (WARN) due to `high_entropy_string` in the alphabet randomization table. |

*(Honorable mention: `dayjs` had 1 alert with 1 evidence item — `long_encoded_blob` on `1.11.19` -> `1.11.20` due to a single-line compiled regex table for locale formatting).*

---

## 6. Suggested Further Changes (Measurement Only — Not Applied)

1. **Entropy Table & Alphabet Carve-Outs for ID/Randomization Modules**:
   - Packages like `nanoid` legitimately declare high-entropy lookup strings (e.g. customized alphanumeric alphabets). Extending entropy suppression to single short variable declarations (`const urlAlphabet = '...'`) where string length is below 128 characters would eliminate `nanoid`'s sole warning.
2. **Postinstall Ad / Funding Notice vs Executable Script Discrimination**:
   - In `superagent`, an added install script simply printed a donation banner (`"postinstall": "node ./bin/notice.js"`). While correctly flagged as HIGH for security review, a policy rule requiring network/process execution corroboration before escalating above WARN prevents false blocks while keeping reviewers informed.
3. **Locale and Formatting Table Long-Line Exemptions**:
   - `dayjs` generated a `long_encoded_blob` warning due to bundled locale regex strings exceeding 500 characters on a single line. Adding directory-level exemptions for locale files (`/locale/`, `/locales/`) or regex-only lines would reduce noise in internationalized libraries.
4. **Native Prebuild Mapping Allowlist**:
   - Native modules like `sharp` vendor precompiled platform-specific binding mappings with content hashes that trip `high_entropy_string`. Recognizing structured JSON or JS platform-binding dictionaries (`@img/sharp-darwin-arm64`) as native binding descriptors would allow `sharp` to pass cleanly.
