# Release Sentinel - Stage 5a Evaluation Report (v4)

This report presents the frozen evaluation results for Release Sentinel Stage 5a, introducing:
1. **Full-scan (no-baseline) mode**: Standalone corroborated detection when no prior release baseline exists.
2. **Dependency-aware updates**: Automatic resolution and depth-1 scanning of runtime dependencies newly added in a release.
3. **Comprehensive benign false-alarm breakdown**: Signal value analysis across all 800 benign packages.

Evaluation protocol rules are strictly maintained:
- **DEV** (< 2026-01-01) and **VAL** (2026-01-01 to 2026-04-30): Examined for tuning and category analysis.
- **TEST** (>= 2026-05-01): Reported strictly as aggregate metrics; never inspected per-pair.
- **Fail-closed vs. Evidence-only**: Both views reported explicitly.

---

## 1. Headline Numbers

### 1.1 Sample-Level Recall

Total Malicious Eval Pairs: **1,349** (DEV: 857, VAL: 94, TEST: 398)

| Split | Total Pairs | Fail-Closed $\ge$WARN | Fail-Closed BLOCK | Evidence-Only $\ge$WARN | Evidence-Only BLOCK |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **ALL** | 1,349 | **1,212 (89.84%)** | **1,022 (75.76%)** | **1,206 (89.40%)** | **1,022 (75.76%)** |
| **DEV** | 857 | **848 (98.95%)** | **781 (91.13%)** | **845 (98.60%)** | **781 (91.13%)** |
| **VAL** | 94 | **94 (100.00%)** | **84 (89.36%)** | **94 (100.00%)** | **84 (89.36%)** |
| **TEST** *(Aggregates Only)* | 398 | **270 (67.84%)** | **157 (39.45%)** | **267 (67.09%)** | **157 (39.45%)** |

---

### 1.2 Cluster-Level Recall (Lenient and Macro)

Total Campaign Clusters: **276** (DEV: 68, VAL: 12, TEST: 196)  
Largest cluster share: **405 pairs (30.02%)**

#### Lenient Cluster Recall (Cluster detected if $\ge 1$ member detected)

| Split | Clusters | Fail-Closed $\ge$WARN | Fail-Closed BLOCK | Evidence-Only $\ge$WARN | Evidence-Only BLOCK |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **ALL** | 276 | **151 (54.71%)** | **48 (17.39%)** | **145 (52.54%)** | **48 (17.39%)** |
| **DEV** | 68 | **64 (94.12%)** | **17 (25.00%)** | **61 (89.71%)** | **17 (25.00%)** |
| **VAL** | 12 | **12 (100.00%)** | **8 (66.67%)** | **12 (100.00%)** | **8 (66.67%)** |
| **TEST** *(Aggregates Only)* | 196 | **75 (38.27%)** | **23 (11.73%)** | **72 (38.27%)** | **23 (11.73%)** |

#### Macro-Averaged Cluster Recall (Mean pair recall per cluster)

| Split | Clusters | Macro Fail-Closed $\ge$WARN | Macro Fail-Closed BLOCK | Macro Evidence-Only $\ge$WARN | Macro Evidence-Only BLOCK |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **ALL** | 276 | **54.19%** | **17.06%** | **52.02%** | **17.06%** |
| **DEV** | 68 | **92.21%** | **24.39%** | **87.79%** | **24.39%** |
| **VAL** | 12 | **100.00%** | **63.54%** | **100.00%** | **63.54%** |
| **TEST** *(Aggregates Only)* | 196 | **38.20%** | **11.67%** | **36.67%** | **11.67%** |

---

## 2. Dependency Resolution Statistics

Across the 1,349 malicious evaluation updates:
- **Releases Adding Direct Runtime Dependencies**: **153 releases**
- **Dependencies Resolved Live**: **24 dependencies**
- **Dependencies Replayed from Local Dataset**: **1 dependency** (`plain-crypto-js` via axios 1.14.1)
- **Unresolvable Dependencies**: **2 dependencies** (`unresolvable_dependency` recorded as INFO)

Impact of Dependency Scanning:
- Recovered detection on supply-chain attacks that hide the payload entirely inside newly added dependencies (e.g. `bun: ^1.3.13` added in compromised packages).
- Zero false blocks introduced across benign updates.

---

## 3. DEV+VAL Miss Categories

Analysis of the 80 clusters in DEV (68) and VAL (12):
- **Detected at BLOCK**: **25 clusters** (17 DEV, 8 VAL)
- **Detected at WARN only**: **51 clusters** (47 DEV, 4 VAL)
- **Undetected (ALLOW)**: **4 clusters** (4 DEV, 0 VAL)

### 3.1 Undetected Clusters (4 clusters, 4 pairs)
1. **WASM Payload Modification (1 cluster, 1 pair)**:
   - `@duckdb/duckdb-wasm@1.29.2`: The compromised release altered internal binary WebAssembly data without modifying package manifest scripts or JS source files.
2. **Build Asset Replacement Without JS APIs (2 clusters, 2 pairs)**:
   - `vant@4.9.12`, `vant@4.9.13`: Bundled CSS/asset artifacts changed without detectable static JS indicators or lifecycle scripts.
3. **Bare URL Without Network Execution (1 cluster, 1 pair)**:
   - `@solana/web3.js@1.95.7`: Introduced a single external URL string in comments/data (`hardcoded_url` alone is LOW).

### 3.2 WARN-Only Clusters (51 clusters, 87 pairs)
1. **CI Workflow Exfiltration (3 clusters, 18 pairs)**:
   - Modified `.github/workflows` to exfiltrate npm deployment tokens (`ci_write` + `hardcoded_ip` + `registry_token`). Capped at WARN because no install script was added.
2. **Obfuscated Blobs Without Lifecycle Hook (35 clusters, 48 pairs)**:
   - Packages like `@react-native-aria/*`, `@gluestack-ui/*`, `ansi-*` introduced large base64/hex payloads (`long_encoded_blob`, `high_entropy_string`, `large_size_jump`). In the absence of an install hook or process execution call, they safely capped at WARN.
3. **Install Hook with Bare URL (5 clusters, 5 pairs)**:
   - Packages like `@toptal/picasso-*` and `@xene/core`: Install hook downloads a script via curl/wget in shell, producing `install_script_added` + `hardcoded_url`.
4. **Resource Budget Limits (4 clusters, 4 pairs)**:
   - Multi-megabyte bundled web assets (`@asyncapi/studio`, `@posthog/variance-plugin`) exceeded single-file budgets and failed closed to WARN (`inspection_incomplete`).
5. **Dependency-Linked Install Script (4 clusters, 12 pairs)**:
   - Packages like `axios@1.14.1`: Added dependencies with install scripts present but without executable payload targets.

---

## 4. Benign Impact and Gate Verification

Evaluated across **800 benign update pairs**:
1. **Tuning Smoke Test** (100 pairs, 20 packages):
   - **ALLOW**: 89 (89.0%)
   - **WARN**: 11 (11.0%)
   - **BLOCK**: **0 (0.0%)**
   - **Alert Burden**: **11.0 alerts per 100 updates** (Change vs Baseline: **+0.0**)
2. **Validation Smoke Test** (100 pairs, 20 packages):
   - **ALLOW**: 96 (96.0%)
   - **WARN**: 4 (4.0%)
   - **BLOCK**: **0 (0.0%)**
   - **Alert Burden**: **4.0 alerts per 100 updates** (Change vs Baseline: **+0.0**)
3. **Matched Negatives** (600 pairs):
   - **ALLOW**: 501 (83.50%)
   - **WARN**: 99 (16.50%)
   - **BLOCK**: **0 (0.0%)**
   - **Alert Burden**: **16.50 alerts per 100 updates** (Change vs Baseline: **+0.17**)

> **Benign Gate Status: PASSED**
> - Total false BLOCKs: **0** (requirement: 0).
> - Maximum alert rate rise: **+0.17 per 100** (requirement: $\le$ +3.0 per 100).

---

## 5. Signal Value Analysis

Tally across all 800 benign updates and 80 DEV+VAL malicious clusters:

| Signal | Sole-Cause WARN (Benign) | Total WARN (Benign) | DEV+VAL Clusters (Malicious / 80) | Value Assessment |
| :--- | :---: | :---: | :---: | :--- |
| `high_entropy_string` | 8 | 67 | 41 | Moderate |
| `inspection_incomplete` | 7 | 8 | 5 | Moderate (Fail-closed budget) |
| `long_encoded_blob` | 2 | 51 | 56 | **High Value** (low sole cost, high cluster utility) |
| `install_script_changed` | 2 | 5 | 4 | Moderate |
| `bin_entry_changed` | 2 | 3 | 1 | Costly (low cluster utility) |
| `install_script_added` | 2 | 2 | 26 | **High Value** (low sole cost, high cluster utility) |
| `notable_new_file` | 1 | 49 | 24 | **High Value** (low sole cost, high cluster utility) |
| `inspection_failed` | 1 | 1 | 1 | Moderate |
| `new_files_summary` | 0 | 74 | 12 | **High Value** (0 sole cost, solid cluster utility) |
| `dependency_added` | 0 | 39 | 5 | **High Value** (0 sole cost, solid cluster utility) |
| `large_size_jump` | 0 | 30 | 32 | **High Value** (0 sole cost, high cluster utility) |
| `hardcoded_url` | 0 | 20 | 19 | **High Value** (0 sole cost, high cluster utility) |
| `large_file_count_jump` | 0 | 15 | 1 | Costly (0 clusters helped) |
| `registry_token` | 0 | 13 | 13 | **High Value** (0 sole cost, high cluster utility) |
| `network_access` | 0 | 3 | 8 | **High Value** (0 sole cost, solid cluster utility) |
| `process_exec` | 0 | 2 | 9 | **High Value** (0 sole cost, solid cluster utility) |
| `hardcoded_ip` | 0 | 0 | 10 | **High Value** (0 sole cost, high cluster utility) |
| `install_script_network`| 0 | 0 | 6 | **High Value** (0 sole cost, standalone BLOCKer) |
| `install_script_executes`| 0 | 0 | 6 | **High Value** (0 sole cost, standalone BLOCKer) |

### Top 5 Costliest Signals (highest sole-cause WARNs in benign sets):
1. `high_entropy_string`: 8 sole WARNs (67 total), helps 41 DEV+VAL clusters.
2. `inspection_incomplete`: 7 sole WARNs (8 total), helps 5 DEV+VAL clusters.
3. `long_encoded_blob`: 2 sole WARNs (51 total), helps 56 DEV+VAL clusters.
4. `install_script_changed`: 2 sole WARNs (5 total), helps 4 DEV+VAL clusters.
5. `bin_entry_changed`: 2 sole WARNs (3 total), helps 1 DEV+VAL clusters.

### Top 5 Most Valuable Signals (highest DEV+VAL cluster utility with lowest sole-cause cost):
1. `long_encoded_blob`: helps 56 DEV+VAL clusters, only 2 sole WARNs.
2. `high_entropy_string`: helps 41 DEV+VAL clusters, 8 sole WARNs.
3. `large_size_jump`: helps 32 DEV+VAL clusters, 0 sole WARNs.
4. `install_script_added`: helps 26 DEV+VAL clusters, only 2 sole WARNs.
5. `notable_new_file`: helps 24 DEV+VAL clusters, only 1 sole WARN.
