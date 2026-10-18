# Release Sentinel — Stage 4b Evaluation Results (Walk-Forward Protocol & Budget Calibration)

> **Evaluation Protocol**: Following the discovery in Stage 4a that the primary generalization gap emerged in 2026, the dataset was re-split chronologically into a walk-forward protocol:
> - **DEV** (< 2026-01-01; 857 pairs, 71 campaign clusters): used for initial development and heuristic definition.
> - **VAL** (2026-01-01 to 2026-04-30; 94 pairs, 12 campaign clusters): newly opened for failure analysis and tuning without burning the held-out test split.
> - **TEST** (>= 2026-05-01; 398 pairs, 203 campaign clusters): held-out final test set; reported strictly as aggregates, never inspected per-pair.
>
> **Honest Recall Reporting**: All recall tables explicitly separate:
> - **(a) Evidence-Only Recall**: Detections driven strictly by security evidence rules without assistance from fail-closed elevation.
> - **(b) Fail-Closed WARN**: Pairs that lacked corroborating evidence and warned solely because an uninspected file triggered `inspection_incomplete`.
> Headline recall reports **(a)** only.

---

## 1. Headline Recall

Under **Lenient Recall**, a cluster is detected if any member pair within that split is detected. **Macro-averaged Recall** computes the detection rate within each campaign cluster first, and takes the unweighted arithmetic mean across all clusters in that split.

### A. Evidence-Only Headline Recall (Category a — Primary Metric)

| Split | Total Pairs | Sample Recall (WARN+) | Sample Recall (BLOCK) | Total Clusters | Lenient Cluster (WARN+) | Lenient Cluster (BLOCK) | Macro Cluster (WARN+) | Macro Cluster (BLOCK) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **DEV** (< 2026-01-01) | 857 | **97.55%** (836 / 857) | **90.20%** (773 / 857) | 71 | **77.46%** (55 / 71) | **16.90%** (12 / 71) | **75.63%** | **16.32%** |
| **VAL** (2026-01 to 2026-04) | 94 | **98.94%** (93 / 94) | **89.36%** (84 / 94) | 12 | **91.67%** (11 / 12) | **66.67%** (8 / 12) | **91.67%** | **63.54%** |
| **TEST** (>= 2026-05-01) *(aggregate only)* | 398 | **67.09%** (267 / 398) | **39.20%** (156 / 398) | 203 | **35.96%** (73 / 203) | **11.33%** (23 / 203) | **35.96%** | **11.33%** |
| **ALL** | **1,349** | **88.66%** (1,196 / 1,349) | **75.09%** (1,013 / 1,349) | **286** | **48.60%** (139 / 286) | **15.03%** (43 / 286) | **48.15%** | **14.76%** |

### B. Fail-Closed WARN Recall (Category b — Incomplete Inspection Only)

| Split | Total Pairs | Sample Fail-Closed WARN | Clusters Affected | Lenient Cluster Share |
| :--- | :---: | :---: | :---: | :---: |
| **DEV** (< 2026-01-01) | 857 | **0.58%** (5 / 857) | 5 | **7.04%** (5 / 71) |
| **VAL** (2026-01 to 2026-04) | 94 | **0.00%** (0 / 94) | 0 | **0.00%** (0 / 12) |
| **TEST** (>= 2026-05-01) *(aggregate only)* | 398 | **0.75%** (3 / 398) | 3 | **1.48%** (3 / 203) |
| **ALL** | **1,349** | **0.59%** (8 / 1,349) | 8 | **2.80%** (8 / 286) |

### C. Total Combined Detection (a + b)

| Split | Total Pairs | Sample WARN+ | Sample BLOCK | Clusters | Lenient WARN+ | Lenient BLOCK | Macro WARN+ | Macro BLOCK |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **DEV** | 857 | **98.13%** (841 / 857) | **90.20%** (773 / 857) | 71 | **84.51%** (60 / 71) | **16.90%** (12 / 71) | **82.68%** | **16.32%** |
| **VAL** | 94 | **98.94%** (93 / 94) | **89.36%** (84 / 94) | 12 | **91.67%** (11 / 12) | **66.67%** (8 / 12) | **91.67%** | **63.54%** |
| **TEST** *(aggregate only)* | 398 | **67.84%** (270 / 398) | **39.20%** (156 / 398) | 203 | **37.44%** (76 / 203) | **11.33%** (23 / 203) | **37.44%** | **11.33%** |
| **ALL** | **1,349** | **89.25%** (1,204 / 1,349) | **75.09%** (1,013 / 1,349) | **286** | **51.40%** (147 / 286) | **15.03%** (43 / 286) | **50.94%** | **14.76%** |

---

## 2. Execution Status Breakdown

With calibrated budgets (25 MB size cap, 10.0s time budget), 1,324 pairs (98.15%) completed full content and capability inspection without hitting resource cutoffs:

| Status | ALL (N=1,349) | DEV (N=857) | VAL (N=94) | TEST (N=398) | Description |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **`ok`** | 1,324 (98.15%) | 845 (98.60%) | 94 (100.0%) | 385 (96.73%) | Complete content, diff, and token scanning without budget cutoffs. |
| **`inspection_incomplete`** | 12 (0.89%) | 5 (0.58%) | 0 (0.00%) | 7 (1.76%) | Massive native binary repositories (>60 MB binaries) caught by wall-clock backstop. |
| **`baseline_download_failed`** | 13 (0.96%) | 7 (0.82%) | 0 (0.00%) | 6 (1.51%) | Predecessor version missing from public registry prior to discovery date. |
| **`error`** | 0 (0.00%) | 0 (0.00%) | 0 (0.00%) | 0 (0.00%) | Zero unhandled runtime exceptions. |

---

## 3. Top 10 Largest Campaign Clusters

| Cluster ID | Rank | Size (Pairs) | Share of Dataset | Earliest Discovery | Decision | Evidence-Only Decision | Statuses |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `cluster_0001` | 1 | 404 | 29.95% | 2025-11-24 | **BLOCK** | **BLOCK** | ok: 404 |
| `cluster_0002` | 2 | 198 | 14.68% | 2025-09-15 | **BLOCK** | **BLOCK** | ok: 198 |
| `cluster_0003` | 3 | 83 | 6.15% | 2025-09-15 | **BLOCK** | **BLOCK** | ok: 81, inspection_incomplete: 2 |
| `cluster_0004` | 4 | 71 | 5.26% | 2026-05-11 | **BLOCK** | **BLOCK** | ok: 70, inspection_incomplete: 1 |
| `cluster_0005` | 5 | 60 | 4.45% | 2026-05-11 | **WARN** | **WARN** | ok: 60 |
| `cluster_0006` | 6 | 35 | 2.59% | 2025-09-16 | **BLOCK** | **BLOCK** | ok: 35 |
| `cluster_0007` | 7 | 25 | 1.85% | 2026-05-11 | **BLOCK** | **BLOCK** | ok: 25 |
| `cluster_0008` | 8 | 24 | 1.78% | 2025-09-14 | **BLOCK** | **BLOCK** | ok: 24 |
| `cluster_0009` | 9 | 23 | 1.70% | 2026-05-19 | **BLOCK** | **BLOCK** | ok: 23 |
| `cluster_0010` | 10 | 22 | 1.63% | 2026-03-20 | **BLOCK** | **BLOCK** | ok: 22 |

*Generalization Insight*: 100% of the top 10 campaigns are blocked or warned by genuine security evidence alone without relying on fail-closed flags.

---

## 4. Per-Evidence Type Coverage

| Evidence ID | Pairs Count | Share of Pairs | Clusters Count | Share of Clusters |
| :--- | :---: | :---: | :---: | :---: |
| `long_encoded_blob` | 1,170 | 86.73% | 125 | 43.71% |
| `notable_new_file` | 1,134 | 84.06% | 82 | 28.67% |
| `high_entropy_string` | 1,062 | 78.72% | 52 | 18.18% |
| `install_script_added` | 1,016 | 75.32% | 48 | 16.78% |
| `large_size_jump` | 975 | 72.28% | 88 | 30.77% |
| `hardcoded_url` | 818 | 60.64% | 21 | 7.34% |
| `process_exec` | 566 | 41.96% | 16 | 5.59% |
| `network_access` | 515 | 38.18% | 13 | 4.55% |
| `registry_token` | 438 | 32.47% | 15 | 5.24% |
| `dynamic_code` | 419 | 31.06% | 63 | 22.03% |
| `shell_profile_write` | 408 | 30.24% | 2 | 0.70% |
| `env_enumeration` | 391 | 28.98% | 5 | 1.75% |
| `ci_write` | 379 | 28.09% | 9 | 3.15% |
| `hardcoded_ip` | 375 | 27.80% | 11 | 3.85% |
| `dependency_added` | 238 | 17.64% | 133 | 46.50% |
| `new_files_summary` | 160 | 11.86% | 62 | 21.68% |
| `dependency_removed` | 80 | 5.93% | 11 | 3.85% |
| `credential_file_read` | 54 | 4.00% | 4 | 1.40% |
| `dependency_version_changed` | 28 | 2.08% | 14 | 4.90% |
| `inspection_incomplete` | 12 | 0.89% | 11 | 3.85% |
| `install_script_changed` | 12 | 0.89% | 4 | 1.40% |
| `native_binary_present` | 12 | 0.89% | 3 | 1.05% |
| `inspection_failed` | 4 | 0.30% | 4 | 1.40% |
| `large_file_count_jump` | 2 | 0.15% | 2 | 0.70% |
| `bin_entry_changed` | 1 | 0.07% | 1 | 0.35% |
| `bin_entry_added` | 1 | 0.07% | 1 | 0.35% |

---

## 5. Operating Point: Benign Alert Burden vs Malicious Recall

| Dataset | Total Pairs | ALLOW | WARN | BLOCK | Incomplete Files | Alert Rate (WARN+) | Gate False Positive (BLOCK) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Benign Tuning Smoke Test** | 100 | **89** (89.0%) | 11 (11.0%) | **0** (0.0%) | 0 pairs | **11.0%** | **0.00%** |
| **Benign Validation Smoke Test** | 100 | **96** (96.0%) | 4 (4.0%) | **0** (0.0%) | 0 pairs | **4.0%** | **0.00%** |
| **Benign Matched Negatives** | 600 | **502** (83.67%) | 98 (16.33%) | **0** (0.0%) | 10 pairs | **16.33%** | **0.00%** |
| **Malicious DEV** (< 2026-01-01) | 857 | 9 (1.05%) | 68 (7.94%) | **773** (90.20%) | 5 pairs | **98.13%** (ev: 97.55%) | **90.20% Recall** |
| **Malicious VAL** (2026-01 to 2026-04) | 94 | 1 (1.06%) | 9 (9.57%) | **84** (89.36%) | 0 pairs | **98.94%** (ev: 98.94%) | **89.36% Recall** |
| **Malicious TEST** *(aggregate only)* | 398 | 122 (30.65%) | 114 (28.64%) | **156** (39.20%) | 7 pairs | **67.84%** (ev: 67.09%) | **39.20% Recall** |
| **Malicious ALL** | 1,349 | 132 (9.79%) | 191 (14.16%) | **1,013** (75.09%) | 12 pairs | **89.25%** (ev: 88.66%) | **75.09% Recall** |

---

## 6. DEV + VAL Miss Analysis

In strict accordance with the evaluation protocol, miss inspection is restricted exclusively to **DEV and VAL**. No TEST samples were inspected. Across DEV and VAL (951 pairs, 83 clusters), there are **22 evidence misses** distributed across 19 campaign clusters.

### Miss Categories by Clusters Affected

| Rank | Root Cause Category | DEV+VAL Clusters Affected | DEV+VAL Pairs Count | Description |
| :---: | :--- | :---: | :---: | :--- |
| **1** | **`baseline_download_failed`** | **7** | 7 | Baseline version removed or published post-`as_of` in public registry. |
| **2** | **`fail_closed_only`** | **5** | 5 | Massive native binary repositories exceeding 60s wall-clock backstop. |
| **3** | **`isolated_uncorroborated_low_or_info`** | **4** | 4 | Single LOW or INFO signal deliberately not escalated by policy (D16). |
| **4** | **`empty_diff_or_pre_existing_capability`** | **3** | 6 | Dry-run version bump or payload API already package-wide in baseline. |

### Concrete Miss Examples by Category

#### 1. `baseline_download_failed` (7 clusters, 7 pairs)
| Package | Old Version | New Version | Cluster ID | Cause |
| :--- | :---: | :---: | :---: | :--- |
| `@nx/enterprise-cloud` | 3.1.1 | 3.2.0 | `cluster_0062` | Baseline 3.1.1 unpublished or unavailable as of discovery date. |
| `@nx/key` | 3.1.1 | 3.2.0 | `cluster_0063` | Baseline 3.1.1 unpublished or unavailable as of discovery date. |
| `@toptal/picasso-charts` | 59.0.6 | 59.1.4 | `cluster_0052` | Baseline 59.0.6 unavailable in registry. |
| `@toptal/picasso-forms` | 73.2.14 | 73.3.2 | `cluster_0053` | Baseline 73.2.14 unavailable in registry. |
| `@toptal/picasso-provider` | 5.0.2 | 5.1.1 | `cluster_0054` | Baseline 5.0.2 unavailable in registry. |
| `@toptal/picasso-quote` | 2.0.11 | 2.1.7 | `cluster_0055` | Baseline 2.0.11 unavailable in registry. |
| `@toptal/picasso-select` | 4.1.12 | 4.2.2 | `cluster_0056` | Baseline 4.1.12 unavailable in registry. |

#### 2. `fail_closed_only` (5 clusters, 5 pairs)
| Package | Old Version | New Version | Cluster ID | Cause |
| :--- | :---: | :---: | :---: | :--- |
| `@asyncapi/studio` | 1.0.1 | 1.0.2 | `cluster_0081` | Massive electron bundle (>63 MB native binaries) exceeded 60s wall clock. |
| `@asyncapi/studio` | 1.0.1 | 1.0.3 | `cluster_0082` | Same massive electron bundle structure. |
| `@posthog/variance-plugin` | 0.0.7 | 0.0.8 | `cluster_0083` | Monorepo tarball exceeded 60s wall clock. |
| `@strapbuild/react-native-perspective-image-cropper` | 0.4.14 | 0.4.15 | `cluster_0084` | Native module bundle exceeded 60s wall clock. |
| `duckdb` | 1.3.2 | 1.3.3 | `cluster_0080` | Native C++ and WASM binary bundle exceeded 60s wall clock. |

#### 3. `isolated_uncorroborated_low_or_info` (4 clusters, 4 pairs)
| Package | Old Version | New Version | Cluster ID | Split | Cause |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `@rxap/ngx-bootstrap` | 19.0.2 | 19.0.3 | `cluster_0027` | DEV | Only `dependency_version_changed` (INFO). Single INFO yields ALLOW. |
| `@solana/web3.js` | 1.95.5 | 1.95.7 | `cluster_0030` | DEV | Single `hardcoded_url` (LOW). Single LOW yields ALLOW. |
| `vant` | 4.9.11 | 4.9.13 | `cluster_0032` | DEV | Only `new_files_summary` (inert README added; LOW). Yields ALLOW. |
| `axios` | 1.14.0 | 1.14.1 | `cluster_0088` | VAL | Only `dependency_added` (LOW). Single LOW yields ALLOW. |

#### 4. `empty_diff_or_pre_existing_capability` (3 clusters, 6 pairs)
| Package | Old Version | New Version | Cluster ID | Cause |
| :--- | :---: | :---: | :---: | :--- |
| `xrpl` | 4.2.0 | 4.2.1 | `cluster_0021` | Seed exfiltration via `fetch('https://0x9c.xyz/xc')`. `fetch` pre-existed package-wide in baseline; URL has 11 chars after scheme (< 20 chars). |
| `xrpl` | 4.2.0 | 4.2.2 | `cluster_0021` | Same seed exfiltration payload as 4.2.1. |
| `xrpl` | 4.2.0 | 4.2.3 | `cluster_0021` | Same seed exfiltration payload as 4.2.1. |
| `xrpl` | 4.2.0 | 4.2.4 | `cluster_0021` | Same seed exfiltration payload as 4.2.1. |
| `@duckdb/duckdb-wasm` | 1.29.0 | 1.29.2 | `cluster_0079` | Empty release diff; zero functional code files added or modified. |
| `vant` | 4.9.11 | 4.9.12 | `cluster_0031` | Probe release: only `version` in `package.json` changed; zero code files added or modified. |
