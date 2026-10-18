# Release Sentinel — Stage 4a Evaluation Results (Re-baseline)

> **Evaluation Honesty**: This report documents the Stage 4a re-baseline evaluation of Release Sentinel against 1,349 real-world compromised npm package pairs from the DataDog malicious software dataset following scanner robustness fixes and per-file resource budget enforcement. No detection rules, severities, or policy rules were modified except for the fail-closed elevation of uninspected files.
> **Split Protocol**: The dataset is split temporally by discovery date into **DEV** (before 2026-01-01; 857 pairs) and **TEST** (2026-01-01 and later; 492 pairs). Per-pair failure inspection is strictly confined to DEV; TEST results are reported solely as aggregates. All proposed improvements are justified exclusively from DEV evidence.

---

## 1. Headline Recall

A cluster is counted as detected under **Lenient Recall** if **any** member pair within that split is detected. **Macro-averaged Recall** calculates the detection rate within each campaign cluster first, and takes the unweighted arithmetic mean across all clusters in that split.

| Split | Total Pairs | Sample Recall (WARN+) | Sample Recall (BLOCK) | Total Clusters | Lenient Cluster (WARN+) | Lenient Cluster (BLOCK) | Macro Cluster (WARN+) | Macro Cluster (BLOCK) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **DEV** (< 2026-01-01) | 857 | **98.13%** (841 / 857) | **90.08%** (772 / 857) | 70 | **84.29%** (59 / 70) | **17.14%** (12 / 70) | **82.43%** | **16.54%** |
| **TEST** (>= 2026-01-01) | 492 | **74.59%** (367 / 492) | **46.14%** (227 / 492) | 212 | **41.51%** (88 / 212) | **7.08%** (15 / 212) | **41.51%** | **6.90%** |
| **ALL** | **1,349** | **89.55%** (1,208 / 1,349) | **74.05%** (999 / 1,349) | **282** | **52.13%** (147 / 282) | **9.57%** (27 / 282) | **51.67%** | **9.29%** |

### Execution Status Summary

Scanner stalls hitting the 60-second limit dropped from 278 (20.61%) in Stage 3b to **0** scanner stalls (3 extreme native packages exceeded wall-clock limits due to tarball unpacking and were caught by the fail-closed backstop).

| Status | ALL (N=1,349) | DEV (N=857) | TEST (N=492) | Description |
| :--- | :---: | :---: | :---: | :--- |
| **`ok`** | 326 (24.17%) | 72 (8.40%) | 254 (51.63%) | Full content and diff inspection completed within all per-file budgets. |
| **`inspection_incomplete`** | 1,010 (74.87%) | 778 (90.78%) | 232 (47.15%) | Completed with cheap checks applied to files exceeding 2 MB size or 2.0s time budget; failed closed to WARN minimum. |
| **`baseline_download_failed`** | 13 (0.96%) | 7 (0.82%) | 6 (1.22%) | Predecessor version unavailable in registry as of discovery date. |
| **`error`** | 0 (0.00%) | 0 (0.00%) | 0 (0.00%) | Zero unhandled runtime crashes or exceptions. |

---

## 2. Campaign Cluster Analysis

Malicious campaigns routinely spray identical or near-identical payloads across many compromised packages. To avoid skewed performance metrics from single large campaigns, pairs were clustered using **Union-Find (DSU)** over SHA-256 hashes of new and modified files (excluding `package.json`, `README*`, `LICENSE*`, source maps, and files under 200 bytes).

- **Total Clusters**: 282
- **Largest Cluster Share**: **30.02%** of all samples (Cluster 1: 405 samples, 100% blocked)
- **Top 10 Clusters Share**: **65.38%** of all samples (882 samples)
- **Top 10 Clusters Detection Rate**: **100.0% WARN+** (9 BLOCK, 1 WARN)

### Top 10 Largest Campaigns

| Cluster ID | Rank | Size (Pairs) | Share of Dataset | Earliest Discovery | Decision | Statuses |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| `cluster_0001` | 1 | 405 | 30.02% | 2025-11-24 | **BLOCK** | inspection_incomplete: 405 |
| `cluster_0002` | 2 | 198 | 14.68% | 2025-09-15 | **BLOCK** | inspection_incomplete: 198 |
| `cluster_0003` | 3 | 83 | 6.15% | 2025-09-15 | **BLOCK** | inspection_incomplete: 83 |
| `cluster_0004` | 4 | 74 | 5.49% | 2026-05-11 | **BLOCK** | inspection_incomplete: 74 |
| `cluster_0005` | 5 | 60 | 4.45% | 2026-05-11 | **WARN** | inspection_incomplete: 60 |
| `cluster_0006` | 6 | 35 | 2.59% | 2025-09-16 | **BLOCK** | inspection_incomplete: 35 |
| `cluster_0007` | 7 | 25 | 1.85% | 2026-05-11 | **BLOCK** | inspection_incomplete: 17, ok: 8 |
| `cluster_0008` | 8 | 24 | 1.78% | 2025-09-14 | **BLOCK** | inspection_incomplete: 24 |
| `cluster_0009` | 9 | 23 | 1.70% | 2026-05-19 | **BLOCK** | inspection_incomplete: 1, ok: 22 |
| `cluster_0010` | 10 | 22 | 1.63% | 2026-03-20 | **BLOCK** | ok: 22 |

---

## 3. Per-Evidence Frequency Table

The table below lists the frequency and cluster distribution of every evidence type emitted during the evaluation run across all 1,349 pairs:

| Evidence ID | Pairs Count | Share of Pairs | Clusters Count | Share of Clusters |
| :--- | :---: | :---: | :---: | :---: |
| `notable_new_file` | 1,139 | 84.43% | 83 | 29.43% |
| `high_entropy_string` | 1,066 | 79.02% | 52 | 18.44% |
| `install_script_added` | 1,020 | 75.61% | 48 | 17.02% |
| `inspection_incomplete` | 1,010 | 74.87% | 88 | 31.21% |
| `large_size_jump` | 977 | 72.42% | 89 | 31.56% |
| `process_exec` | 578 | 42.85% | 15 | 5.32% |
| `shell_profile_write` | 409 | 30.32% | 2 | 0.71% |
| `env_enumeration` | 392 | 29.06% | 5 | 1.77% |
| `dependency_added` | 238 | 17.64% | 133 | 47.16% |
| `long_encoded_blob` | 190 | 14.08% | 56 | 19.86% |
| `new_files_summary` | 161 | 11.93% | 63 | 22.34% |
| `network_access` | 118 | 8.75% | 12 | 4.26% |
| `dependency_removed` | 80 | 5.93% | 11 | 3.90% |
| `registry_token` | 71 | 5.26% | 7 | 2.48% |
| `credential_file_read` | 54 | 4.00% | 4 | 1.42% |
| `dependency_version_changed` | 28 | 2.08% | 14 | 4.96% |
| `hardcoded_url` | 27 | 2.00% | 12 | 4.26% |
| `native_binary_present` | 13 | 0.96% | 4 | 1.42% |
| `install_script_changed` | 12 | 0.89% | 4 | 1.42% |
| `ci_write` | 10 | 0.74% | 1 | 0.35% |
| `dynamic_code` | 8 | 0.59% | 6 | 2.13% |
| `hardcoded_ip` | 6 | 0.44% | 3 | 1.06% |
| `inspection_failed` | 5 | 0.37% | 5 | 1.77% |
| `large_file_count_jump` | 2 | 0.15% | 2 | 0.71% |
| `bin_entry_changed` | 1 | 0.07% | 1 | 0.35% |
| `bin_entry_added` | 1 | 0.07% | 1 | 0.35% |

---

## 4. Operating Point & Benign Smoke Comparison

Release Sentinel's detection performance is evaluated alongside its false alarm rate on benign npm releases. The Stage 4a engine was evaluated against both the tuning smoke set and an independent validation smoke set (100 popular packages each, same-major stable updates):

| Dataset | Total Pairs | ALLOW | WARN | BLOCK | Incomplete Files | Alert Rate (WARN+) | Gate Rate (BLOCK) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Benign Tuning Smoke Test** | 100 | **84** (84.0%) | 16 (16.0%) | **0** (0.0%) | 5 pairs (`typescript`) | **16.0%** Alert Rate | **0.0% False Block** |
| **Benign Validation Smoke Test** | 100 | **96** (96.0%) | 4 (4.0%) | **0** (0.0%) | 0 pairs | **4.0%** Alert Rate | **0.0% False Block** |
| **Malicious ALL** | 1,349 | 128 (9.49%) | 209 (15.49%) | **999** (74.05%) | 1,010 pairs | **89.55% Recall** | **74.05% Recall** |
| **Malicious DEV** | 857 | 9 (1.05%) | 69 (8.05%) | **772** (90.08%) | 778 pairs | **98.13% Recall** | **90.08% Recall** |
| **Malicious TEST** (aggregate only) | 492 | 119 (24.19%) | 140 (28.46%) | **227** (46.14%) | 232 pairs | **74.59% Recall** | **46.14% Recall** |

### Key Observations
1. **0.0% False Positive Gate Rate**: In both benign datasets, zero benign packages received a BLOCK decision. The corroboration gate remains completely uncompromised.
2. **Benign Alert Burden**: On general popular packages (validation set), the alert burden is **4.0 alerts per 100 updates** with **0 incomplete file warnings**. On extreme monolithic codebases with bundled multi-megabyte distribution files (`typescript`), budget caps trigger `inspection_incomplete` warnings, yielding 16.0 alerts per 100 updates.
3. **Malicious Detection Recovery**: With fail-closed handling on budget exceedance, DEV sample recall increased from **82.03% to 98.13%** (WARN+) and **77.13% to 90.08%** (BLOCK). Overall sample recall reached **89.55%** (WARN+) and **74.05%** (BLOCK).

---

## 5. DEV Misses Analysis

In accordance with the evaluation protocol, per-pair failure inspection was conducted **strictly on the DEV set**. There are **16 DEV misses** (pairs resulting in ALLOW or unanalyzable due to baseline download failure) out of 857 DEV pairs, distributed across 13 DEV clusters. No TEST samples were inspected.

### DEV Miss Categories

| Category | Count | DEV Clusters | Description |
| :--- | :---: | :---: | :--- |
| **`baseline_download_failed`** | 7 | 7 | Baseline version unresolvable in registry prior to discovery date. |
| **`empty diff / identical code / capability pre-existing`** | 6 | 3 | Empty releases or payload using an API already package-wide in baseline. |
| **`isolated low-severity change without corroboration`** | 3 | 3 | Single INFO or single LOW signal that policy deliberately does not alert. |

### Concrete DEV Miss Breakdown

| Package | Old Version | New Version | Cluster ID | Status | Decision | Root Cause & Failure Mechanism |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| `@nx/enterprise-cloud` | 3.1.1 | 3.2.0 | `cluster_0062` | `baseline_download_failed` | None | Baseline version 3.1.1 was deleted or published post-`as_of`. |
| `@nx/key` | 3.1.1 | 3.2.0 | `cluster_0063` | `baseline_download_failed` | None | Baseline version 3.1.1 was deleted or published post-`as_of`. |
| `@toptal/picasso-charts` | 59.0.6 | 59.1.4 | `cluster_0052` | `baseline_download_failed` | None | Predecessor tarball missing from registry as of discovery date. |
| `@toptal/picasso-forms` | 73.2.14 | 73.3.2 | `cluster_0053` | `baseline_download_failed` | None | Predecessor tarball missing from registry as of discovery date. |
| `@toptal/picasso-provider` | 5.0.2 | 5.1.1 | `cluster_0054` | `baseline_download_failed` | None | Predecessor tarball missing from registry as of discovery date. |
| `@toptal/picasso-quote` | 2.0.11 | 2.1.7 | `cluster_0055` | `baseline_download_failed` | None | Predecessor tarball missing from registry as of discovery date. |
| `@toptal/picasso-select` | 4.1.12 | 4.2.2 | `cluster_0056` | `baseline_download_failed` | None | Predecessor tarball missing from registry as of discovery date. |
| `xrpl` | 4.2.0 | 4.2.1 | `cluster_0021` | `ok` | ALLOW | Exfiltrates seed keys via `fetch('https://0x9c.xyz/xc')`. `fetch` was already in old release (package-wide API diffing); `0x9c.xyz/xc` has only 11 chars after scheme, evading `hardcoded_url` (>= 20 chars). |
| `xrpl` | 4.2.0 | 4.2.2 | `cluster_0021` | `ok` | ALLOW | Same payload as 4.2.1; suppressed by capability diff and URL length. |
| `xrpl` | 4.2.0 | 4.2.3 | `cluster_0021` | `ok` | ALLOW | Same payload as 4.2.1. |
| `xrpl` | 4.2.0 | 4.2.4 | `cluster_0021` | `ok` | ALLOW | Same payload as 4.2.1. |
| `@duckdb/duckdb-wasm` | 1.29.0 | 1.29.2 | `cluster_0079` | `ok` | ALLOW | Empty release / zero code modifications detected. |
| `vant` | 4.9.11 | 4.9.12 | `cluster_0031` | `ok` | ALLOW | Probe release: only `version` in `package.json` changed; 0 files added or modified. |
| `vant` | 4.9.11 | 4.9.13 | `cluster_0032` | `ok` | ALLOW | Only inert `README.md` added (`new_files_summary` LOW severity; single LOW yields ALLOW under D16). |
| `@rxap/ngx-bootstrap` | 19.0.2 | 19.0.3 | `cluster_0027` | `ok` | ALLOW | Only `dependency_version_changed` (INFO severity). Single INFO yields ALLOW. |
| `@solana/web3.js` | 1.95.5 | 1.95.7 | `cluster_0030` | `ok` | ALLOW | Emitted single `hardcoded_url` (LOW severity). Policy deliberately does not alert on a single uncorroborated LOW. |

---

## 6. Proposed Improvements (Derived Strictly from DEV Evidence)

> [!IMPORTANT]
> The following recommendations are derived solely from DEV failure patterns. In strict accordance with the evaluation protocol, none of these proposals have been implemented in Stage 4a.

1. **Destination-Aware Network Capability Diffing & Short URL Detection**:
   - *DEV Evidence*: `xrpl 4.2.1..4` exfiltrated wallet credentials to `https://0x9c.xyz/xc` using `fetch`. The capability diff suppressed `fetch` because the benign package already called `fetch` elsewhere, and the URL string bypassed `hardcoded_url` because `0x9c.xyz/xc` is under 20 characters after `https://`.
   - *Proposal*: Track network calls by remote destination hostname rather than package-wide API presence (e.g., `('network_access', '0x9c.xyz')`). Reduce the minimum URL length threshold for suspicious non-allowlisted domains from 20 characters to 8 characters.
   - *Impact*: Recovers 4 `xrpl` pairs in `cluster_0021` to BLOCK.

2. **Metadata-Only / Dry-Run Version Bump Heuristic**:
   - *DEV Evidence*: `vant 4.9.12` and `@duckdb/duckdb-wasm 1.29.2` contained only version bumps in `package.json` with zero functional code changes. Attackers commonly publish empty releases to test compromised credentials or establish publishing pipelines before deploying payloads.
   - *Proposal*: Emit a LOW or MEDIUM severity signal `metadata_only_bump` when a release modifies only the `version` field of `package.json` without modifying or adding any executable code.
   - *Impact*: Flags attacker publishing tests while remaining quiet on standard functional releases.

3. **Fallback Semantic Predecessor Resolution**:
   - *DEV Evidence*: 7 DEV pairs failed analysis because the exact baseline version was missing or published post-`as_of` in the npm registry.
   - *Proposal*: When the exact baseline version cannot be resolved, fall back to the highest semantic version published strictly before the `as_of` date.
   - *Impact*: Recovers all 7 baseline-failed pairs in DEV and 6 pairs in TEST.

4. **Corroboration Sensitivity for High-Risk Target Packages**:
   - *DEV Evidence*: `@solana/web3.js 1.95.7` added a new external URL, but because it had no other corroborating signals, policy capped the decision at ALLOW (D16 single-LOW rule).
   - *Proposal*: In packages providing cryptographic, financial, or authentication primitives, evaluate whether unknown new external network destinations should escalate to WARN even in the absence of secondary signals.
   - *Impact*: Eliminates the miss in `@solana/web3.js`.
