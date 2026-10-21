# Release Sentinel — Stage 5e Comprehensive Evaluation Report (v1.0 vs v1.1 vs v1.2)

This report presents the definitive comparative evaluation of Release Sentinel **v1.0** (tag `v1.0`), **v1.1** (tag `v1.1`), and **v1.2** (tag `v1.2`), incorporating strict protocol disclosure, disjoint campaign assignments, and the lookalike rule audit.

> [!CAUTION]
> **Protocol Disclosure: Post-Hoc Status of v1.2 on TEST-A and TEST-B**:
> The TEST-B split ($\ge 2026-05-01$, second half) was consumed during the final held-out run of v1.1 in Stage 5c. The rules introduced in v1.2 (`hollow_dependency_injection` and `lookalike_dependency_name`) were designed **post-hoc** after observing the detector-independent detectability audit and after specific TEST-B dependency names (`easy-day-js`) were inspected in reporting. Consequently, **ALL v1.2 numbers on TEST-A and TEST-B are post-hoc and must not be cited as held-out generalization evidence**. The post-hoc 92.93% sample BLOCK on TEST-B was driven by sample inspection and is not a held-out result. True held-out generalization must be measured prospectively using `scripts/prospective_eval.py` on samples discovered strictly after today's dataset freeze.

---

## 1. Disjoint Splits & Campaign Accounting

Pairs and campaigns are assigned strictly and disjointly across splits:
- **Pair Assignment Rule**: Assigned individually by ISO `discovery_date`:
  - **DEV**: `discovery_date < "2026-01-01"`: **857 pairs**
  - **VAL**: `"2026-01-01" <= discovery_date <= "2026-04-30"`: **94 pairs**
  - **TEST-A**: `discovery_date >= "2026-05-01"` (cluster ranks 0..97): **299 pairs**
  - **TEST-B**: `discovery_date >= "2026-05-01"` (cluster ranks 98..106): **99 pairs**
  - **ALL**: $857 + 94 + 299 + 99 = \mathbf{1,349\text{ pairs}}$ (100% disjoint)
- **Campaign Assignment Rule**: Assigned to exactly one split by the **earliest discovery date** of any member (`primary_split`):
  - **DEV**: **29 campaigns** (earliest date 2024-12-03 to 2025-11-24)
  - **VAL**: **3 campaigns** (earliest date 2026-02-17 to 2026-04-21)
  - **TEST-A**: **49 campaigns** (earliest date 2026-05-11 to 2026-09-22)
  - **TEST-B**: **3 campaigns** (earliest date 2026-09-23 to 2026-10-08)
  - **ALL**: $29 + 3 + 49 + 3 = \mathbf{84\text{ campaigns}}$ (100% disjoint)

*Note on multi-split campaigns*: Two campaigns spanned discovery dates: `camp_0001` (size 1,211; earliest date 2024-12-03 in DEV) and `camp_0008` (size 10; earliest date 2025-07-17 in DEV). By assigning them strictly to DEV by earliest discovery date, campaign counts across splits sum to exactly 84 (resolving the previous $29+5+50+4=88$ multi-count).

---

## 2. Comprehensive Performance Tables: Samples & Campaigns

### 2.1 Sample-Level Recall (1,349 Pairs)

| Split | Version | Pairs | Fail-Closed $\ge$WARN | Fail-Closed BLOCK | Evidence-Only $\ge$WARN | Evidence-Only BLOCK | Incomplete / Timeouts |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **ALL** | v1.0 | 1,349 | 1,213 (89.92%) | 1,022 (75.76%) | 1,206 (89.40%) | 1,022 (75.76%) | 12 (0.89%) |
| | v1.1 | 1,349 | 1,213 (89.92%) | 1,097 (81.32%) | 1,207 (89.47%) | 1,097 (81.32%) | 10 (0.74%) |
| | **v1.2** *(Post-hoc)* | 1,349 | **1,327 (98.37%)** | **1,202 (89.10%)** | **1,313 (97.33%)** | **1,202 (89.10%)** | **18 (1.33%)** |
| **DEV** | v1.0 | 857 | 848 (98.95%) | 781 (91.13%) | 845 (98.60%) | 781 (91.13%) | 5 (0.58%) |
| *(< 2026-01-01)* | v1.1 | 857 | 848 (98.95%) | 808 (94.28%) | 844 (98.48%) | 808 (94.28%) | 4 (0.47%) |
| | **v1.2** | 857 | **849 (99.07%)** | **801 (93.47%)** | **837 (97.67%)** | **801 (93.47%)** | **13 (1.52%)** |
| **VAL** | v1.0 | 94 | 94 (100.0%) | 84 (89.36%) | 94 (100.0%) | 84 (89.36%) | 0 (0.00%) |
| *(2026-01 to 04)* | v1.1 | 94 | 94 (100.0%) | 91 (96.81%) | 94 (100.0%) | 91 (96.81%) | 0 (0.00%) |
| | **v1.2** | 94 | **94 (100.0%)** | **92 (97.87%)** | **94 (100.0%)** | **92 (97.87%)** | **0 (0.00%)** |
| **TEST-A** | v1.0 | 299 | 262 (87.63%) | 154 (51.51%) | 258 (86.29%) | 154 (51.51%) | 3 (1.00%) |
| *(VAL2)* | v1.1 | 299 | 262 (87.63%) | 195 (65.22%) | 260 (86.96%) | 195 (65.22%) | 2 (0.67%) |
| | **v1.2** *(Post-hoc)* | 299 | **286 (95.65%)** | **217 (72.58%)** | **284 (94.98%)** | **217 (72.58%)** | **2 (0.67%)** |
| **TEST-B** | v1.0 | 99 | 9 (9.09%) | 3 (3.03%) | 9 (9.09%) | 3 (3.03%) | 4 (4.04%) |
| *(Final Held-out)* | v1.1 | 99 | 9 (9.09%) | 3 (3.03%) | 9 (9.09%) | 3 (3.03%) | 4 (4.04%) |
| | **v1.2** *(Post-hoc)* | 99 | **98 (98.99%)** | **92 (92.93%)** | **98 (98.99%)** | **92 (92.93%)** | **3 (3.03%)** |

---

### 2.2 Campaign-Level Recall (Counts $k$ of $n$, Macro, and Clopper-Pearson 95% CI)

> [!NOTE]
> Splits with fewer than 10 campaigns (VAL with $n=3$, TEST-B with $n=3$) are too small for standalone percentages; they are reported as exact counts $k$ of $n$ alongside exact two-sided 95% Clopper-Pearson binomial confidence intervals.

| Split | Version | Campaigns ($n$) | Lenient EO $\ge$WARN ($k/n$) | 95% CI ($\ge$WARN) | Lenient EO BLOCK ($k/n$) | 95% CI (BLOCK) | Macro EO $\ge$WARN | Macro EO BLOCK |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **ALL** | v1.0 | 84 | 75 / 84 (89.29%) | [80.59%, 95.01%] | 7 / 84 (8.33%) | [3.41%, 16.42%] | 88.26% | 6.78% |
| | v1.1 | 84 | 74 / 84 (88.10%) | [79.20%, 94.13%] | 49 / 84 (58.33%) | [47.09%, 68.99%] | 87.08% | 57.25% |
| | **v1.2** *(Post-hoc)*| 84 | **74 / 84 (88.10%)** | [79.20%, 94.13%] | **50 / 84 (59.52%)** | [48.27%, 70.12%] | **87.18%** | **58.54%** |
| **DEV** | v1.0 | 29 | 25 / 29 (86.21%) | [68.34%, 96.11%] | 4 / 29 (13.79%) | [3.89%, 31.66%] | 85.83% | 13.18% |
| | v1.1 | 29 | 24 / 29 (82.76%) | [64.23%, 94.15%] | 6 / 29 (20.69%) | [8.00%, 39.71%] | 82.39% | 20.13% |
| | **v1.2** | 29 | **24 / 29 (82.76%)** | [64.23%, 94.15%] | **6 / 29 (20.69%)** | [8.00%, 39.71%] | **82.69%** | **20.42%** |
| **VAL** | v1.0 | 3 | 3 / 3 | [29.24%, 100.0%] | 1 / 3 | [0.84%, 90.57%] | 100.00% | 20.83% |
| | v1.1 | 3 | 3 / 3 | [29.24%, 100.0%] | 1 / 3 | [0.84%, 90.57%] | 100.00% | 33.33% |
| | **v1.2** | 3 | **3 / 3** | [29.24%, 100.0%] | **2 / 3** | [9.43%, 99.16%] | **100.00%** | **66.67%** |
| **TEST-A**| v1.0 | 49 | 45 / 49 (91.84%) | [80.40%, 97.73%] | 1 / 49 (2.04%) | [0.05%, 10.85%] | 90.31% | 0.51% |
| | v1.1 | 49 | 45 / 49 (91.84%) | [80.40%, 97.73%] | 41 / 49 (83.67%) | [70.34%, 92.68%] | 90.31% | 82.14% |
| | **v1.2** *(Post-hoc)*| 49 | **45 / 49 (91.84%)** | [80.40%, 97.73%] | **41 / 49 (83.67%)** | [70.34%, 92.68%] | **90.31%** | **82.14%** |
| **TEST-B**| v1.0 | 3 | 2 / 3 | [9.43%, 99.16%] | 1 / 3 | [0.84%, 90.57%] | 66.67% | 33.33% |
| | v1.1 | 3 | 2 / 3 | [9.43%, 99.16%] | 1 / 3 | [0.84%, 90.57%] | 66.67% | 33.33% |
| | **v1.2** *(Post-hoc)*| 3 | **2 / 3** | [9.43%, 99.16%] | **1 / 3** | [0.84%, 90.57%] | **66.67%** | **33.33%** |

---

## 3. Lookalike Rule Audit & Over-Merging Investigation

### 3.1 Lookalike Rule Audit (Part 3)
1. **Popularity List (`data/top_npm_packages.json`)**:
   - Contains 226 package names representing popular npm packages across web frameworks, utilities, build tools, and database clients.
2. **Full Affix List**:
   - `_LOOKALIKE_PREFIXES`: `("easy-", "simple-", "plain-", "official-", "open-", "free-", "fast-", "node-", "lib-", "js-")`
   - `_LOOKALIKE_SUFFIXES`: `("-js", "-lib", "-node", "-ts", "-api", ".js", "_js")`
3. **Sample-Derived Contamination Disclosure**:
   - The prefix `"easy-"` was copied directly from inspecting the TEST-B sample `easy-day-js`.
   - **Effect of removing `"easy-"`**: Without `"easy-"`, `easy-day-js` is no longer flagged as a lookalike of `dayjs`. v1.2's post-hoc BLOCK recall on TEST-B drops from 92.93% (92 / 99) back to **3.03% (3 / 99)**, proving that the post-hoc gain on TEST-B was entirely an artifact of sample contamination.
4. **Eligible Benign Population**:
   - In the 800 benign benchmark pairs, exactly **0 pairs** are hollow releases that add a runtime dependency (when legitimate packages add dependencies, code changes accompany them).
   - Because the eligible count is $n = 0$, "0 false BLOCKs out of 800" does not statistically constrain the false positive rate on hollow releases specifically (95% CI upper bound is undefined / 100%). Over all 22 benign pairs adding direct runtime dependencies, 0 false BLOCKs yields an exact 95% upper bound of **15.4%**; over all 91 pairs adding any dependency, 0 false BLOCKs yields **3.96%**.
5. **Benign Dependency Names Flagged by Name Alone**:
   - Across the 91 benign pairs adding dependencies (117 distinct names), exactly **1 package** is flagged by name alone:
     - `commondir` (Levenshtein edit-distance 2 from popular package `commander`).
   - This did not trigger a false BLOCK because `commondir` was added in a legitimate release with code modifications, and single signals are capped at WARN.

### 3.2 Campaign Builder Over-Merging Analysis (Part 1c)
Union-Find over-merging occurred in `camp_0001` (1,211 pairs) because:
1. `added_deps` excluded only dependencies appearing in the 800 benign smoke pairs, failing to exclude common unobserved benign dependencies (e.g., `jsonwebtoken`, `jose`, `openai`, `zustand`, `async-mutex`, `@azure/storage-blob`).
2. Generic lifecycle commands (e.g., `node index.js`, `rm /s /q`) and popular packages acted as hubs in the graph, linking disparate attack clusters across DEV, VAL, TEST-A, and TEST-B into a single component.
3. Breakdown of merges in `camp_0001`:
   - 1,074 merges from payload hashes
   - 168 merges from added dependencies (e.g., `easy-day-js`: 105, `jose`: 4, `jsonwebtoken`: 3)
   - 23 merges from lifecycle commands (`node index.js`: 16)

---

## 4. Benign Benchmark Summary (v1.2)

| Benchmark Set | Pairs | ALLOW | WARN | BLOCK | Alert Rate (/100) | False BLOCK Rate |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Tuning Smoke** | 100 | 89 | 11 | **0** | **11.00** | **0.00%** |
| **Validation Smoke** | 100 | 96 | 4 | **0** | **4.00** | **0.00%** |
| **Matched Negatives** | 600 | 500 | 100 | **0** | **16.67** | **0.00%** |
| **Total Canonical Benign** | **800** | **685 (85.62%)** | **115 (14.38%)** | **0 (0.00%)** | **14.38** | **0.00% (95% CI: $\le 0.373\%$)** |

---

## 5. Frozen Code Hashes

### v1.0 Baseline (Tag `v1.0`):
- `src/release_sentinel/differ.py`: `d2f242fba6e701b159e3d1431c175be4880784cec7c5adc89e39b59bc308807a`
- `src/release_sentinel/content_scanner.py`: `cd718fbd17380d81065397d0a417899fac65ec13c3adaeea3e02ea21ee6f0cdc`
- `data/policy_default.toml`: `64ae77647929a616fa127181d659ccaf648c0fdc654a7fb1396df3351f172d8d`
- **Combined SHA-256**: `5cc63ec781c5f7a05c366701b0a41c59c9220287edb5f68247ae9b6df50cb7d7`

### v1.1 Frozen Release (Tag `v1.1`):
- `src/release_sentinel/differ.py`: `aa70120050bc7630cf564f031733eefbab33a3350795cd46d8717994c02aa07a`
- `src/release_sentinel/content_scanner.py`: `ac00c54011c6be7af27664fdf219d029e75a5c340d37686c160602610c093d11`
- `data/policy_default.toml`: `a054dc8c35496420e4b99b6643ed0e13343412cdee845366124f4d2eb0a71898`
- **Combined SHA-256**: `863bb4e12846950b0c934d0e5b5c8443f8643ac8280a510770023320e980418e`

### v1.2 Post-hoc Release (Tag `v1.2`):
- `src/release_sentinel/differ.py`: `8f3588c90d7b6ce4ff5c3208d6c1ca0e06aa10726ca2c70baf3bba06cd06f12d`
- `src/release_sentinel/content_scanner.py`: `ac00c54011c6be7af27664fdf219d029e75a5c340d37686c160602610c093d11`
- `data/policy_default.toml`: `c4acc81afd3bc9503119e0738bcf07157aab615f1688a890529e878252f4dc64`
- **Combined SHA-256**: `5ed1ecb3e93723f35386a23927d5c557b7f40a7efe4e2777e25c71b41d9e0359`
