# Release Sentinel — Stage 5b Frozen v1.0 Evaluation Report (v5)

This report presents the final frozen evaluation results for **Release Sentinel v1.0**, incorporating:
1. **General Rule Gaps**: Inline lifecycle command downloader/shell-pipe analysis, CI workflow injection detection, and obfuscated code detection in non-minified source.
2. **Policy Variant 3 Selection**: Pairwise corroborations for CI workflow injection and behavior-corroborated obfuscation.
3. **Reconciled Dependency Resolution Tracking**: Verified exact counts for direct runtime dependencies added in updates.
4. **Walk-Forward TEST Split**: Held-out TEST ($\ge 2026-05-01$, 196 clusters) partitioned into chronological sub-cohorts **TEST-A** (98 clusters) and **TEST-B** (98 clusters), reported strictly as aggregates.

---

## 1. Headline Numbers

### 1.1 Sample-Level Recall

Total Malicious Eval Pairs: **1,349** (DEV: 857, VAL: 94, TEST: 398 [TEST-A: 298, TEST-B: 100])

| Split | Total Pairs | Fail-Closed $\ge$WARN | Fail-Closed BLOCK | Evidence-Only $\ge$WARN | Evidence-Only BLOCK |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **ALL** | 1,349 | **1,213 (89.92%)** | **1,054 (78.13%)** | **1,205 (89.33%)** | **1,054 (78.13%)** |
| **DEV** | 857 | **848 (98.95%)** | **807 (94.17%)** | **843 (98.37%)** | **807 (94.17%)** |
| **VAL** | 94 | **94 (100.00%)** | **90 (95.74%)** | **94 (100.00%)** | **90 (95.74%)** |
| **TEST-ALL** *(Aggregates Only)* | 398 | **271 (68.09%)** | **157 (39.45%)** | **268 (67.34%)** | **157 (39.45%)** |
| **TEST-A** *(Aggregates Only)* | 298 | **262 (87.92%)** | **154 (51.68%)** | **259 (86.91%)** | **154 (51.68%)** |
| **TEST-B** *(Aggregates Only)* | 100 | **9 (9.00%)** | **3 (3.00%)** | **9 (9.00%)** | **3 (3.00%)** |

---

### 1.2 Cluster-Level Recall (Lenient and Macro)

Total Campaign Clusters: **277** (DEV: 69, VAL: 12, TEST: 196 [TEST-A: 98, TEST-B: 98])  
Largest cluster share: **404 pairs (29.95%)**

#### Lenient Cluster Recall ($\ge 1$ pair in cluster detected)

| Split | Clusters | Fail-Closed $\ge$WARN | Fail-Closed BLOCK | Evidence-Only $\ge$WARN | Evidence-Only BLOCK |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **ALL** | 277 | **152 (54.87%)** | **56 (20.22%)** | **144 (51.99%)** | **56 (20.22%)** |
| **DEV** | 69 | **65 (94.20%)** | **25 (36.23%)** | **60 (86.96%)** | **25 (36.23%)** |
| **VAL** | 12 | **12 (100.00%)** | **8 (66.67%)** | **12 (100.00%)** | **8 (66.67%)** |
| **TEST-ALL** *(Aggregates Only)* | 196 | **75 (38.27%)** | **23 (11.73%)** | **72 (36.73%)** | **23 (11.73%)** |
| **TEST-A** *(Aggregates Only)* | 98 | **68 (69.39%)** | **20 (20.41%)** | **65 (66.33%)** | **20 (20.41%)** |
| **TEST-B** *(Aggregates Only)* | 98 | **7 (7.14%)** | **3 (3.06%)** | **7 (7.14%)** | **3 (3.06%)** |

#### Macro-Averaged Cluster Recall (Mean pair recall across clusters)

| Split | Clusters | Macro Fail-Closed $\ge$WARN | Macro Fail-Closed BLOCK | Macro Evidence-Only $\ge$WARN | Macro Evidence-Only BLOCK |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **ALL** | 277 | **54.37%** | **20.05%** | **51.48%** | **20.05%** |
| **DEV** | 69 | **92.32%** | **35.75%** | **85.07%** | **35.75%** |
| **VAL** | 12 | **100.00%** | **66.67%** | **100.00%** | **66.67%** |
| **TEST-ALL** *(Aggregates Only)* | 196 | **38.21%** | **11.67%** | **36.68%** | **11.67%** |
| **TEST-A** *(Aggregates Only)* | 98 | **69.28%** | **20.28%** | **66.22%** | **20.28%** |
| **TEST-B** *(Aggregates Only)* | 98 | **7.14%** | **3.06%** | **7.14%** | **3.06%** |

---

## 2. Dependency Resolution Statistics (Reconciled)

Across the 1,349 malicious evaluation updates:
- **Releases Adding Direct Runtime Dependencies**: **153 releases**
- **Dependencies Resolved Live from npm Registry**: **160 dependencies**
- **Dependencies Replayed from Local Dataset**: **1 dependency** (`plain-crypto-js@^4.2.1` via `axios@1.14.1`)
- **Dependencies Unresolvable**: **2 dependencies** (`@vant/use@workspace:^` in `vant@2.13.3` and `vant@2.13.4` due to workspace protocol specifiers)
- **Dependencies Skipped (Over Per-Release Limit)**: **0 dependencies** (no release added $> 5$ runtime dependencies; maximum was 3)

---

## 3. Benign Gate & Alert Burden (800 Updates)

Evaluated under frozen default policy (`data/policy_default.toml`):

| Benign Set | Updates | ALLOW | WARN | BLOCK | Alert Burden (WARN+BLOCK) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Tuning Smoke** | 100 | 89 | 11 | **0** | **11.0 alerts / 100** |
| **Validation Smoke** | 100 | 93 | 7 | **0** | **7.0 alerts / 100** |
| **Matched Negatives** | 600 | 497 | 103 | **0** | **17.17 alerts / 100** |
| **Total Benign** | **800** | **679** | **121** | **0** | **15.13 alerts / 100** |

- **Total False BLOCKs**: **0** (0.00% empirical false block rate).
- **Statistical Upper Bound (95% Confidence)**:
  By the Rule of Three, $p_{95\%} \approx 3/800 = \mathbf{0.375\%}$ (exact Clopper-Pearson: $\mathbf{0.3737\%}$, or $< 3.74$ per 1,000 updates).

---

## 4. Operational Robustness

- **Total Pairs Evaluated**: 1,349
- **OK Status**: 1,337 (99.11%)
- **Inspection Incomplete (Fail-Closed)**: 12 (0.89%)
  - 8 pairs hit the 60.0s safety time limit (`@asyncapi/studio@1.0.2`, `@asyncapi/studio@1.0.3`, `@posthog/variance-plugin@0.0.8`, `@strapbuild/react-native-perspective-image-cropper@0.4.15`, `@uipath/ap-chat@1.5.7`, `@uipath/apollo-core@5.9.2`, `@uipath/apollo-react@4.24.5`, `duckdb@1.3.3`).
  - 4 pairs triggered resource size/budget caps.
- **Unhandled Exceptions / Errors**: **0** (0.00%)
- **Largest Cluster Share**: 404 pairs (29.95% of dataset).

---

## 5. Frozen Release Hashes

- `src/release_sentinel/differ.py`: `d2f242fba6e701b159e3d1431c175be4880784cec7c5adc89e39b59bc308807a`
- `src/release_sentinel/content_scanner.py`: `cd718fbd17380d81065397d0a417899fac65ec13c3adaeea3e02ea21ee6f0cdc`
- `data/policy_default.toml`: `64ae77647929a616fa127181d659ccaf648c0fdc654a7fb1396df3351f172d8d`
- **Combined SHA-256**: `5cc63ec781c5f7a05c366701b0a41c59c9220287edb5f68247ae9b6df50cb7d7`
- **Git Tag**: `v1.0`
