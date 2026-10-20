# Release Sentinel — Time-Decay Analysis (v1.0 Frozen Baseline)

## 1. Protocol & Overview

To understand detector durability over time and diagnose where performance degrades, this document analyzes the frozen **v1.0** detector baseline across time cohorts:
- **DEV (before 2026)**: Disaggregated by calendar quarter (2024-Q4 through 2025-Q4).
- **VAL (2026-01 to 2026-04)**: Disaggregated by calendar month.
- **TEST-A (2026-05 and 2026-06)**: Disaggregated by calendar month (unlocked for aggregate and cluster-level review).
- **TEST-B (2026-07 onward / remainder of TEST)**: Reported strictly as a single aggregate point (per-pair detector outputs strictly held out).

All metrics are computed on the frozen v1.0 run (`data/eval_results_v5.jsonl`, 1,349 pairs, 277 clusters). Recall is reported at both **$\ge$WARN** and **BLOCK**, showing both **Fail-Closed (FC)** and **Evidence-Only (EO)** numbers to separate true signal detection from budget-limit fail-closed fallbacks.

---

## 2. Comprehensive Time-Decay Recall Table

| Time Period | Cohort | Clusters | Pairs | Sample $\ge$WARN (FC / EO) | Sample BLOCK | Cluster Lenient $\ge$WARN (FC / EO) | Cluster Lenient BLOCK | Cluster Macro $\ge$WARN (FC / EO) | Cluster Macro BLOCK |
|:---|:---|:---:|:---:|:---|:---|:---|:---|:---|:---|
| **2024-Q4** | DEV | 5 | 11 | 8 / 11 (72.7%) [EO: 72.7%] | 7 / 11 (63.6%) | 2 / 5 (40.0%) [EO: 40.0%] | 2 / 5 (40.0%) | 40.0% [EO: 40.0%] | 33.3% |
| **2025-Q1** | DEV | 1 | 2 | 1 / 2 (50.0%) [EO: 50.0%] | 0 / 2 (0.0%) | 1 / 1 (100.0%) [EO: 100.0%] | 0 / 1 (0.0%) | 50.0% [EO: 50.0%] | 0.0% |
| **2025-Q2** | DEV | 19 | 23 | 19 / 23 (82.6%) [EO: 82.6%] | 0 / 23 (0.0%) | 19 / 19 (100.0%) [EO: 100.0%] | 0 / 19 (0.0%) | 95.8% [EO: 95.8%] | 0.0% |
| **2025-Q3** | DEV | 39 | 413 | 412 / 413 (99.8%) [EO: 99.5%] | 396 / 413 (95.9%) | 38 / 39 (97.4%) [EO: 94.9%] | 22 / 39 (56.4%) | 97.4% [EO: 94.9%] | 56.4% |
| **2025-Q4** | DEV | 5 | 408 | 408 / 408 (100.0%) [EO: 99.0%] | 404 / 408 (99.0%) | 5 / 5 (100.0%) [EO: 20.0%] | 1 / 5 (20.0%) | 100.0% [EO: 20.0%] | 20.0% |
| *2026-01* | VAL | 0 | 0 | — | — | — | — | — | — |
| **2026-02** | VAL | 1 | 1 | 1 / 1 (100.0%) [EO: 100.0%] | 0 / 1 (0.0%) | 1 / 1 (100.0%) [EO: 100.0%] | 0 / 1 (0.0%) | 100.0% [EO: 100.0%] | 0.0% |
| **2026-03** | VAL | 7 | 71 | 71 / 71 (100.0%) [EO: 100.0%] | 69 / 71 (97.2%) | 7 / 7 (100.0%) [EO: 100.0%] | 5 / 7 (71.4%) | 100.0% [EO: 100.0%] | 71.4% |
| **2026-04** | VAL | 4 | 22 | 22 / 22 (100.0%) [EO: 100.0%] | 21 / 22 (95.5%) | 4 / 4 (100.0%) [EO: 100.0%] | 3 / 4 (75.0%) | 100.0% [EO: 100.0%] | 75.0% |
| **2026-05** | TEST-A | 16 | 215 | 203 / 215 (94.4%) [EO: 93.0%] | 138 / 215 (64.2%) | 9 / 16 (56.2%) [EO: 37.5%] | 4 / 16 (25.0%) | 55.6% [EO: 36.8%] | 24.2% |
| **2026-06** | TEST-A | 82 | 83 | 59 / 83 (71.1%) [EO: 71.1%] | 16 / 83 (19.3%) | 59 / 82 (72.0%) [EO: 72.0%] | 16 / 82 (19.5%) | 72.0% [EO: 72.0%] | 19.5% |
| **TEST-B (Agg.)** | TEST-B | 98 | 100 | 9 / 100 (9.0%) [EO: 9.0%] | 3 / 100 (3.0%) | 7 / 98 (7.1%) [EO: 7.1%] | 3 / 98 (3.1%) | 7.1% [EO: 7.1%] | 3.1% |

---

## 3. Cohort Aggregate Summary

| Cohort | Clusters | Pairs | Sample $\ge$WARN (FC / EO) | Sample BLOCK | Cluster Lenient $\ge$WARN (FC / EO) | Cluster Lenient BLOCK | Cluster Macro $\ge$WARN (FC / EO) | Cluster Macro BLOCK |
|:---|:---:|:---:|:---|:---|:---|:---|:---|:---|
| **DEV** | 69 | 857 | 848 / 857 (98.95%) [EO: 98.37%] | 807 / 857 (94.17%) | 65 / 69 (94.20%) [EO: 86.96%] | 25 / 69 (36.23%) | 92.32% [EO: 85.07%] | 35.75% |
| **VAL** | 12 | 94 | 94 / 94 (100.00%) [EO: 100.00%] | 90 / 94 (95.74%) | 12 / 12 (100.00%) [EO: 100.00%] | 8 / 12 (66.67%) | 100.00% [EO: 100.00%] | 66.67% |
| **TEST-A** | 98 | 298 | 262 / 298 (87.92%) [EO: 86.91%] | 154 / 298 (51.68%) | 68 / 98 (69.39%) [EO: 66.33%] | 20 / 98 (20.41%) | 69.28% [EO: 66.22%] | 20.28% |
| **TEST-B** | 98 | 100 | 9 / 100 (9.00%) [EO: 9.00%] | 3 / 100 (3.00%) | 7 / 98 (7.14%) [EO: 7.14%] | 3 / 98 (3.06%) | 7.14% [EO: 7.14%] | 3.06% |
| **ALL** | 277 | 1,349 | 1,213 / 1,349 (89.92%) [EO: 89.33%] | 1,054 / 1,349 (78.13%) | 152 / 277 (54.87%) [EO: 51.99%] | 56 / 277 (20.22%) | 54.37% [EO: 51.48%] | 20.05% |

---

## 4. Key Diagnostic Observations

1. **Pre-2026 Stability (DEV)**:
   - Throughout 2024 and 2025, sample recall remained consistently high ($98.95\%$ $\ge$WARN, $94.17\%$ BLOCK).
   - In 2025-Q2, 19 of 19 clusters were flagged $\ge$WARN, but 0 reached BLOCK because the attacks relied on single suspicious capabilities (e.g. dynamic code or process execution without secondary corroboration).
   - In 2025-Q3 and 2025-Q4, large campaigns (`cluster_0001` with 404 pairs, `cluster_0002` with 381 pairs) exhibited dense corroboration (install scripts, outbound network, credential file reads), leading to sample BLOCK rates $> 95\%$.

2. **Early 2026 Alignment (VAL)**:
   - VAL (February through April 2026) exhibits near-perfect recall: $100\%$ sample $\ge$WARN, $95.74\%$ sample BLOCK, and $66.67\%$ cluster BLOCK. The campaign patterns in VAL closely mirror the techniques present in DEV (install hooks, token exfiltration, network-based payloads).

3. **Onset of Degradation in Mid-2026 (TEST-A)**:
   - In May 2026, sample $\ge$WARN remained strong ($94.4\%$), but cluster lenient recall dropped to $56.2\%$ and cluster BLOCK to $25.0\%$.
   - In June 2026 (TEST-A portion: 82 clusters), cluster $\ge$WARN was $72.0\%$, but cluster BLOCK dropped to $19.5\%$.
   - Noticeably, Fail-Closed vs Evidence-Only gap was small ($87.92\%$ vs $86.91\%$ on samples), confirming that timeouts or budget truncations are not the primary cause of missed detections in TEST-A.

4. **The Cliff in Late-2026 (TEST-B)**:
   - In TEST-B (98 clusters, 100 pairs), detection collapses completely: only **9 of 100 samples (9.0%)** and **7 of 98 clusters (7.14%)** trigger $\ge$WARN. Only **3 samples (3.0%)** trigger BLOCK.
   - Crucially, Fail-Closed and Evidence-Only metrics are identical (9/100 and 7/98), proving that this collapse is **not** caused by scanner timeouts, resource limits, or incomplete parsing.
   - The drop from $100\%$ (VAL) $\to 69\%$ (TEST-A) $\to 7.1\%$ (TEST-B) indicates a fundamental change in the malicious package updates themselves. Whether this represents uninspectable updates (metadata-only, binary-only, empty diffs, non-JS text) or evasion of JavaScript diff scanning is directly investigated in the Part 2 Detectability Audit.
