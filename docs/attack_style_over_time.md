# Malicious Attack Style Over Time (Detector-Independent Analysis)

This document analyzes the historical structural evolution of npm supply chain attacks across **1,349 real malicious packages** strictly using **detector-independent ground truth**.

![Attack Style Over Time](attack_style_over_time.png)

---

## 1. Attack Style Evolution by Split

| Split | Sample Size | Adds Runtime Dep | Hollow Release (Zero Code) | Adds Lifecycle Hook | Changes / Injects Code |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **DEV** | 857 | 10 (1.17%) | 0 (0.00%) | 793 (92.53%) | 852 (99.42%) |
| **VAL** | 94 | 1 (1.06%) | 1 (1.06%) | 91 (96.81%) | 92 (97.87%) |
| **TEST-A** | 299 | 51 (17.06%) | 23 (7.69%) | 163 (54.52%) | 270 (90.30%) |
| **TEST-B** | 99 | 94 (94.95%) | 89 (89.90%) | 1 (1.01%) | 10 (10.10%) |

---

## 2. Attack Style Evolution by Calendar Quarter

| Quarter | Samples | Adds Runtime Dep | Hollow Release | Adds Lifecycle Hook | Changes Code | Primary Delivery Mechanism |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **2024-Q4** | 11 | 5 (45.5%) | 0 (0.0%) | 7 (63.6%) | 11 (100.0%) | Transitive dependency addition alongside script hooks |
| **2025-Q1** | 1 | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 1 (100.0%) | Direct JS payload injection |
| **2025-Q2** | 24 | 1 (4.2%) | 0 (0.0%) | 0 (0.0%) | 24 (100.0%) | Direct JS payload injection |
| **2025-Q3** | 413 | 1 (0.2%) | 0 (0.0%) | 378 (91.5%) | 408 (98.8%) | Inline lifecycle command execution (`preinstall` / `install`) |
| **2025-Q4** | 408 | 3 (0.7%) | 0 (0.0%) | 408 (100.0%) | 408 (100.0%) | Inline lifecycle command execution (`preinstall` / `install`) |
| **2026-Q1** | 72 | 1 (1.4%) | 1 (1.4%) | 70 (97.2%) | 70 (97.2%) | Inline lifecycle command execution (`preinstall` / `install`) |
| **2026-Q2** | 415 | 145 (34.9%) | 112 (27.0%) | 184 (44.3%) | 297 (71.6%) | Transitive dependency addition alongside script hooks |
| **2026-Q3** | 3 | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 3 (100.0%) | Direct JS payload injection |
| **2026-Q4** | 2 | 0 (0.0%) | 0 (0.0%) | 1 (50.0%) | 2 (100.0%) | Direct JS payload injection |

---

## 3. Runtime Dependency Resolution Breakdown

How added direct dependencies resolve on the public npm registry today:

| Split | Pairs Adding Dep | Distinct Dep Names | Live Packages | Delisted (npm Placeholder) | 404 / Removed | Other / Unsupported |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **DEV** | 17 | 65 | 64 | 0 | 0 | 1 |
| **VAL** | 1 | 1 | 0 | 1 | 0 | 0 |
| **TEST-A** | 54 | 94 | 94 | 0 | 0 | 0 |
| **TEST-B** | 94 | 4 | 4 | 0 | 0 | 0 |

---

## 4. Key Security Insights

1. **Tactical Regime Shift in 2026-Q3 / Q4**: Prior to 2026, over 90% of attacks executed inline lifecycle scripts or modified JavaScript runtime files directly. In TEST-B (late 2026), 94.95% of attacks completely abandoned code modifications, publishing entirely **hollow metadata releases** that deliver payloads via external dependencies.
2. **Delisting Lag**: 100% of dependencies added in TEST-B were delisted by npm security teams (replaced by security placeholders), leaving zero inspectable malicious JavaScript in retroactive audits. Time-aware gate detection at the point of release is strictly necessary before delisting occurs.