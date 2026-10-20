# Release Sentinel -- Corrected Signal Lift Analysis (v1.0 / Stage 5c)

Signal discrimination analysis comparing prevalence across all **800 real benign updates** (Tuning Smoke, Validation Smoke, Matched Negatives) vs **179 unlocked malicious clusters** (DEV: 69, VAL: 12, TEST-A: 98).

## 1. Methodology & Mathematical Definitions

- **Benign Prevalence**: $p_{\text{benign}} = a / N_{\text{benign}}$, where $N_{\text{benign}} = 800$.
- **Malicious Any-Member Prevalence**: $p_{\text{mal, any}} = b / N_{\text{mal}}$, where $b$ is the number of unlocked clusters containing $\ge 1$ release with the signal ($N_{\text{mal}} = 179$).
- **Malicious Cluster-Macro Prevalence**: $p_{\text{mal, macro}} = \frac{1}{N_{\text{mal}}} \sum_{i=1}^{N_{\text{mal}}} \frac{k_i}{m_i}$, where $k_i$ is the number of pairs in cluster $i$ with the signal out of $m_i$ total pairs in that cluster. This measures typical prevalence across independent campaigns without distortion from large campaigns (e.g. cluster_0001 with 404 pairs).
- **Empirical Lift**: $\text{Lift} = \frac{b / N_{\text{mal}}}{a / N_{\text{benign}}}$.
  - $\text{Lift} = \infty$: Signal observed in malicious campaigns with **zero** occurrences across all 800 benign updates (pure attack indicator).
  - $\text{Lift} > 1.0$: Signal enriches for malicious releases.
  - $\text{Lift} < 1.0$: Signal is more prevalent in routine legitimate updates than in malware campaigns.

> [!NOTE]
> **Bug Fix Note**: In the Stage 5b report, a calculation error divided the malicious cluster fraction by a benign percentage rather than a fraction (e.g. $0.7625 / 1.5 = 0.508$), artificially deflating lift values by $100\times$. The table below computes all metrics programmatically using consistent decimal fractions and reports both any-member and cluster-macro prevalence.

## 2. Corrected Signal Lift Table (DEV + VAL + TEST-A)

| Rank | Signal | Benign (N=800) | Malicious Any (N=179) | Malicious Macro | Lift (Any) | Lift (Macro) | In WARN-Only Clusters (N=92) |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | `install_script_network` | 0 (0.00%) | 12/179 (6.7%) | 6.02% | **∞** | ∞ | 0 |
| 2 | `install_script_executes` | 0 (0.00%) | 11/179 (6.1%) | 5.75% | **∞** | ∞ | 0 |
| 3 | `hardcoded_ip` | 0 (0.00%) | 11/179 (6.1%) | 5.74% | **∞** | ∞ | 1 |
| 4 | `ci_write` | 0 (0.00%) | 9/179 (5.0%) | 4.82% | **∞** | ∞ | 0 |
| 5 | `credential_file_read` | 0 (0.00%) | 4/179 (2.2%) | 1.87% | **∞** | ∞ | 0 |
| 6 | `shell_profile_write` | 0 (0.00%) | 2/179 (1.1%) | 1.12% | **∞** | ∞ | 0 |
| 7 | `unresolvable_dependency` | 0 (0.00%) | 1/179 (0.6%) | 0.22% | **∞** | ∞ | 0 |
| 8 | `credential_leak` | 0 (0.00%) | 1/179 (0.6%) | 0.16% | **∞** | ∞ | 0 |
| 9 | `install_script_credential_read` | 0 (0.00%) | 1/179 (0.6%) | 0.16% | **∞** | ∞ | 0 |
| 10 | `obfuscated_code` | 0 (0.00%) | 1/179 (0.6%) | 0.01% | **∞** | ∞ | 0 |
| 11 | `dynamic_code` | 1 (0.12%) | 60/179 (33.5%) | 33.45% | **268.16x** | 267.64x | 41 |
| 12 | `install_script_added` | 2 (0.25%) | 46/179 (25.7%) | 25.02% | **102.79x** | 100.09x | 1 |
| 13 | `process_exec` | 2 (0.25%) | 12/179 (6.7%) | 6.40% | **26.82x** | 25.59x | 1 |
| 14 | `inspection_failed` | 1 (0.12%) | 4/179 (2.2%) | 1.68% | **17.88x** | 13.42x | 3 |
| 15 | `network_access` | 3 (0.38%) | 10/179 (5.6%) | 4.60% | **14.90x** | 12.26x | 1 |
| 16 | `native_binary_present` | 1 (0.12%) | 3/179 (1.7%) | 1.20% | **13.41x** | 9.58x | 0 |
| 17 | `large_size_jump` | 30 (3.75%) | 83/179 (46.4%) | 43.94% | **12.36x** | 11.72x | 48 |
| 18 | `long_encoded_blob` | 51 (6.38%) | 119/179 (66.5%) | 65.48% | **10.43x** | 10.27x | 80 |
| 19 | `env_enumeration` | 2 (0.25%) | 4/179 (2.2%) | 1.71% | **8.94x** | 6.85x | 0 |
| 20 | `notable_new_file` | 49 (6.12%) | 76/179 (42.5%) | 41.92% | **6.93x** | 6.84x | 44 |
| 21 | `inspection_incomplete` | 8 (1.00%) | 11/179 (6.1%) | 5.05% | **6.15x** | 5.05x | 9 |
| 22 | `install_script_present` | 3 (0.38%) | 4/179 (2.2%) | 1.17% | **5.96x** | 3.13x | 2 |
| 23 | `registry_token` | 13 (1.62%) | 13/179 (7.3%) | 6.70% | **4.47x** | 4.13x | 0 |
| 24 | `install_script_changed` | 5 (0.62%) | 4/179 (2.2%) | 0.26% | **3.58x** | 0.41x | 0 |
| 25 | `hardcoded_url` | 27 (3.38%) | 20/179 (11.2%) | 10.24% | **3.31x** | 3.03x | 2 |
| 26 | `high_entropy_string` | 67 (8.38%) | 46/179 (25.7%) | 24.63% | **3.07x** | 2.94x | 23 |
| 27 | `new_files_summary` | 149 (18.62%) | 61/179 (34.1%) | 32.54% | **1.83x** | 1.75x | 41 |
| 28 | `dependency_added` | 98 (12.25%) | 37/179 (20.7%) | 19.60% | **1.69x** | 1.60x | 3 |
| 29 | `bin_entry_added` | 3 (0.38%) | 1/179 (0.6%) | 0.56% | **1.49x** | 1.49x | 0 |
| 30 | `bin_entry_changed` | 3 (0.38%) | 1/179 (0.6%) | 0.56% | **1.49x** | 1.49x | 0 |
| 31 | `dependency_removed` | 66 (8.25%) | 7/179 (3.9%) | 3.46% | **0.47x** | 0.42x | 1 |
| 32 | `large_file_count_jump` | 15 (1.88%) | 1/179 (0.6%) | 0.11% | **0.30x** | 0.06x | 1 |
| 33 | `dependency_version_changed` | 362 (45.25%) | 9/179 (5.0%) | 2.77% | **0.11x** | 0.06x | 2 |
| 34 | `env_harvesting` | 2 (0.25%) | 0/179 (0.0%) | 0.00% | **0.00x** | 0.00x | 0 |
