# Release Sentinel -- Signal Lift Analysis (v4)

Signal discrimination analysis comparing prevalence across all **800 benign updates** (Tuning Smoke, Validation Smoke, Matched Negatives) vs **80 malicious DEV+VAL clusters**.

Lift is defined as: `(DEV+VAL cluster prevalence) / (benign pair prevalence)`.
- `Lift = inf`: Signal observed in malicious clusters with **0** occurrences across all 800 benign packages (perfect precision).
- `Lift > 1.0`: Signal enriches for malicious behavior.
- `Lift < 1.0`: Signal is more prevalent in benign routine updates than in malicious releases.

## Signal Lift Table

| Rank | Signal | Benign Pairs (out of 800) | DEV+VAL Clusters (out of 80) | Lift | In WARN-Only Clusters (out of 51) |
| :---: | :--- | :---: | :---: | :---: | :---: |
| 1 | `hardcoded_ip` | 0 (0.00%) | 10 (12.5%) | ∞ | 3 |
| 2 | `ci_write` | 0 (0.00%) | 9 (11.2%) | ∞ | 3 |
| 3 | `install_script_executes` | 0 (0.00%) | 6 (7.5%) | ∞ | 0 |
| 4 | `install_script_network` | 0 (0.00%) | 6 (7.5%) | ∞ | 0 |
| 5 | `credential_file_read` | 0 (0.00%) | 4 (5.0%) | ∞ | 0 |
| 6 | `shell_profile_write` | 0 (0.00%) | 2 (2.5%) | ∞ | 0 |
| 7 | `credential_leak` | 0 (0.00%) | 1 (1.2%) | ∞ | 0 |
| 8 | `install_script_credential_read` | 0 (0.00%) | 1 (1.2%) | ∞ | 0 |
| 9 | `unresolvable_dependency` | 0 (0.00%) | 1 (1.2%) | ∞ | 0 |
| 10 | `install_script_added` | 2 (0.25%) | 26 (32.5%) | 130.00x | 6 |
| 11 | `process_exec` | 2 (0.25%) | 9 (11.2%) | 45.00x | 1 |
| 12 | `dynamic_code` | 1 (0.12%) | 4 (5.0%) | 40.00x | 1 |
| 13 | `native_binary_present` | 1 (0.12%) | 4 (5.0%) | 40.00x | 1 |
| 14 | `network_access` | 3 (0.38%) | 8 (10.0%) | 26.67x | 0 |
| 15 | `env_enumeration` | 2 (0.25%) | 4 (5.0%) | 20.00x | 0 |
| 16 | `long_encoded_blob` | 51 (6.38%) | 56 (70.0%) | 10.98x | 39 |
| 17 | `large_size_jump` | 30 (3.75%) | 32 (40.0%) | 10.67x | 19 |
| 18 | `inspection_failed` | 1 (0.12%) | 1 (1.2%) | 10.00x | 0 |
| 19 | `registry_token` | 13 (1.62%) | 13 (16.2%) | 10.00x | 3 |
| 20 | `install_script_changed` | 5 (0.62%) | 4 (5.0%) | 8.00x | 0 |
| 21 | `hardcoded_url` | 27 (3.38%) | 19 (23.8%) | 7.04x | 9 |
| 22 | `install_script_present` | 3 (0.38%) | 2 (2.5%) | 6.67x | 1 |
| 23 | `inspection_incomplete` | 8 (1.00%) | 5 (6.2%) | 6.25x | 4 |
| 24 | `high_entropy_string` | 67 (8.38%) | 41 (51.2%) | 6.12x | 24 |
| 25 | `notable_new_file` | 49 (6.12%) | 24 (30.0%) | 4.90x | 4 |
| 26 | `bin_entry_added` | 3 (0.38%) | 1 (1.2%) | 3.33x | 0 |
| 27 | `bin_entry_changed` | 3 (0.38%) | 1 (1.2%) | 3.33x | 0 |
| 28 | `dependency_removed` | 66 (8.25%) | 6 (7.5%) | 0.91x | 1 |
| 29 | `new_files_summary` | 149 (18.62%) | 12 (15.0%) | 0.81x | 1 |
| 30 | `large_file_count_jump` | 15 (1.88%) | 1 (1.2%) | 0.67x | 1 |
| 31 | `dependency_added` | 98 (12.25%) | 5 (6.2%) | 0.51x | 2 |
| 32 | `dependency_version_changed` | 362 (45.25%) | 7 (8.8%) | 0.19x | 2 |
| 33 | `env_harvesting` | 2 (0.25%) | 0 (0.0%) | 0.00x | 0 |
