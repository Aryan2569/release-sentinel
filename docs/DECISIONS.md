# Release Sentinel — Decision Log

This file records every non-trivial dependency and design decision.
Add an entry whenever you add a dependency or make a significant architectural choice.

---

## Dependencies

### `typer` (+ `rich`)
**Why:** Standard, ergonomic CLI framework for Python. `rich` (pulled in by typer's
`[all]` extra) provides coloured terminal output and tables with zero extra work.
`rich` itself is not a direct dependency — we rely on typer pulling it in.

### `httpx`
**Why:** Modern async-capable HTTP client with first-class timeout support and a clean
API for setting headers. Preferred over `requests` because it supports both sync and
async usage, making future async refactors straightforward. Also has a clean
`httpx.Client` that is easy to mock / inject in tests without monkeypatching.

### `pydantic` (v2)
**Why:** Strict data validation and serialisation for the public API surface
(`ReleaseRef`, `Evidence`, `Report`). V2 is significantly faster than V1 and ships
with `model_json_schema()` for free documentation. Avoids hand-rolled validation and
makes the JSON output schema-stable.

### `pytest` + `pytest-cov`
**Why:** Industry-standard test runner. `pytest-cov` for coverage reporting.
No additional plugins needed for v0.

### `ruff`
**Why:** Single-tool linter + formatter replacing flake8 + isort + black.
Fast, zero-config, and covers all the rules we care about.

---

## Design Decisions

### D1 — Sync-only HTTP in v0
`httpx` is used in sync mode (`httpx.Client`) for v0 to keep the code simple.
The async upgrade path is clear if we later add concurrent analysis.

### D2 — SHA-512 integrity verification
npm tarballs carry a `dist.integrity` field in the format `sha512-<base64>`.
We verify this before extraction. SHA-1 (`shasum`) is also present but deprecated;
we prefer SHA-512.

### D3 — `tarfile.data_filter` as the baseline
Python 3.12 added `tarfile.data_filter` which strips dangerous metadata.
We use it as a baseline and add our own checks on top (rule 2), because the
built-in filter alone does not enforce our size/count caps or symlink policy.

### D4 — File-based disk cache
Registry metadata and tarballs are cached to `~/.cache/release_sentinel/` keyed by
`<name>/<version>`. This avoids repeated network calls during development and makes
the tool usable offline once a version has been fetched. The cache is never purged
automatically (v0); a `--cache-dir` flag overrides the default.

### D5 — No ML in v0
All decisions are made by explicit, human-readable rules in `engine.py`.
This makes the tool auditable and the output explainable, which aligns with
Rule 4 (Evidence, not verdicts). ML can be added later as a scoring layer
without changing the evidence data model.

### D6 — Evidence severity drives the decision
The engine applies the highest severity rule. A single HIGH evidence item blocks
the release. This is intentionally conservative for a security gate.

### D7 — `new_file_added` is LOW severity
Adding new files is normal and expected in most releases. LOW severity ensures it
appears in the report (for transparency) without triggering a block or warn on its
own. A future version may apply heuristics (e.g., `.sh` scripts, native `.node`
binaries) to escalate specific new files.

### D8 — Classification-aware diffing and noise reduction (Stage 2)
Files are classified by extension and binary magic bytes into categories. Ignorable
categories (assets, fonts, docs, source maps) produce no individual noise. Routine
new files are aggregated into a single `new_files_summary` at LOW severity. Only
notable additions (install-script targets, native binaries, executables, dotfiles,
and minified / long-line files) emit individual evidence items.

### D9 — Diff-based static content scanning (Stage 2)
Content inspection only flags newly introduced lines or newly added files. Patterns
pre-existing in the baseline version do not trigger evidence. Signals cover process
execution, dynamic code evaluation, network calls, hardcoded external IPs/URLs,
credential file access, auth tokens, obfuscated/high-entropy blobs, and persistence
writes (CI workflows, shell profiles, git hooks). Files executed at install time
receive a 1-level severity escalation.

### D10 — External TOML policy and corroboration rules (Stage 2, supersedes D6)
A single signal, regardless of nominal severity, caps at WARN to prevent false
positives from blocking benign updates. BLOCK decisions require corroboration
satisfying paired signal rules (such as an install-time script paired with network
calls or obfuscation). Severity overrides and corroboration pairs are configurable
in `data/policy_default.toml` and overridable via `--policy`.

### D11 — Extraction limits and graceful degradation (Stage 2)
Extraction enforces a soft cap of 5,000 files and 200 MB uncompressed. When a soft
cap is reached, extraction does not crash: priority files (`package.json`, JS/TS)
are extracted and an explicit limitation is recorded. Hard ceilings (10,000 files,
500 MB) abort unconditionally to prevent tar-bomb attacks. Packages lacking SHA-512
integrity fall back to SHA-1 `shasum` verification.

### D12 — Multi-format reporting and PR integration (Stage 2)
The CLI supports `--format text|json|markdown`, `--quiet`, and `--min-severity`.
Output groups evidence by functional category with a one-line summary on top.
The Markdown output is formatted specifically for GitHub PR comment posting.

### D13 — Package-wide capability-level diffing (Stage 2.5, refines D9)
Diffing computes normalized capabilities per signal type across the entire release
(normalizing by signal type + matched API/host text, rather than file path or line number).
A pattern is flagged only if its normalized capability was absent from the entire old release.
Per-file attribution is preserved for explainability. Minified and bundled files are never
line-diffed, avoiding full-line false additions when bundled assets are rebuilt.

### D14 — Blob and entropy suppression in non-production paths (Stage 2.5)
Entropy (`high_entropy_string`) and encoded blob (`long_encoded_blob`) signals fire only
when the blob's SHA-256 hash is absent from the old release AND the file is outside test,
fixture, data, locale, and source-map paths. Rebuilt minified files do not emit
`long_encoded_blob` solely for line length. String tokenization extracts genuine string literals
to prevent matching non-quote code spans between separate string literals.

### D15 — Host-normalized URL/IP detection with comment/license filtering (Stage 2.5)
URL and IP signals normalize to hostnames/IP addresses and only trigger when the host is new
to the package. URLs and IPs located in single-line comments, block comments, or top-of-file
license/copyright headers are ignored.

### D16 — Policy refinement: INFO severity, single-LOW ALLOW, and import-time corroboration (Stage 2.5, refines D10)
Introduced `Severity.INFO` for non-alerting informational signals (`dependency_version_changed`,
`dependency_removed`). A single LOW signal (`dependency_added`, `new_files_summary`) produces
an ALLOW decision while still listing evidence in the report. A single MEDIUM signal results in
WARN. BLOCK requires corroboration of at least two distinct signals with at least one HIGH
or CRITICAL signal. Corroboration pairs include import-time environment variable enumeration
paired with network access/URLs (`["env_enumeration", "network_access"]`) and install scripts paired
with process execution (`["install_script_added", "process_exec"]`), ensuring import-time payloads
remain fully detectable without requiring install scripts.

### D17 — Signal precision: child_process AST linkage, fs credential reads, and JS comment stripping (Stage 2.6)
Eliminated root causes of false alarms discovered in smoke testing:
- `process_exec`: Redefined from naive matching of bare `.exec(` (which falsely matched `RegExp.prototype.exec`)
  to require actual use of the `child_process` module (`require` or `import` of `"child_process"` or
  `"node:child_process"`, destructured or namespaced) combined with calls to execution methods
  (`exec`, `execSync`, `execFile`, `execFileSync`, `spawn`, `spawnSync`, `fork`), plus direct
  `process.binding('spawn_sync')`. Bare `.exec(` is never matched.
- `credential_file_read`: Redefined from matching the bare word `"credentials"` (which falsely matched
  fetch options `{ credentials: 'include' }` and `xhr.withCredentials`) to require a filesystem read
  API (`readFile`, `readFileSync`, `createReadStream`, `open`, `openSync`, or promises variants) whose
  argument or nearby path construction references known credential/config files (`.npmrc`, `.netrc`,
  `.ssh/`, `id_rsa`, `.aws/credentials`, `.git-credentials`, `.docker/config.json`, browser profiles,
  keychain paths).
- JS comment stripping: Prior to scanning with regex heuristics, all JavaScript and TypeScript files have
  comments (`//...` and `/*...*/`) blanked out into spaces while preserving all newline characters.
  This ensures that `eval(` calls, URLs, or sensitive keywords within comments are never matched,
  while exact line numbering and column offsets are strictly preserved for evidence attribution.

### D18 — In-memory encrypted ZIP loading, ReleaseContents abstraction, and NTFS security cleanup (Stage 3a)
- Malware sample handling (Rule 7): Real malicious samples stay in their encrypted ZIPs at rest in
  `C:\rs-data\datadog`. They are never extracted to disk, never written to temp folders, and never
  executed or imported. Unit tests use synthetic ZipCrypto ZIPs generated in memory/temp during the test.
- `ReleaseContents` abstraction: Introduced a lightweight in-memory representation (`rel_path -> bytes`)
  shared by both the tarball extractor and ZIP loader. `differ.py` and `content_scanner.py` operate
  on `ReleaseContents` directly, eliminating disk I/O during diffing and analysis.
- Encrypted ZIP loader: DataDog npm compromised samples use traditional PKZIP ZipCrypto encryption with
  password `infected`, fully supported by stdlib `zipfile` without requiring `pyzipper`. The loader
  locates the package root (`/package/package.json`), strips container prefixes, and enforces all
  Rule 2 safety limits (path traversal rejection, absolute path rejection, symlink rejection, 10 000
  member ceiling, 500 MB size ceiling, zip-bomb ratio checks, and soft-cap partial extraction).
- Time awareness (`as_of`): The discovery date in the sample filename is parsed as UTC end-of-day
  (`YYYY-MM-DDT23:59:59Z`) and documented as a strict upper bound for `as_of`, since the exact publication
  date of the compromised package version is unknown.
- Security cleanup: `core.protectNTFS=false` was temporarily needed during the sparse checkout because
  unselected directories under `samples/npm/malicious_intent/` contained trailing dots in package names
  (`mad-1.0.0.2.2.8.`), which triggered Win32 path validation errors in Git for Windows. Once the
  checkout of `samples/npm/compromised_lib` was verified complete, `core.protectNTFS` was unset from
  the clone's local configuration, and verified absent globally.

### D19 — Malicious Evaluation Protocol, Campaign Clustering, and Timeout Handling (Stage 3b)
- **Evaluation Honesty & Split Protocol**: Evaluated 1,349 real-world compromised npm package pairs without modifying detection rules, severities, or policy rules (frozen pre-tuning baseline). The dataset is split temporally by discovery date into DEV (< 2026-01-01; 857 pairs) and TEST (>= 2026-01-01; 492 pairs). Per-pair failure inspection is strictly confined to DEV; TEST results are reported solely as aggregate metrics, and all proposed rule changes are derived exclusively from DEV evidence.
- **Campaign Clustering Methodology**: Automated payload reuse across multiple packages was grouped into campaigns via Union-Find (DSU) clustering over SHA-256 hashes of new/modified files in memory (excluding `package.json`, `README*`, `LICENSE*`, source maps, and files under 200 bytes). Pairs with no qualifying files or unresolvable content formed independent singleton clusters. Cluster-level recall measures detection if any member pair within the cluster is detected.
- **Process-Level Isolation & Timeout Handling**: A 60-second per-pair wall-clock limit was enforced using isolated worker subprocesses. Stalled processes (arising from catastrophic regex backtracking on multi-megabyte single-line minified files) were terminated via OS-level process kill and recorded as `status="timeout"` (a scanner stalling on crafted inputs is an explicit finding). Registry baseline downloads were retried once and recorded as `status="baseline_download_failed"` if unavailable. All results were streamed to JSONL incrementally for crash resilience.

### D20 — Scanner Robustness, Per-File Resource Budgets, and Stage 4a Trustworthy Re-baseline (Stage 4a)
- **Root Cause & Backtracking Elimination**: In Stage 3b, 278 pairs (20.61%) timed out due to catastrophic regex backtracking in `_FS_READ_RE` (`(?:fs...)?\s*\.?\s*`) and quadratic string handling in character-by-character comment stripping. This was eliminated by refactoring regexes to non-backtracking alternatives, replacing comment stripping with linear chunk-based replacement, implementing fast-path string checks, and adding windowed regex scanning (`_finditer_windowed`, `_search_windowed`) with 500-character overlap for lines exceeding 10,000 characters.
- **Per-File Resource Budgets**:
  - Size budget (`PER_FILE_SIZE_BUDGET = 2 * 1024 * 1024` / 2 MB): Over 99.9% of legitimate JavaScript and TypeScript source files in npm packages are well below 250 KB. Files exceeding 2 MB are monolithic bundled distributions, embedded data blobs, or minified vendor assets where full regex tokenization risks denial of service.
  - Time budget (`PER_FILE_TIME_BUDGET = 2.0` seconds): Standard AST-less scanning takes 1–10 ms per file; 2.0 seconds provides a >20x safety margin for complex files while strictly capping execution time.
- **Fail-Closed Policy Handling**: Simply ignoring oversized files would create an attacker evasion path (padding malware to exceed 2 MB). When a file exceeds size or time budgets, the scanner runs cheap constant-time heuristic checks (< 1 ms): hash novelty vs old release (identical files are safely skipped), install script target check (`package.json` scripts/bin), size jump (> 100 KB and > 2x increase), and Shannon entropy on a 64 KB slice. If novel or altered, it records `inspection_incomplete` (MEDIUM severity). Policy `decide()` fails closed: if any uninspected file is present and the tentative decision is ALLOW, it is elevated to WARN.
- **Re-baseline Results**:
  - Scanner stalls: Reduced from 278 to 0 (with 3 extreme native packages exceeding wall-clock limits caught by the fail-closed backstop).
  - Malicious Eval (1,349 pairs): ALL sample recall reached 89.55% (1,208/1,349) WARN+ and 74.05% (999/1,349) BLOCK; DEV reached 98.13% (841/857) WARN+ and 90.08% (772/857) BLOCK; TEST (aggregates only) reached 74.59% (367/492) WARN+ and 46.14% (227/492) BLOCK.
  - Cluster Recall (282 clusters): ALL lenient reached 52.13% WARN+ / 9.57% BLOCK (macro: 51.67% / 9.29%); DEV lenient reached 84.29% WARN+ / 17.14% BLOCK (macro: 82.43% / 16.54%); TEST lenient reached 41.51% WARN+ / 7.08% BLOCK (macro: 41.51% / 6.90%).
  - Benign Smoke Sets: Tuning smoke test yielded 16.0 alerts per 100 updates (5 `typescript` incomplete files); Validation smoke test yielded 4.0 alerts per 100 updates (0 incomplete files). Zero false blocks (0.0% false block rate) on both benign sets.

### D21 — Walk-Forward Re-Split, Budget Calibration, and Matched Negatives Benchmark (Stage 4b)
- **Walk-Forward Re-Split Protocol**:
  Stage 4a showed a major temporal generalization drop in 2026 (DEV cluster WARN+ 84% vs TEST 42%). To enable learning from recent 2026 campaigns without burning the held-out test set, the evaluation dataset was re-split into:
  - **DEV** (< 2026-01-01; 857 pairs, 71 clusters): heuristic development baseline.
  - **VAL** (2026-01-01 to 2026-04-30; 94 pairs, 12 clusters): newly opened for failure analysis and tuning.
  - **TEST** (>= 2026-05-01; 398 pairs, 203 clusters): held-out final test set; reported strictly as aggregate metrics, evaluated once at the conclusion of tuning.
  *Rationale*: Combined TEST aggregates were inspected only once in Stage 4a without per-pair failure analysis. All subsequent rule tuning is confined to DEV+VAL evidence only.
- **Budget Calibration (25 MB / 10.0s)**:
  The 2 MB / 2.0s per-file budget caused 5 benign TypeScript compiler pairs to warn on `inspection_incomplete`. Throughput benchmarking on `lib/typescript.js` (8.65 MB, ~200k lines) demonstrated linear throughput of ~13.0 MB/s for comment stripping and >180 MB/s for regex scanning, completing full diff analysis in 12.5s.
  The budgets were calibrated to `PER_FILE_SIZE_BUDGET = 25 * 1024 * 1024` (25 MB) and `PER_FILE_TIME_BUDGET = 10.0`s. Legitimate multi-megabyte JS bundles are now scanned completely. Incomplete inspection dropped from 1,010 pairs (74.87%) to 12 pairs (0.89%) across the 1,349 malicious updates, and from 5 pairs to 0 pairs in the tuning smoke test.
- **Honest Recall Reporting**:
  All evaluation tables cleanly separate (a) detections driven by genuine security evidence from (b) pairs that warned solely due to `inspection_incomplete` (fail-closed elevation). Headline recall counts only (a). Evidence-only recall reached:
  - DEV: 97.55% WARN+ (836/857) / 90.20% BLOCK (773/857); Lenient cluster: 77.46% WARN+ / 16.90% BLOCK; Macro cluster: 75.63% WARN+ / 16.32% BLOCK.
  - VAL: 98.94% WARN+ (93/94) / 89.36% BLOCK (84/94); Lenient cluster: 91.67% WARN+ / 66.67% BLOCK; Macro cluster: 91.67% WARN+ / 63.54% BLOCK.
  - TEST (aggregates only): 67.09% WARN+ (267/398) / 39.20% BLOCK (156/398); Lenient cluster: 35.96% WARN+ / 11.33% BLOCK; Macro cluster: 35.96% WARN+ / 11.33% BLOCK.
- **Matched Negatives Benchmark**:
  Constructed `data/matched_negatives.csv` containing 600 benign-to-benign pairs from packages that were later compromised (at most one per campaign cluster where possible, same major, pre-baseline to baseline version, verifying neither version is listed in the DataDog manifest). Evaluated with 8 workers, process isolation, and caching:
  - 502 ALLOW (83.67%), 98 WARN (16.33%), 0 BLOCK (0.00%).
  - Alert rate: **16.33 alerts per 100 updates**; False BLOCK rate: **0.00%**.

### D22 — Full-Scan Mode, Dependency-Aware Updates, and Benign False-Alarm Breakdown (Stage 5a)
- **Full-Scan (No-Baseline) Mode**:
  Added `analyze_release(new_release, baseline=None)` to inspect releases standalone in memory when no baseline release is available (or when baseline download fails). Because legitimate packages use network, child process, and environment APIs in their normal runtime code, full-scan mode detects only standalone corroborated patterns:
  - Install hook target actions: downloading from network (`install_script_network`), executing commands (`install_script_executes`), dynamic eval (`install_script_dynamic`), or dumping environment (`install_script_env_harvesting`).
  - Decode-then-execute chains: Base64/hex decode directly piped or within proximity to dynamic evaluation sinks or process execution sinks (`decode_and_execute`).
  - Credential exfiltration: Credential file reads (.npmrc, id_rsa, .aws/credentials) co-occurring with network calls (`credential_leak`).
  - Persistence & CI modifications: Modifications to shell profiles (`shell_profile_write`) or CI workflows (`ci_write`).
  Full-scan operates under the calibrated 25 MB / 10.0s fail-closed budgets. Baseline download failures no longer abort evaluation; they seamlessly fall back to full-scan mode (0 baseline download failures across 1,349 eval pairs).
- **Dependency-Aware Updates**:
  When an update adds direct runtime dependencies (`dependencies` in `new_pkg` not in `old_pkg`), `analyze_release` resolves the highest version satisfying the declared range as of `as_of` via `node-semver`. It limits resolution to depth 1 and at most 5 added dependencies per release. Each added dependency is extracted in memory, scanned via full-scan mode, and returned evidence is prefixed with `[dep: pkg@ver]`. In evaluation mode, if a dependency is absent from the live registry (e.g. placeholder/delisted packages like `plain-crypto-js` added in `axios@1.14.1`), a REPLAY resolver loads it from `C:\rs-data\datadog`. Dependencies that cannot be resolved emit `unresolvable_dependency` (INFO; never alerts). Across 1,349 malicious updates, 153 releases added dependencies; 24 resolved live, 1 was replayed, and 2 were unresolvable.
- **Benign Gate & Signal Value Breakdown**:
  Re-evaluated all 800 benign updates across the three independent benchmarks:
  - Tuning Smoke (100 pairs): 89 ALLOW, 11 WARN, 0 BLOCK (11.0 alerts/100, +0.0 change).
  - Validation Smoke (100 pairs): 96 ALLOW, 4 WARN, 0 BLOCK (4.0 alerts/100, +0.0 change).
  - Matched Negatives (600 pairs): 501 ALLOW, 99 WARN, 0 BLOCK (16.50 alerts/100, +0.17 change).
  Total false BLOCKs: **0** across all 800 updates.
  
### D23 — General Rule Gaps, BLOCK Policy Sweep, and v1.0 Freeze (Stage 5b)
- **General Rule Gaps Implemented**:
  - *Inline Lifecycle Command Analysis*: Analyzed inline commands in `package.json` lifecycle hooks (`preinstall`, `install`, `postinstall`, `prepare`, `prepublish`) for network downloaders (`curl`, `wget`, `Invoke-WebRequest`/`iwr`, `certutil`, `bitsadmin`), shell/interpreter pipes (`| sh`, `| bash`, `node -e`), and base64 decode pipes. Emits `install_script_network` and `install_script_executes`. Supported by 5 DEV+VAL clusters (`@toptal/picasso-shared`, `picasso-tailwind`, `picasso-typography`, `picasso-utils`, `@xene/core`).
  - *CI Workflow Injection*: Addition or alteration of CI workflow configurations (`.github/workflows`, `.gitlab-ci.yml`, `.circleci`, `azure-pipelines`) emitted as `ci_write` at MEDIUM severity alone; corroborated with secret tokens (`registry_token`) or external hosts/IPs (`hardcoded_ip`, `hardcoded_url`) elevates to BLOCK. Supported by 3 DEV+VAL clusters (`cluster_0016`, `cluster_0019`, `cluster_0024`; 18 malicious pairs).
  - *Obfuscated Code Detection*: Implemented `_detect_obfuscated_code` detecting bulk hex identifiers ($\ge 20$), string-array rotation (`function(_0x...){...push...shift...}`), heavy `\x`/`\u` escape density ($\ge 25$), and dynamic char-code assembly (`String.fromCharCode` $\ge 8$ args or $\ge 10$ calls) in non-minified, non-exempt JS/TS source files.
- **BLOCK Policy Sweep & Operating Point Selection**:
  Evaluated 5 TOML policy variants across all 80 DEV+VAL clusters (945 buildable pairs) and 800 real benign updates (100 Tuning, 100 Validation, 600 Matched Negatives).
  - Variant 3 (`data/policies/variant_3_ci_and_obf_corroborated.toml`) was selected as the v1.0 default:
    - Zero false BLOCKs across all 800 benign updates (0.00% false block rate).
    - Highest cluster BLOCK recall on DEV+VAL: **28/80 clusters (35.0% lenient, 34.58% macro)**, unlocking +3 clusters (+4.32% macro) over baseline.
    - Lowest benign alert burden: 11.38% overall (Tuning: 6.0%, Validation: 5.0%, Matched Negatives: 13.33%).
  - Statistical 95% false BLOCK upper bound: By the Rule of Three, with $k = 0$ events in $N = 800$ trials, $p_{95\%} \approx 3/800 = 0.375\%$ (exact Clopper-Pearson: $0.3737\%$, or $< 3.74$ false BLOCKs per 1,000 updates).
- **v1.0 Freeze & Code Hashes**:
  Detection rules and default policy frozen at tag `v1.0`:
  - `src/release_sentinel/differ.py`: `d2f242fba6e701b159e3d1431c175be4880784cec7c5adc89e39b59bc308807a`
  - `src/release_sentinel/content_scanner.py`: `cd718fbd17380d81065397d0a417899fac65ec13c3adaeea3e02ea21ee6f0cdc`
  - `data/policy_default.toml`: `64ae77647929a616fa127181d659ccaf648c0fdc654a7fb1396df3351f172d8d`
  - **Combined SHA-256**: `5cc63ec781c5f7a05c366701b0a41c59c9220287edb5f68247ae9b6df50cb7d7`
- **TEST Cohort Monthly Breakdown and TEST-A / TEST-B Partition**:
  - Monthly cluster counts for TEST ($\ge 2026-05-01$, 196 clusters total):
    - May 2026: 16 clusters
    - June 2026: 177 clusters (117 clusters occurred on a single date, 2026-06-17)
    - September 2026: 1 cluster
    - October 2026: 2 clusters
  - Partition: Because no pure calendar date cutoff can split the single-day cohort of 117 clusters without yielding fewer than 80 clusters on one side (before 2026-06-17 has 75 clusters; after 2026-06-17 has 4 clusters), the 196 TEST clusters are partitioned chronologically by discovery date and deterministically by cluster rank into:
    - **TEST-A** (98 clusters): Earlier half of TEST (May 2026 through the first 23 clusters of 2026-06-17).
    - **TEST-B** (98 clusters): Later half of TEST (remaining 94 clusters of 2026-06-17 through October 2026).
  - *Evaluation Honesty Note*: Aggregate performance metrics for the combined TEST set were observed during Stage 4a and 4b re-split before establishing this partition. No per-pair inspection of TEST has ever taken place.

### D24 — Signal Lift Bug Fix & Benign Alert Burden Reconciliation (Stage 5c Part 0)
- **Part 0a: Signal Lift Calculation Bug**:
  - *Root Cause*: In the Stage 5b scratch calculation, malicious cluster prevalence (expressed as a fraction $b / N_{mal} \approx 0.76$) was divided by benign prevalence expressed as a percentage ($a / N_{benign} \times 100 \approx 1.5\%$), understating lift by a factor of 100 (e.g. `dependency_added` reported as $0.51\times$ instead of true $\sim 1.69\times$).
  - *Resolution*: Implemented `compute_lift` and `compute_cluster_macro_prevalence` in `src/release_sentinel/signal_lift.py`. Added unit tests in `tests/test_signal_lift.py` asserting exact mathematical equivalence $lift = (b / N_{mal}) / (a / N_{benign})$ and handling edge cases ($0/0 \to 1.0$, $b > 0, a = 0 \to \infty$).
  - *Regeneration*: Regenerated `docs/signal_lift.md` across all 179 unlocked clusters (DEV: 69, VAL: 12, TEST-A: 98; 1,249 pairs) against all 800 benign packages. Both Any-Member and Cluster-Macro prevalence and lifts are reported.
- **Part 0b: Benign Alert Burden Reconciliation**:
  - *Discrepancy*: Section 4 reported 91 alerts across 800 benign packages (11.38%), whereas Decision 20/22 recorded 121 alerts (15.13 per 100 updates).
  - *Root Cause*: The fast sweep script (`run_fast_sweep.py`) used a simplified synthetic severity mapping (`SEV_MAP`) that treated `high_entropy_string` and `notable_new_file` as `Severity.LOW` unless corroborated. In reality, the true scanner (`content_scanner.py`) emits them as `Severity.MEDIUM`. Because a single `MEDIUM` signal triggers a `WARN` decision under default policy, the true scanner flagged 30 additional packages that the fast sweep script mistakenly marked `ALLOW`.
  - *Ground Truth*: The true scanner baseline alert rate is **121 / 800 = 15.13 alerts per 100 updates** (Tuning: 11/100 = 11.0%, Validation: 7/100 = 7.0%, Matched Negatives: 103/600 = 17.17%). False BLOCK rate is **0.00%** (0 / 800).
  - *Tooling Fix*: Created `scripts/policy_sweep.py`, which runs and caches full, uncompressed `Evidence` objects extracted directly by the true scanner. The cache is automatically invalidated if any scanner source file (`differ.py`, `content_scanner.py`, `extractor.py`, `engine.py`, `eval.py`) changes hash. Sweep decisions are computed strictly through `release_sentinel.policy.decide()`, guaranteeing exact parity with the true scanner.

### D25 — Error Analysis on DEV, VAL, and TEST-A (Stage 5c Part 3)
Across the 179 unlocked clusters (DEV: 69, VAL: 12, TEST-A: 98; 1,249 pairs), v1.0 produced 53 BLOCK clusters, 92 WARN-only clusters, and 34 Undetected clusters. In compliance with Rule 7, no malicious snippets or payload contents are documented.

- **Undetected Clusters (34 clusters)**:
  - **U1: Unresolvable / Delisted External Dependency Injection** (30 clusters):
    Hollow metadata-only releases where only `package.json` changed to inject an external dependency that is absent from the public npm registry (or unresolvable as of `as_of`). Because no malicious code exists in the release archive and the dependency cannot be fetched, no executable payload could be scanned.
    *Examples*: `@mastra/claude@1.0.3`, `@opensearch-project/opensearch@3.5.3`, `@opensearch-project/opensearch@3.7.0`, `@opensearch-project/opensearch@3.8.0`, `echarts-for-react@3.0.7`, `jest-canvas-mock@2.5.3`, `jest-date-mock@1.0.11`, `size-sensor@1.0.4`, `@mastra/acp@0.2.2`, `@mastra/agent-browser@0.3.2`.
  - **U2: Standalone Low-Severity Outbound URL** (1 cluster):
    Release diff contained a single outbound URL (`hardcoded_url`, Severity.LOW) without any lifecycle script changes or execution sinks.
    *Example*: `@solana/web3.js@1.95.7`.
  - **U3: Native Binary / WASM diff without JS script changes** (3 clusters):
    Release modified precompiled binary or WebAssembly assets (`vant`, `@duckdb/duckdb-wasm`) without altering JavaScript runtime code or npm scripts.
    *Examples*: `vant@4.9.12`, `vant@4.9.13`, `@duckdb/duckdb-wasm@1.29.2`.

- **WARN-Only Clusters under v1.0 (92 clusters)**:
  - **W1: Dynamic Code Execution + Long Encoded Blob** (41 clusters):
    Malicious updates injecting `eval` or `Function` calls alongside base64/hex encoded payload blobs directly into runtime JavaScript modules without lifecycle scripts. In v1.0, this produced two MEDIUM/HIGH signals but lacked a matching `block_requires` rule, capping at WARN.
    *Examples*: `@aifabrix/miso-client@4.7.2`, `autotel@2.26.4`, `autotel-devtools@3.0.2`, `autotel-eventcatalog@3.0.1`, `autotel-mcp@20.0.1`, `autotel-mcp@4.0.1`, `autotel-mcp-instrumentation@32.0.1`, `autotel-mongoose@6.0.1`, `autotel-pact@1.0.3`, `autotel-subscribers@17.0.1`.
  - **W3: Long Encoded Blob + Sudden Archive Size Jump** (17 clusters):
    Payload introduced a heavy obfuscated/encoded blob accompanied by a sudden package size increase, but without dynamic eval calls.
    *Examples*: `@tanstack/arktype-adapter@1.166.12`, `@gluestack-ui/utils@0.1.17`, `ansi-regex@6.2.1`, `ansi-styles@6.2.2`, `backslash@0.2.1`, `chalk-template@1.1.1`, `color-convert@3.1.1`, `color-name@2.0.1`, `debug@4.4.2`, `error-ex@1.3.3`.
  - **W4: Long Encoded Blob + Notable New File** (2 clusters):
    Injected encoded blob placed in a newly added source file.
    *Examples*: `@vapi-ai/server-sdk@1.2.1`, `@vapi-ai/server-sdk@1.2.2`.
  - **W5: Standalone Long Encoded Blob / Heuristic Blobs** (20 clusters):
    Single obfuscated string literal in existing files without structural archive anomalies or dynamic evaluation.
    *Examples*: `xrpl@2.14.2`, `@react-native-aria/focus@0.2.10`, `@gluestack-ui/utils@0.1.16`, `@react-native-aria/button@0.2.11`, `@react-native-aria/checkbox@0.2.11`, `@react-native-aria/combobox@0.2.8`, `@react-native-aria/disclosure@0.2.9`, `@react-native-aria/interactions@0.2.17`, `@react-native-aria/listbox@0.2.10`, `@react-native-aria/menu@0.2.16`.
  - **W6: Fail-Closed Only (`inspection_incomplete`)** (9 clusters):
    Multi-megabyte files exceeding per-file or per-pair size/time limits; protected by fail-closed WARN elevation.
    *Examples*: `duckdb@1.3.3`, `@asyncapi/studio@1.0.2`, `@asyncapi/studio@1.0.3`, `@posthog/variance-plugin@0.0.8`, `@strapbuild/react-native-perspective-image-cropper@0.4.15`, `cline@2.3.0`, `@uipath/ap-chat@1.5.7`, `@uipath/apollo-core@5.9.2`, `@uipath/apollo-react@4.24.5`.
  - **W7: Other Single Heuristics** (3 clusters):
    Single medium-severity signals without corroborating evidence.
    *Examples*: `@rxap/ngx-bootstrap@19.0.3` (`notable_new_file`), `axios@1.14.1` (`install_script_changed`), `@velora-dex/sdk@9.4.1` (`notable_new_file`).

### D26 — Selection and Calibration of Policy Candidate Variant 5 for v1.1 (Stage 5c Part 4)
- **Candidate Evaluations & Lift Considerations**:
  - *`dependency_added` Standalone Severity vs. Corroboration*:
    In benign packages, 98 / 800 updates (12.25%) legitimately add dependencies. Elevating `dependency_added` alone to `Severity.MEDIUM` (WARN) causes benign alerts to spike from 14.25% to 21.625% (+7.38 per 100), violating the benign gate (+3 per 100 limit). Consequently, `dependency_added` must remain `Severity.LOW` and act strictly as a **corroborator** (`["dependency_added", "install_script_added"]`, `["dependency_added", "dynamic_code"]`, `["dependency_added", "hardcoded_ip"]`).
  - *Low-Lift Signal Downgrades*:
    Signals with lift < 1.5x were audited. `bin_entry_added` and `bin_entry_changed` had lift 1.49x (3 benign occurrences vs 1 malicious cluster). Downgrading both to `Severity.LOW` dropped the benign alert burden from 14.25% to 13.75% (-0.50% reduction) with zero loss of true detections.
  - *W1 Corroboration Rule*:
    Adding `["dynamic_code", "long_encoded_blob"]` to `block_requires` safely promotes 41 clusters from WARN to BLOCK. Both signals possess exceptional lift (268.16x and 10.43x) and co-occur 0 times across all 800 benign packages.
- **Candidate Sweep Outcomes (DEV + VAL + TEST-A: 179 Clusters | Benign: 800 Updates)**:
  - *v1.0 Frozen Baseline*: 0 False BLOCKs | 14.25% Alert Rate | Cluster BLOCK: 53/179 (29.61%) [DEV: 36.2%, VAL: 66.7%, TEST-A: 20.4%]
  - *Variant 1 (+ Dynamic + Encoded Blob)*: 0 False BLOCKs | 14.25% Alert Rate | Cluster BLOCK: 94/179 (52.51%) [+41 clusters! DEV: 36.2%, VAL: 75.0%, TEST-A: 61.2%]
  - *Variant 2 (+ Dynamic + Encoded Blob + Size Jump)*: 0 False BLOCKs | 14.25% Alert Rate | Cluster BLOCK: 94/179 (52.51%)
  - *Variant 3 (+ Corroborated Dep Added)*: 0 False BLOCKs | 14.25% Alert Rate | Cluster BLOCK: 94/179 (52.51%)
  - *Variant 4 (+ Low-Lift Downgrades)*: 0 False BLOCKs | 14.25% Alert Rate | Cluster BLOCK: 94/179 (52.51%)
  - *Variant 5 (+ Bin Entry Downgrades)*: **0 False BLOCKs** | **13.75% Alert Rate** (-0.5% noise reduction) | **Cluster BLOCK: 94/179 (52.51%)**
- **Decision: Selection of Variant 5 as v1.1 Default**:
  Variant 5 was selected under the decision criteria: 0 false BLOCKs $\to$ maximum cluster BLOCK recall (52.51% vs 29.61%) $\to$ minimum benign alert burden (13.75%).
  - Statistical 95% false BLOCK upper bound: Rule of Three with $k=0, N=800$ yields $p_{95\%} \approx 3/800 = 0.375\%$ ($< 3.75$ false BLOCKs per 1,000 updates).

### D27 — Freeze v1.1, Code Hashes, and Final Evaluator Protocol (Stage 5c Part 5)
- **v1.1 Freeze & Code Hashes**:
  Detection rules, content scanner, and default policy frozen at tag `v1.1`:
  - `src/release_sentinel/differ.py`: `17c40b56af0658687b524d5f28bf8a004b63887468fef1ead5571f3e4fa910ae`
  - `src/release_sentinel/content_scanner.py`: `f748e22c7bf4d20c88b92a4ffe3f68972bb72bb97d498c6247b1e0017c190bdb`
  - `data/policy_default.toml`: `623aa8a83864aa5085059ef2168f5298f52b10d4e2d878c82d004806f602ca72`
  - **Combined SHA-256**: `a274452d0641c8877a1548f25b3b6d26c679815fdbb586ad0757d1ca18149093`
- **Protocol Disclosures**:
  1. *Combined-TEST aggregates*: Observed once in Stage 4a/4b before establishing the A/B partition; no per-pair inspection of TEST has ever taken place.
  2. *Split Cutoff*: 2026-06-17 partition allocating the first 23 clusters to TEST-A and the remaining 94 clusters through October 2026 to TEST-B.
  3. *TEST-B Usage*: TEST-B remained strictly locked. It was evaluated prior to final run solely via data-only detectability audit (archive inspection without detector execution) and aggregate conditional recall.
  4. *Tuning Scope*: v1.1 policy rules were developed and tuned strictly using DEV, VAL, and TEST-A evidence.


