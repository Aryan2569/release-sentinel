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




