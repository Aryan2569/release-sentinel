# Release Sentinel: Technical Deep Dive & System Architecture (20 Interview Q&As)

---

### Q1: What problem does Release Sentinel solve, and why is software supply chain defense uniquely difficult?
**Answer**:
Release Sentinel secures the open-source software supply chain by inspecting package release updates (e.g. on `npm`) *before* they are installed into build pipelines or production servers. 
Supply chain attacks are uniquely difficult because:
1. **Legitimate Distribution Channel**: Attackers compromise legitimate publisher credentials or use account takeovers, publishing malware through the official registry (`registry.npmjs.org`).
2. **Install-Time Execution**: Package managers like `npm` execute lifecycle scripts (`preinstall`, `install`, `postinstall`) automatically with full system permissions upon installation.
3. **No Known Signatures**: Supply-chain attack payloads are customized, transient, and never appear in traditional antivirus signature databases.
4. **Extreme Downstream Reach**: A single compromised utility package can automatically propagate to thousands of organizations within minutes.

---

### Q2: Why choose static diffing over dynamic runtime sandboxing?
**Answer**:
Dynamic sandboxing (executing the package in a disposable VM or container) has severe structural limitations in supply-chain defense:
- **Sandbox Evasion**: Attackers easily detect virtualized environments, check CI environment variables, sleep for hours, or remain dormant unless specific production hostnames are present.
- **Latency & Cost**: Spinning up isolated sandboxes takes seconds to minutes per package, whereas Release Sentinel diffs releases statically in memory in under 0.2 seconds.
- **Flaky Environmental Dependencies**: Legitimate packages may fail to build in a generic sandbox due to missing system headers or architecture differences, creating false-positive execution failures.
Static diffing compares the abstract syntax and structural differences between the new release and its clean historical baseline, detecting dangerous behavioral capabilities without ever risking code execution.

---

### Q3: What is Rule 1 (Zero Code Execution) and how is it technically enforced?
**Answer**:
Rule 1 mandates that no package code is ever executed under any circumstances:
- Neither `node`, `npm`, `npx`, nor shell interpreters are ever invoked on package contents.
- Scripts in `package.json` are never run.
- JavaScript and TypeScript files are analyzed using static regex-based tokenizers and heuristics over string contents.
- Python never imports or evals any file from the untrusted tarball or zip archive.

---

### Q4: How does Release Sentinel defend against malicious archives (Rule 2: Path Traversal, Absolute Paths, Zip Bombs)?
**Answer**:
Untrusted archives can compromise the host machine before analysis even begins. Release Sentinel enforces defensive boundaries in memory:
- **Path Traversal Check**: Every archive entry is inspected using `PurePosixPath`. Any member whose path components include `..` or start with `/` or Windows drive letters (`C:`) is immediately rejected with `ExtractionError`.
- **Symlink Disallowance**: Symlink header flags (such as Unix `0o120000`) are explicitly rejected to prevent symlink race conditions.
- **Hard Ceilings**: Extraction aborts if member count exceeds 10,000 files or total uncompressed size exceeds 500 MB.
- **Zip Bomb Ratio**: Every member's uncompressed-to-compressed ratio is checked; ratios exceeding 100:1 for files $> 1$ MB trigger an extraction rejection.
- **In-Memory Streaming**: Malicious archives are never written to disk; members are read directly into memory buffers as `ReleaseContents`.

---

### Q5: What is time-bounding (`as_of`) and why is it essential to prevent look-ahead bias (Rule 3)?
**Answer**:
When evaluating a past attack (say, from May 2025), querying the public npm registry naively would return metadata, versions, and dependencies as they exist *today* (in 2026). This introduces severe **look-ahead bias**:
- The baseline version chosen might have been published *after* the attack.
- Transitive dependencies might have been updated, patched, or delisted.
Under Rule 3, every registry operation takes an explicit cut-off timestamp (`as_of = discovery_date`). The registry client parses the time manifest from npm and filters out any release, tag, or version published after `as_of`, accurately reconstructing the exact registry state visible to the attacker on the day of compromise.

---

### Q6: Why does Release Sentinel separate evidence collection from policy verdicts (Rule 4)?
**Answer**:
Tying detection directly to verdicts couples "what is observable" with "what is tolerable." 
Release Sentinel decouples this into two distinct layers:
1. **Sensors (Differ & Content Scanner)**: Output objective, indisputable facts as structured `Evidence` objects (`id`, `severity`, `file`, `line`, `explanation`, `legitimate_use_note`).
2. **Policy Engine (`decide`)**: A stateless rulebook (defined in `data/policy_default.toml`) that maps combinations of evidence to gate decisions (`ALLOW`, `WARN`, `BLOCK`).
This separation allows security teams to adjust risk tolerance, add exemptions, or simulate policy changes without altering detector scanner code.

---

### Q7: Why must `inspection_incomplete` fail closed, and how is it reported?
**Answer**:
If an attacker crafts an enormous 50 MB bundle or deeply nested files designed to exhaust scanner memory or exceed timeouts, a scanner that ignores timeouts would fail *open*, allowing the uninspected malware into production.
Release Sentinel enforces a **fail-closed** architecture: if a file exceeds budget limits (e.g. 25 MB or timeouts), an `inspection_incomplete` evidence item is generated. The policy engine elevates the decision to at least **WARN**.
Critically, to maintain scientific honesty in reporting, Release Sentinel disaggregates recall into two distinct metrics:
- **Evidence-Only Recall**: True detections based strictly on extracted malicious capabilities.
- **Fail-Closed Recall**: Elevating pairs to WARN due to incomplete inspection.

---

### Q8: How does the "Rule of Three" establish statistical confidence for 0 false BLOCKs on 800 benign packages?
**Answer**:
In statistical testing, when zero events are observed ($k = 0$) across $N$ independent trials, one cannot claim the true probability is zero. 
By the **Rule of Three**, the 95% upper confidence bound on the Poisson/Binomial rate is:
$$p_{95\%} \le \frac{-\ln(0.05)}{N} \approx \frac{3}{N}$$
For $N = 800$ benign release pairs evaluated with zero false blocks:
$$p_{95\%} \le \frac{3}{800} = 0.375\%$$
Under exact Clopper-Pearson binomial intervals, the 95% one-sided upper limit is **0.3737%**. This guarantees with 95% statistical confidence that the detector will generate fewer than **3.74 false BLOCKs per 1,000 release updates** in production.

---

### Q9: What is the difference between cluster-level lenient recall and cluster-level macro recall?
**Answer**:
When an attacker compromises 100 packages using the exact same script:
- **Sample Recall** would count this as 100 separate successes, heavily biasing the score toward high-volume campaigns.
- **Cluster Lenient Recall**: A cluster is considered detected if **at least 1 pair** in the cluster is flagged:
  $$\text{Recall}_{\text{lenient}} = \frac{\sum_{c} \mathbb{I}(\text{detected}_c > 0)}{N_{\text{clusters}}}$$
- **Cluster Macro Recall**: The fraction of detected pairs is computed *within* each cluster, and then averaged across all clusters, weighting small and large attacks equally:
  $$\text{Recall}_{\text{macro}} = \frac{1}{N_{\text{clusters}}} \sum_{c} \frac{\text{detected pairs in } c}{\text{total pairs in } c}$$
Macro recall provides the truest measure of generalization across disparate threat actors.

---

### Q10: Why did Stage 4b re-split the evaluation dataset chronologically (walk-forward protocol)?
**Answer**:
Standard cross-validation (randomly shuffling samples into train/test) causes catastrophic **temporal data leakage** in security: the detector "learns" from future attacks to detect past attacks, masking real-world detection decay.
Stage 4b instituted a **walk-forward chronological protocol**:
- **DEV**: All attacks discovered before `2026-01-01` (857 pairs, 29 campaigns).
- **VAL**: Attacks discovered between `2026-01-01` and `2026-04-30` (94 pairs, 3 campaigns).
- **TEST**: Attacks discovered `2026-05-01` onward (398 pairs: 299 in TEST-A / 49 campaigns, 99 in TEST-B / 3 campaigns; total = 1,349 pairs / 84 campaigns).
Rules could only be engineered and tuned using DEV and VAL. TEST was locked and run aggregates-only at the very end of evaluation.

---

### Q11: Why was the TEST cohort partitioned into TEST-A and TEST-B?
**Answer**:
When analyzing the TEST cohort ($\ge 2026-05-01$), a severe temporal anomaly occurred: **117 distinct clusters were discovered on a single calendar day (2026-06-17)**. 
Because of this concentration, no calendar date cutoff could divide the 196 TEST clusters with at least 80 clusters on both sides.
The cohort was partitioned chronologically by discovery date and deterministically by cluster rank into:
- **TEST-A (299 pairs, 49 campaigns)**: Unlocked in Stage 5c as "VAL2" for error analysis and policy calibration.
- **TEST-B (99 pairs, 3 campaigns)**: Kept strictly locked and held-out for the final verification run of v1.1.

---

### Q12: What was the "Late-2026 Shift" uncovered in TEST-B?
**Answer**:
In TEST-B, cluster BLOCK recall dropped sharply to 3.09%. A detector-independent archive audit revealed this was not detector degradation, but an abrupt paradigm shift in attacker technique:
- In DEV and VAL, **$>90\%$ of attacks modified JavaScript code** or added install lifecycle hooks (`preinstall`, `curl ... | sh`).
- In TEST-B, **$89.9\%$ of attacks were metadata-only (zero modified JS code)** and **$94.9\%$ injected a direct runtime dependency** (such as `easy-day-js`).
Attackers completely stopped touching source files and moved the payload into transitive dependencies.

---

### Q13: What is a "hollow release" and how does `hollow_dependency_injection` detect it?
**Answer**:
A **hollow release** is a package update where an attacker keeps all executable source code, assets, and build files 100% identical to the clean version, but modifies `package.json` to add a new direct runtime dependency.
The `hollow_dependency_injection` rule detects this by checking two conditions:
1. At least one direct runtime dependency was added (`new_deps - old_deps > 0`).
2. Every added or modified file in the release matches metadata patterns (`package.json`, `README*`, `CHANGELOG*`, `LICENSE*`, `.gitignore`).
If no code files were added or modified, the release is classified as hollow.

---

### Q14: How does `lookalike_dependency_name` detect typosquats and lookalikes without false-alarming on legitimate packages?
**Answer**:
The rule evaluates whether an added dependency is a disguised variant of a high-impact package from `data/top_npm_packages.json` (a curated list of ~230 top npm libraries):
1. **Exact Matches Are Excluded**: If `dep_name == popular_name`, it is the legitimate package, not a lookalike.
2. **Affix Stripping**: Checks if stripping common attacker affixes (`easy-`, `simple-`, `plain-`, `-js`, `-lib`, `-node`) yields a popular package name (e.g. `easy-day-js` $\to$ `dayjs`; `plain-crypto-js` $\to$ `crypto-js`).
3. **Separator Normalization**: Strips hyphens, underscores, and dots (e.g. `cryptojs` vs `crypto-js`).
4. **Bounded Edit Distance**: Computes Levenshtein distance $\le 1$ for names $\ge 5$ chars, or $\le 2$ for names $\ge 7$ chars (e.g. `cha1k` $\to$ `chalk`).

*Stage 5e Audit Disclosure*: Auditing revealed that `"easy-"` was sample-derived from observing `easy-day-js`. Removing `"easy-"` causes `easy-day-js` not to match `dayjs`, dropping v1.2's post-hoc TEST-B BLOCK recall from 92.93% back to 3.03%. This proves that post-hoc numbers on observed test sets are highly vulnerable to subtle sample overfitting.

---

### Q15: Why was the hollow+lookalike composite BLOCK rule removed in v1.2.1 in favor of an experimental WARN flag (`--experimental-hollow`)?
**Answer**:
Rigorous audit revealed two critical issues:
1. **Sample Contamination**: The prototype lookalike affix list included `"easy-"`, which was mined directly from observing the TEST-B sample `easy-day-js`. Purging sample-specific affixes is required to maintain guardrails against overfitting.
2. **Unconstrained Benign False-Alarm Rate**: Across our 800-package benign benchmark, exactly **0 packages** were hollow releases that added dependencies ($n = 0$). Because no benign package in the benchmark tested this pattern, the empirical false-positive rate of an automated BLOCK rule is statistically unconstrained (95% upper bound is undefined / 100%).
In accordance with Rule 2 (benign gate) and Rule 5 (honest reporting), **v1.2.1** removed the composite BLOCK rule and downgraded both signals to `Severity.MEDIUM` (WARN only). Both signals are placed behind `--experimental-hollow`, ensuring that default behavior strictly matches v1.1's thoroughly validated, zero-false-block baseline.

---

### Q16: How does Union-Find campaign clustering work, and how was the 1,211-pair mega-blob resolved in Stage 5f?
**Answer**:
Campaign clustering links pairs sharing detector-independent attack infrastructure (identical non-metadata payload SHA-256 hash $\ge 200$ bytes, added direct runtime dependency, or added lifecycle command).
In early iterations, a 1,211-pair mega-blob appeared. Review in Stage 5f identified the true technical root causes:
1. **Scoped Package Baseline Cache Bug**: `build_campaigns.py` looked for baselines under `CACHE_DIR/<pkg>/...`. For scoped packages like `@scope/pkg`, the forward slash caused file lookups to fail for 1,017 of 1,349 pairs (75.4%). When the baseline failed to load, every dependency and script appeared "newly added", creating bogus dependency links across years.
2. **Hub Suppression & 30-Day Window**: Common keys shared by $>50$ pairs spanning $>60$ days (e.g. `node index.js`) were suppressed as hubs, and links were constrained to pairs discovered within a 30-day temporal window.
Fixing baseline loading via `_safe_filename(pkg)` eliminated all 1,017 missing baselines (0 missing). The blob resolved into **140 coherent campaigns** (DEV: 53, VAL: 12, TEST-A: 71, TEST-B: 4).
The top two campaigns are historically justified: `camp_0001` (407 pairs) links packages compromised on 2025-11-24 sharing the identical 4.9 KB `setup_bun.js` payload hash; `camp_0002` (351 pairs) links the mid-September 2025 `node bundle.js` campaign across 2025-09-14 to 2025-09-16.

---

### Q17: How is campaign recall evaluated across splits without cross-split leakage?
**Answer**:
In Stage 5e/5f, campaign assignment and evaluation were strictly decoupled:
1. **Campaign Assignment**: Each campaign is assigned to exactly one split (`primary_split`) based on the earliest discovery date among its member pairs.
2. **Within-Split Evaluation**: When evaluating campaign-level recall for a split, recall is evaluated **strictly on member pairs that fall within that split**. Member pairs belonging to earlier or later splits are excluded from that split's score.
This ensures 100% disjointness of pairs and campaigns across splits and prevents future attack variants from inflating past split scores.

---

### Q18: What is signal lift, how was it corrected, and why is it vital for policy design?
**Answer**:
Signal lift measures how much more frequently an evidence signal appears in malicious attacks compared to benign software:
$$\text{Lift} = \frac{P(\text{Signal} \mid \text{Malicious})}{P(\text{Signal} \mid \text{Benign})} = \frac{b / N_{\text{mal}}}{a / N_{\text{benign}}}$$
In Stage 5b, an arithmetic bug divided a fraction by a percentage, reporting lift for `dependency_added` as $0.51\times$ instead of its true value ($51.0\times$).
In Stage 5c, programmatically verified lift tables were established. Signals with high lift ($>200\times$) and zero benign occurrences (e.g. `dynamic_code + long_encoded_blob`) are safe for BLOCK corroboration, while low-lift signals ($<1.5\times$, like `bin_entry_added`) were downgraded to prevent benign alert noise.

---

### Q19: Why must v1.2's evaluation on TEST-B be explicitly labelled "post-hoc, not held out"?
**Answer**:
Scientific integrity is paramount. In Stage 5c, TEST-B was used for the single final verification run of v1.1. After that run, the distribution of TEST-B was observed (revealing the 94.9% hollow dependency injection pattern).
Because the rules for v1.2 (`hollow_dependency_injection` and `lookalike_dependency_name`) were designed *after* seeing the TEST-B distribution, TEST-B was no longer a blind, unobserved test set for v1.2.
Labelling v1.2's numbers on TEST-B as "post-hoc, not held out" prevents p-hacking and maintains scientific honesty.

---

### Q20: How does the prospective evaluation protocol provide the definitive final exam for v1.2?
**Answer**:
The only scientifically honest way to evaluate a post-hoc detector is **prospectively**:
1. Today's Datadog dataset snapshot was frozen at commit `8a74a4c8ee0e1a2927f0419e0710968702ded609` (cutoff: `2026-10-16`).
2. When new real attacks are added to the repository in the future, `scripts/prospective_eval.py` extracts only samples with `discovery_date > 2026-10-16`.
3. Each prospective attack is paired with a contemporaneous benign release from the same week.
4. Frozen detector code is executed without any modifications.
This prospective protocol guarantees zero leakage, zero observer bias, and tests true generalization against future adversaries.

---

### Q21: What was the cause of the DEV evidence-only regression observed in v1.2?
**Answer**:
Versus v1.1, DEV evidence-only $\ge$WARN recall dropped from 844 to 837 pairs, and `inspection_incomplete` increased from 4 to 13 on DEV.
The root cause was a **timeout ceiling regression**:
The addition of string distance and regex lookalike checks against 2,000 package names added per-pair CPU latency. For 8 packages that were already near the 60.0s per-pair scan ceiling in v1.1 (34s–58s):
- `@postman/pm-bin-linux-x64` (versions 1.24.3, 1.24.4, 1.24.5)
- `@postman/pm-bin-macos-x64` (versions 1.24.3, 1.24.4, 1.24.5)
- `@strapbuild/react-native-perspective-image-cropper` (0.4.15)
- `@uipath/apollo-core` (5.9.2) [TEST-A]
The extra processing pushed total scan duration past 60.0s. Release Sentinel executed its fail-closed mechanism, stopping analysis and returning `inspection_incomplete` (WARN). Because fail-closed WARNs do not count toward evidence-only recall, evidence-only recall dropped by exactly 7 pairs in DEV.

---

### Q22: What precision hardening and packaging readiness changes were made in v1.3 (Stage 5g)?
**Answer**:
Release Sentinel v1.3 represents the frozen shipping version hardened for production deployment:
1. **Narrowed Over-Broad Regex Patterns**:
   - Audited 2,000 top npm packages across 1,992 install hooks.
   - Narrowed bare word `fetch` to explicit URL/call syntax (`\bfetch\s*(?:\(|\s+https?://)`).
   - Narrowed `rm -rf` to dangerous targets (`/`, `~`, `$HOME`, `%USERPROFILE%`, `..`, bare `*`, absolute system paths), eliminating all 17 benign false flags on build directories (`rm -rf dist`) while retaining 100% of malicious wipers.
   - Narrowed `sudo` to explicit command execution.
2. **Refined Dependency Signals**:
   - `dependency_added` (LOW) is now emitted strictly for runtime and optional dependencies. `devDependencies` and `peerDependencies` additions became separate INFO findings (`dev_dependency_added`, `peer_dependency_added`), reducing benign alert prevalence by 76% (from 12.38% to 3.00%).
3. **Robust Install-Target Parsing**:
   - Parsed node command flags (e.g., `--no-warnings`, `-r/--require <file>`), alternative shells (`sh`, `bash`, `zsh`), `python`, `./script.sh`, extensionless scripts (`.js`, `.cjs`, `.mjs`), and script indirection up to depth 3 with cycle protection.
4. **Packaging Readiness**:
   - Bundled all static assets (`top_npm_packages.json`, `policy_default.toml`) inside the package (`src/release_sentinel/data/`) loaded via `importlib.resources`.
   - Defaulted CLI live mode `as_of` to the current UTC timestamp and invoked `analyze_release` with the client, activating live dependency scanning.
   - Anchored Azure Pipelines CI workflow detection.

---

### Q23: Why did wall-clock timeout limits cause machine-dependent evaluation results, and how was this solved in v1.3?
**Answer**:
In v1.1 and v1.2, evaluation enforced a strict 60.0-second wall-clock subprocess timeout. Under parallel evaluation (8 worker threads), CPU contention caused 8 binary-heavy releases (e.g. `@postman/pm-bin-*`, `@uipath/apollo-core`, containing 10–97 MB ELF/Mach-O binaries and 10 MB minified JavaScript files) to take 34–58 seconds on an idle system, but intermittently exceed 60.0 seconds when multiple workers competed for CPU cycles. When timed out, the scanner emitted `inspection_incomplete` (WARN), artificially deflating evidence-only BLOCK recall on slower machines.

In v1.3, this was replaced with:
1. **Fast-pathing Native Binaries and WASM**: Binary assets are categorized by magic bytes and recorded by hash and size without expensive regex text-scanning.
2. **Deterministic Work Budgets**: Scans enforce strict byte budgets (`MAX_SCAN_BYTES_PER_FILE = 2 MB`) and regex operation caps (`MAX_REGEX_OPS_PER_FILE = 50,000`).
3. **Wall-Clock Backstop**: The subprocess timeout was increased to 300.0 seconds merely as an emergency safety net. Profiling confirmed all 8 slow pairs now evaluate cleanly to BLOCK within 26–52 seconds across all environments.

---

### Q24: Why did v1.2.1 show TEST-A WARN+ recall of 64/71 compared to 63/71 in v1.1, and how does the pure date cutoff resolve this?
**Answer**:
Under the Stage 5e split definition, the single calendar day `2026-06-17` was split alphabetically: packages named $\le$ `@mastra/clickhouse` or equal to `@mastra/openai` were placed into TEST-A (23 pairs), while remaining packages went to TEST-B.
In v1.1, those 23 hollow-release pairs triggered no alerts and were classified as `ALLOW`. The Mastra campaign (`camp_0136`) was therefore undetected in TEST-A, yielding 63/71 detected campaigns.
In v1.2.1, the evaluation artifact (`eval_results_v8.jsonl`) recorded results with experimental hollow release detection active. Those 23 pairs triggered `hollow_dependency_injection` + `lookalike_dependency_name` $\to$ `WARN`, causing `camp_0136` to become detected at WARN+ in TEST-A and raising the count from 63 to 64.

In v1.3 (Stage 5g Part 6e), this arbitrary within-day package name boundary was eliminated in favor of a **pure calendar date cutoff** (`< 2026-06-17` for TEST-A, $\ge$ `2026-06-17` for TEST-B). Under the pure date cutoff:
- All 118 pairs of `camp_0136` belong cleanly to TEST-B.
- TEST-A comprises 70 campaigns total (and 274 pairs).
- In both v1.1 and v1.3, TEST-A lenient WARN+ is exactly **63 / 70 (90.00%)**, and lenient BLOCK is **58 / 70 (82.86%)**. Disjointness and reproducibility are completely restored.

---

### Q25: What caused the two v1.3 regressions (VAL dropping 1 detection and benign alerts increasing), and how did v1.3.1 resolve them?
**Answer**:
During post-release auditing of v1.3, two measurement regressions were detected:
1. **VAL Regression**:
   - *Symptom*: VAL lost one WARN+ detection (94 $\to$ 93 pairs; 12/12 $\to$ 11/12 campaigns).
   - *Root Cause*: In `scripts/run_eval.py`, child worker processes were invoked without `samples_root=SAMPLES_ROOT`. For the pair `axios@1.14.0@1.14.1` (Campaign `camp_0061`), the added dependency `plain-crypto-js` had been delisted from npm and resided exclusively in the local encrypted sample repository. Without `samples_root`, offline dependency replay was bypassed, yielding `unresolvable_dependency` (INFO) instead of resolving the install hook (`install_script_present`, HIGH).
   - *Fix*: Passing `samples_root=SAMPLES_ROOT` to worker invocations restores `axios` to `WARN`, returning VAL to **94 / 94 pairs (100.0%)** and **12 / 12 campaigns (100.0%)**.
2. **Benign Alert Increase**:
   - *Symptom*: Benign tuning smoke alerts increased from 11 to 16 per 100, and matched negatives from 16.33% to 17.50%.
   - *Root Cause*: In `src/release_sentinel/content_scanner.py`, files $> 2$ MB invoked `_apply_budget_exceeded_cheap_checks()`. That function unconditionally generated `inspection_incomplete` (MEDIUM) and evaluated Shannon entropy on raw slices, firing `high_entropy_string` (MEDIUM) on normal minified JS files. This falsely warned on all 5 tested versions of `typescript` (which contain a clean 9.2 MB JS bundle).
   - *Fix*: Large files $> 2$ MB are now bounded to 2 MB of text scan without generating fail-closed budget findings. All `typescript` versions return to clean `ALLOW`. Tuning smoke alerts drop back to **11 / 100 (11.0%)**; matched negatives return to **16.33% (98/600)**; and total benign false BLOCKs remain at **0 (0.00%)** across all 800 pairs.

---

### Q26: Why is lenient campaign-level recall misleading without member-level reporting, and what accounts for the execution latency of "slow" evaluation pairs?
**Answer**:
1. **Lenient k-of-n vs. Member-Level Fractions**:
   Under lenient campaign recall, an entire campaign is marked as "detected" if *at least one* of its member packages is detected.
   For large campaigns, this can severely overstate real-world protection:
   - For `camp_0136` (TEST-B, 118 members, Mastra hollow attacks): Lenient reporting claims **100% recall (1/1 WARN+, 1/1 BLOCK)**. However, member-level evaluation reveals that in v1.1 only **4 / 118 (3.39%)** were warned and **1 / 118 (0.85%)** was blocked.
   - For `camp_0066` (TEST-A, 60 members, TanStack injection): Lenient reports 100% WARN+ and 0% BLOCK. Member-level evaluation reveals that **60 / 60 (100.0%)** are warned and **0 / 60 (0.0%)** are blocked because the injected file lacks install hooks or `eval()`.
   Reporting both metrics side-by-side ensures operational honesty.
2. **Latency of "Slow" Evaluation Pairs**:
   Profiling the 8 slowest evaluation pairs (e.g. `@postman/pm-bin-*`, `@strapbuild/react-native-perspective-image-cropper`, taking 26–52s) revealed:
   - Baseline cache read: $< 0.1$ seconds.
   - Pure-Python ZIP decryption (`zipfile.ZipFile.read()` with `pwd=b'infected'` on 34–83 MB archives): **24.5 – 38.0 seconds** ($> 85\%$ of total time).
   - In-memory archive structuring: 25.0 – 41.8 seconds.
   - Content scanning and regex-based analysis: **0.37 – 4.33 seconds**.
   Static scanning executes in single-digit seconds even on 80 MB packages. The multi-second latency is an artifact of Python's standard library decrypting password-protected sample archives in pure software during benchmark runs, an overhead that does not exist in production npm `.tgz` operation.

---

### Q27: How does v1.4 eliminate false alarms on popular packages in dependency-aware scanning (diff mode vs full-scan mode)?
**Answer**:
In v1.3, any newly added dependency was inspected in full-scan mode as if it were a single-version, brand-new package. When legitimate popular packages (e.g. `esbuild`, `vite`, `next`, `mongodb`) were added as dependencies, their complex bundled assets legitimately contained dynamic evaluation, base64 data, and environment variable lookups. Full-scan mode produced 10 false BLOCKs (2.0%) across 500 popular packages and warned on 13 of 24 benign updates.

In v1.4:
1. **Diff Mode Resolution**: When a runtime dependency is added, Release Sentinel queries registry metadata as of `as_of`. If the package has an earlier published version before `as_of`, it is analyzed in **DIFF mode** against its own prior version under standard update policy.
2. **Tightened Full-Scan Mode**: Only brand-new, single-version packages without prior releases use full-scan mode. For full-scan mode, the policy was tightened: a single heuristic (`decode_and_execute`, `env_harvesting`, or `obfuscated_code` alone) cannot BLOCK; BLOCK is reserved for corroborated execution chains (install-time download/execution or credential exfiltration).
3. **Verification**: In diff mode, 0 of the 10 popular packages BLOCK (5 become ALLOW, 5 become WARN). Across 24 benign dependency-adding updates, 0 BLOCK (11 ALLOW, 13 WARN).

---

### Q28: How does v1.4 scan large files up to the 25 MB ceiling without payload blind spots or catastrophic regex backtracking?
**Answer**:
v1.3.1 bounded text scanning on large files to the first 2 MB prefix. If an attacker positioned a malicious payload after the 2 MB boundary (e.g. at 3 MB or 20 MB inside a 21 MB bundle), the prefix scan would miss it completely.

In v1.4:
1. **Linear-Time Chunked Scanning**: Files up to the 25 MB hard ceiling are scanned completely using overlapping windows (1 MB window size, 64 KB overlap). This guarantees that regex patterns spanning window boundaries are detected while preventing catastrophic backtracking or unbounded memory consumption.
2. **Fail-Closed Boundary**: Only files strictly exceeding the 25 MB hard ceiling generate a `partial_scan` limitation (failing closed to WARN).
3. **Performance**: In-memory chunked scanning on a 21 MB file completes in **0.362 seconds** (well within the 5.0-second limit). Tests with payloads placed after 3 MB and after 20 MB verify complete detection.

---

### Q29: How does lockfile diffing work across package-lock.json v1, v2, and v3, and why are yarn and pnpm unsupported?
**Answer**:
1. **Format Support**:
   - `package-lock.json` v1: Recursively traverses nested `dependencies` trees.
   - `package-lock.json` v2/v3: Parses flat `packages` dictionaries with `node_modules/` keys, ignoring the root application entry.
2. **Integrity & Exact Tarballs**:
   Uses the lockfile's declared `resolved` URL and Subresource Integrity (`integrity`) hash (e.g. `sha512-...`). The downloaded tarball is verified against the lockfile's declared hash before extraction. Any hash mismatch emits `integrity_mismatch` (HIGH severity / Decision.BLOCK) and fails closed.
3. **Safety Budget**:
   `sentinel check` enforces `--max-packages` (default 200). If more than 200 packages changed, the first 200 are scanned, skipped packages are recorded in limitations, and the gate fails closed to WARN.
4. **Rejection of Yarn & pnpm**:
   Yarn (`yarn.lock`) and pnpm (`pnpm-lock.yaml`) use custom line-oriented or YAML formats. Supplying them raises `UnsupportedLockfileError` with clear explanatory guidance.

---

### Q30: What are the CLI exit codes, and how does the GitHub Action prevent privilege escalation on fork pull requests?
**Answer**:
1. **CLI Exit Codes (`sentinel check`)**:
   - `0`: Policy satisfied (verdict is clean/ALLOW, or policy threshold satisfied).
   - `1`: Security gate failed per `--fail-on` (default: fails on BLOCK; configurable to `warn` or `never`).
   - `2`: Usage error, invalid option, or internal failure (never exits 0 on internal failure).
2. **GitHub Action Security Design**:
   - **Trigger**: Strictly requires `pull_request`, NEVER `pull_request_target`. `pull_request_target` runs with base repository permissions and secret access, creating a dangerous privilege-escalation vector on fork PRs. `pull_request` executes in an unprivileged, read-only fork context.
   - **Least Privilege**: Requests only `contents: read` and `pull-requests: write`.
   - **Fork PR Resilience**: On fork PRs where tokens lack write permissions, the action skips PR commenting without failing the workflow, preserving the full markdown report in `$GITHUB_STEP_SUMMARY`.
   - **Shell Safety**: All PR inputs (branch names, paths) are passed via environment variables rather than string interpolation, preventing shell injection. Third-party actions are pinned by immutable commit SHAs.


---

### Q31: What are the architectural differences between the `strict` and `default` policy profiles?
**Answer**:
In Stage 6b, Release Sentinel bifurcated its policy into two formally verified profiles:
1. **`strict` Profile (`policy_strict.toml`)**:
   - Preserves the exact frozen v1.4 research evaluation policy.
   - Designed for high-assurance audits and academic benchmark reproducibility.
   - Evaluates single heuristics aggressively, flagging every anomalous signal for maximum sensitivity.
2. **`default` Profile (`policy_default.toml`)**:
   - Designed for production CI/CD gates where false developer disruption must remain $\le 2\%$.
   - **Lifecycle Script Hardening**: Restricts registry dependency install targets strictly to `{"preinstall", "install", "postinstall"}`, recognizing that npm never runs `prepare` or `prepublish` for public registry dependencies.
   - **Sink-Constrained Execution**: Tightens `decode_and_execute` to require explicit execution sinks (`eval`, `child_process`).
   - **Corroboration Enforcement**: Non-install-time single heuristic signals demote from BLOCK to WARN, reserving automated BLOCKs for verified install-time execution, network exfiltration, credential theft, and corroborated attack clusters.

---

### Q32: What did large-scale replay across 12 real-world repositories reveal about developer alert-burden and the "Aggregation Effect"?
**Answer**:
Replaying historical lockfile updates across 12 popular open-source repositories (applications, frameworks, and developer tools) revealed the **Aggregation Effect** in package managers:
- When a pull request updates a lockfile, an average of $n \approx 20$ packages are upgraded simultaneously.
- If a security tool has a seemingly low per-package false-BLOCK rate of $p = 1.72\%$, the probability that *at least one* package in the pull request falsely triggers a BLOCK is:
  $$P(\text{Blocked Update}) = 1 - (1 - p)^n = 1 - (0.9828)^{20} \approx 29.5\%$$
- In our initial 4-repo baseline under strict rules, $17.9\%$ of pull requests were blocked by benign tools.
- *Solution*: By addressing lifecycle hook semantics (`prepare`/`prepublish`) and decoupling single heuristics from automated blocks in the `default` profile, the per-update false-BLOCK rate dropped from $13.4\%$ down to **$0.0\%$** across real-world updates, proving that security gates can prevent supply-chain attacks without breaking developer CI pipelines.

---

### Q33: How does Release Sentinel defend against Lockfile Injection and Package Aliasing attacks (Stage 7b)?
**Answer**:
In lockfile injection attacks, an attacker crafts a malicious `package-lock.json` where a trusted dependency name (such as `lodash@4.17.21`) has its `resolved` URL pointed to a completely different malicious tarball (e.g. `https://registry.npmjs.org/evil/-/evil-1.0.0.tgz`), while omitting or spoofing integrity hashes.
Release Sentinel thwarts this attack vector through multiple layers:
1. **Resolved URL Path Verification**: For registry-sourced entries, Release Sentinel validates that the `resolved` path strictly conforms to `/{name}/-/{basename}-{version}.tgz` (handling scoped packages like `/@scope/pkg/-/pkg-version.tgz`). Any URL path mismatch generates `lockfile_resolved_mismatch` (HIGH severity / Decision.BLOCK under both `default` and `strict` profiles), immediately halting analysis without downloading untrusted tarballs.
2. **Missing Integrity Alerts**: An entry without an `integrity` hash generates `lockfile_missing_integrity` (MEDIUM severity / Decision.WARN).
3. **Cryptographically Bound Cache Keys**: Tarball cache paths are strictly bound to `(name, version, integrity or resolved-URL hash)`. Cached files cannot be aliased or served across mismatched URLs or corrupted checksums.
4. **Streaming Tarball Size Caps**: Tarballs are streamed in 64 KB chunks with per-tarball size limits (`MAX_TARBALL_BYTES = 100 MB`) and session download limits enforced chunk-by-chunk while reading, preventing denial-of-service from unbounded tarballs.
5. **Metadata Time-To-Live**: Live registry mode invalidates cached packuments older than 1 hour (`metadata_ttl_seconds = 3600`), ensuring rapid detection of newly published or unpublished versions.

---

### Q34: How is GitHub Action Supply-Chain Hygiene enforced?
**Answer**:
1. **Hash-Locked Dependencies**:
   The action dependencies are locked with cryptographic SHA-256 hashes in `requirements-action.lock`. In CI, dependencies are installed using `pip install --require-hashes -r requirements-action.lock` followed by `pip install --no-deps "${{ github.action_path }}"`. This ensures that every byte installed on the CI runner is tamper-evident and immune to PyPI dependency hijacking.
2. **Commit SHA Verification**:
   All third-party GitHub Actions (such as `actions/checkout` and `actions/setup-python`) are pinned by immutable 40-character commit SHAs rather than mutable tags. Every pinned SHA is verified against the official GitHub API to eliminate drift.
3. **Security Permissions & Event Triggers**:
   - Workflows specify explicit least-privilege permissions: `permissions: contents: read` (plus `pull-requests: write` when commenting is enabled).
   - The action strictly requires the `pull_request` event trigger, **never** `pull_request_target`. `pull_request_target` grants repository write permissions and secrets to fork PRs, enabling dangerous privilege escalation. `pull_request` executes in the isolated, unprivileged context of the PR.
   - The action strictly performs static analysis and **never** executes package code or lifecycle scripts.

---

### Q35: Why does the `default` profile BLOCK 2025 install-hook waves while only WARNING on 2026 waves, and how does `comment-on: notable` solve the alert burden?
**Answer**:
1. **Evolving Attack Vectors**:
   - In 2025, attackers launched massive automated publishing waves (`camp_0052` with 407 packages, `camp_0048` with 351 packages) containing blatant install-time hooks (`preinstall`/`postinstall`) that immediately executed shell commands or downloaded payloads. The `default` profile blocks these waves decisively: **394 of 407 (96.8%)** in `camp_0052` and **349 of 351 (99.4%)** in `camp_0048`.
   - In late 2025 and 2026, attackers adapted by abandoning install scripts to evade basic detectors (`camp_0065` with 103 packages, `camp_0066` with 60 packages, and `camp_0136` with 118 packages). These releases hide obfuscated code or delayed runtime exfiltration within deep package files. In the low-noise `default` profile, single uncorroborated heuristics cap at **WARN** to preserve zero false-BLOCKs on production code, resulting in **103/103 WARN** on `camp_0065`, **60/60 WARN** on `camp_0066`, and **4/118 WARN** on `camp_0136` (0 BLOCKs).
   - In comparison, the research `strict` profile blocks `camp_0065` (103/103) by treating single heuristics as blocking signals.
2. **PR Comment Optimization (`comment-on: notable`)**:
   - Posting a PR comment on every single warning would flood developers across 43.1% of historical dependency updates.
   - Restricting comments to BLOCK only would completely silence the three 2026 waves, dropping campaign comment coverage down to **24.3% (34 of 140 campaigns)**.
   - Under `comment-on: notable` (Variant B), PR comments are triggered on BLOCK or WARN containing HIGH/CRITICAL signals, install-hook changes, or $\ge 2$ distinct medium evidence types.
   - This achieves the optimal trade-off: it captures **90.0% of campaigns (126 of 140)**—including the major 2026 waves—while cutting developer PR comment noise from 43.1% down to **29.9%** on real-world repository replays.

