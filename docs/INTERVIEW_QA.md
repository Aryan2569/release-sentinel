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
- JavaScript and TypeScript files are analyzed using static AST parsers (via safe tokenizers) and regular expressions over string contents.
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

### Q15: Why is `hollow_dependency_injection` + `lookalike_dependency_name` required to reach BLOCK together?
**Answer**:
Defense in depth requires corroboration:
- **`hollow_dependency_injection` Alone**: Legitimate packages occasionally bump a metadata version and add a utility library without touching code immediately (e.g. `ora@7.0.1` adding `string-width`). Emitting BLOCK on hollow releases alone would cause false blocks.
- **`lookalike_dependency_name` Alone**: Legitimate packages may have names that coincidentally resemble popular packages (e.g. `cypress` resembles `express` at edit distance 2; `preact` resembles `react`).
- **Corroborated Pair**: A hollow release that simultaneously injects a lookalike dependency is an unmistakable attacker signature. Under the policy, neither signal alone blocks, but together they immediately trigger **BLOCK**. On our 800 benign packages, this combination caused **0 false BLOCKs**.

---

### Q16: How does Union-Find campaign clustering differ from file-hash clustering?
**Answer**:
File-hash clustering groups pairs only if they share an identical new-or-changed file SHA-256 hash. If an attacker varies a random variable name or comment in each release, file-hash clustering fragments the attack into dozens of separate singletons.
**Union-Find Campaign Grouping** links two pairs if they share *any* of 4 detector-independent linkages:
1. Identical new/changed non-metadata file hash ($\ge 200$ bytes).
2. Identical added direct runtime dependency (excluding benign dependencies).
3. Identical added lifecycle command string.
4. Identical added hardcoded public IP or attacker C2 domain.
This collapsed the 275 fragmented clusters into **84 coherent real-world campaigns** (DEV: 29, VAL: 3, TEST-A: 49, TEST-B: 3).

---

### Q17: Why did early Union-Find implementations collapse packages into a mega-campaign, and how was it investigated?
**Answer**:
In `camp_0001` (1,211 pairs), chaining occurred because the benign dependency exclusion list only drew from the 800 benign smoke pairs, missing standard open-source libraries (`jsonwebtoken`, `jose`, `openai`, `zustand`, `async-mutex`, `@azure/storage-blob`).
Generic lifecycle commands (`node index.js`, `rm /s /q`) and popular packages acted as hubs in Union-Find, bridging disparate clusters into a single mega-component.
By assigning each campaign strictly by its earliest discovery date, every campaign belongs to exactly one split (DEV: 29, VAL: 3, TEST-A: 49, TEST-B: 3), preventing multi-counting while accurately recording real-world attacker overlap.

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
4. Frozen v1.2 code is executed without any modifications.
This prospective protocol guarantees zero leakage, zero observer bias, and tests true generalization against future adversaries.
