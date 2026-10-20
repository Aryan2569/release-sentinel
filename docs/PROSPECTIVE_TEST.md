# Prospective Evaluation Protocol for Release Sentinel v1.2

This document establishes the scientific protocol for future, prospectively held-out evaluation of Release Sentinel **v1.2** (frozen at git tag `v1.2`).

---

## 1. Baseline Dataset Snapshot

All retrospective analyses and post-hoc rules for v1.2 were developed using the Datadog dataset as of the snapshot below:

- **Repository**: `C:\rs-data\datadog`
- **Git Commit Hash**: `8a74a4c8ee0e1a2927f0419e0710968702ded609`
- **Snapshot Date**: `2026-10-16 10:25:21 +0200`
- **Dataset Cutoff**: All samples discovered on or before `2026-10-16`

Any sample added to the repository after this commit hash represents an unobserved, prospectively held-out evaluation sample.

---

## 2. Prospective Testing Protocol

When new real supply-chain attack samples are committed to the upstream repository, the prospective test must be executed strictly following these 5 steps:

### Step 1: Upstream Synchronization
Pull the latest commits from the Datadog dataset repository:
```powershell
git -C C:\rs-data\datadog pull origin main
```

### Step 2: Prospective Cohort Extraction
Extract all newly published malicious pairs whose discovery date is strictly greater than the snapshot cutoff:
$$\text{discovery\_date} > 2026-10-16$$
For each compromised package, identify:
- `new_version`: The compromised release version.
- `old_version`: The latest preceding non-compromised release published before `discovery_date`.
- `discovery_date`: The exact ISO timestamp recorded by the upstream dataset.

### Step 3: Contemporaneous Benign Negative Matching
To prevent temporal distribution shift from distorting the false alarm rate, construct a matched negative cohort:
- For every prospective malicious pair, select a benign package release published on `registry.npmjs.org` within $\pm 7$ days of the discovery date.
- Match package tier (e.g. popular vs long-tail) to ensure equivalent complexity.

### Step 4: Strict Detector Freeze Execution
Execute the evaluation using `scripts/prospective_eval.py` without modifying any detector code or policy thresholds:
```powershell
python scripts/prospective_eval.py --as-of-cutoff 2026-10-16 --output-dir data/prospective
```
- No rules, weights, severities, or lookalike lists may be tuned or edited retroactively.
- The v1.2 code hashes (recorded in `docs/DECISIONS.md`) must be verified before execution.

### Step 5: Metric Reporting & Campaign Grouping
Report prospective performance in two complementary dimensions:
1. **Sample-Level Metrics**:
   - Evidence-only $\ge$WARN recall and evidence-only BLOCK recall.
   - Fail-closed $\ge$WARN recall (tracking `inspection_incomplete` separately).
2. **Campaign-Level Metrics**:
   - Group prospective pairs using the 4 detector-independent Union-Find linkage rules:
     1. Identical new/changed non-metadata file hash ($\ge 200$ bytes).
     2. Identical added direct runtime dependency (excluding known benign dependencies).
     3. Identical added lifecycle command string.
     4. Identical added hardcoded public IP or attacker C2 domain.
   - Report lenient campaign recall ($\ge 1$ pair detected) and macro campaign recall.
3. **Benign False Alarm Rate**:
   - Report false BLOCK rate (target: 0.00%) and alert burden (alerts per 100 updates) on the contemporaneous benign negative cohort.
