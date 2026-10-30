# Reproducing Evaluation Results

This guide explains how to independently reproduce the evaluation results reported in Release Sentinel's documentation and metrics, without requiring any proprietary data or malware redistribution.

---

## Safety Requirements

All evaluations strictly follow the seven core safety rules in [`PROJECT_RULES.md`](PROJECT_RULES.md):
- **Safe In-Memory Inspection**: Malicious packages are never executed, installed, or extracted to disk. They remain in encrypted ZIP archives at rest (`password: infected`) and are inspected solely in memory.
- **Time-Awareness**: Evaluation functions enforce time-awareness via `as_of: datetime` cutoffs matching discovery timestamps.

---

## 1. Obtaining the Research Dataset

The malicious evaluation dataset is sourced directly from the public [DataDog Malicious Software Packages Dataset](https://github.com/DataDog/malicious-software-packages-dataset).

To clone only the necessary npm samples using git sparse-checkout:

```powershell
# Set target directory (e.g., $HOME/rs-data/datadog on Windows or ~/rs-data/datadog on Linux)
$SAMPLES_DIR = "$HOME/rs-data/datadog"

git clone --depth 1 --filter=blob:none --no-checkout https://github.com/DataDog/malicious-software-packages-dataset.git $SAMPLES_DIR
git -C $SAMPLES_DIR config core.protectNTFS false
git -C $SAMPLES_DIR sparse-checkout set --no-cone "/samples/npm/manifest.json" "/samples/npm/compromised_lib/**"
git -C $SAMPLES_DIR checkout HEAD
```

Set the environment variable pointing Release Sentinel to this directory:

```powershell
# Windows PowerShell:
$env:RS_SAMPLES_ROOT = "$HOME/rs-data/datadog"
[System.Environment]::SetEnvironmentVariable("RS_SAMPLES_ROOT", "$HOME/rs-data/datadog", "User")

# Linux / macOS:
export RS_SAMPLES_ROOT=~/rs-data/datadog
```

---

## 2. Running Evaluation

With the dataset directory configured and Release Sentinel installed in your virtual environment:

### A. Run Full Evaluation on Malicious Pairs

```powershell
python scripts/run_eval.py
```
This runs time-aware differential analysis across all 1,349 compromised npm evaluation pairs in memory and records results to `data/eval_results_v14.jsonl`.

### B. Evaluate Default Profile

```powershell
python scripts/evaluate_default_profile.py
```
This applies the low-noise `default` profile rules to the evidence dataset, generating `data/eval_results_default.jsonl`.

### C. Verify Metrics Integrity

```powershell
python scripts/verify_metrics.py
```
This script computes all sample-level and campaign-level recall metrics (including 95% Clopper-Pearson confidence intervals), asserts consistency against `docs/METRICS.json`, and verifies zero metric discrepancies.

---

## 3. Evaluation Splits & Protocol

- **DEV (857 pairs, 53 campaigns)**: Used for initial heuristic development and policy calibration.
- **VAL (94 pairs, 12 campaigns)**: Used for tuning validation and regression checking.
- **TEST-A (274 pairs, 70 campaigns)**: Tuned on / post-hoc evaluation split.
- **TEST-B (124 pairs, 5 campaigns)**: Aggregate-only blind evaluation split; no per-pair inspection.
