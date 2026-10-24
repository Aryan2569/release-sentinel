# Release Sentinel

[![CI](https://github.com/release-sentinel/release-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/release-sentinel/release-sentinel/actions)
[![PyPI version](https://img.shields.io/pypi/v/release-sentinel.svg)](https://pypi.org/project/release-sentinel/)
[![Python versions](https://img.shields.io/pypi/pyversions/release-sentinel.svg)](https://pypi.org/project/release-sentinel/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Release Sentinel is a time-aware static security gate that catches compromised npm package updates in pull requests before you merge them. Unlike vulnerability scanners that query advisory databases of known CVEs or dynamic sandboxes that execute untrusted code, Release Sentinel performs fast, safe, in-memory differential static analysis between published package versions at update time.

---

## Status: Public Alpha (v0.5.0)

Release Sentinel is in public alpha. It is engineered with an **advisory-first** philosophy:

- **Recommended initial adoption**: Configure `fail-on: never` (PR-comment-only advisory mode) or `fail-on: block` under the low-noise `default` profile. This allows security and platform teams to observe dependency alerts on their own pull requests and calibrate review thresholds before blocking merges.
- **Fail-closed guarantees**: If network errors, unsupported tarball sources, or safety limits are exceeded, Release Sentinel records explicit limitations and alerts rather than silently allowing uninspected code through.

---

## Quickstart

### Local CLI Installation

Install Release Sentinel from PyPI using Python 3.12+:

```bash
pip install release-sentinel
```

### Auditing a Lockfile Diff

Audit changes between your existing and updated `package-lock.json`:

```bash
sentinel check --base package-lock.json.old --head package-lock.json.new
```

Or check changes directly against a git base branch in your repository:

```bash
sentinel check --base-ref origin/main --head package-lock.json
```

### Exit Code Semantics

Release Sentinel adheres to standard CI exit codes:

- **`0` (Pass)**: All inspected package changes passed within configured security policy.
- **`1` (Gate Failed)**: One or more package changes triggered a policy violation (`BLOCK`, or `WARN` when `--fail-on warn` is set).
- **`2` (Usage / Input Error)**: Invalid arguments, malformed lockfiles, or unsupported formats (e.g. yarn/pnpm).

---

## GitHub Action Usage

Add Release Sentinel to your repository by creating `.github/workflows/sentinel.yml`:

```yaml
name: "Dependency Security Gate"

on:
  pull_request:
    paths:
      - "package-lock.json"

jobs:
  audit-dependencies:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write # Required for posting PR comments
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Run Release Sentinel
        uses: release-sentinel/release-sentinel@v0.5.0
        with:
          lockfile: "package-lock.json"
          fail-on: "block"
          comment-on: "notable"
          profile: "default"
          max-packages: 300
```

### Action Configuration Options

| Input | Description | Default | Allowed Values |
| :---- | :---------- | :------ | :------------- |
| `lockfile` | Path to npm `package-lock.json` file | `package-lock.json` | Valid file path |
| `fail-on` | Threshold that causes the CI job to fail | `block` | `block`, `warn`, `never` |
| `comment-on` | Condition to post or update PR comments | `notable` | `block`, `notable`, `warn`, `always` |
| `profile` | Policy configuration profile | `default` | `default` (low-noise), `strict` (research baseline) |
| `max-packages`| Maximum changed packages to analyze before capping | `300` | Integer $\ge 1$ |
| `github-token`| Token for posting pull request comments | `${{ github.token }}` | GitHub token with PR write access |

> **Performance Note**: The composite action includes caching via `actions/cache@v4` for `~/.cache/release_sentinel` keyed on the lockfile hash. A cache hit drops the typical workflow run time from ~30s to ~2s.

---

## Example Pull Request Comment

When a compromised package is detected in a dependency update, Release Sentinel posts an actionable review comment directly on the pull request:

<!-- release-sentinel-pr-comment -->
## Release Sentinel Security Gate

**Verdict:** 🛑 **BLOCK** — 1 package(s) blocked out of 1 scanned.

### Flagged Packages

| Package | Version Change | Decision | Top Evidence | Why It Matters | Legitimate Explanation |
| :--- | :---: | :---: | :--- | :--- | :--- |
| `axios` | `1.14.0` → `1.14.1` | 🛑 BLOCK | `[dep: plain-crypto-js@1.0.0] install_script_executes` | Newly introduced dependency executes shell commands during `npm install`. | Packages legitimately add install helper scripts. Review the file content to verify it performs only expected setup. |

<details>
<summary><b>Inspected Packages (ALLOW) (0)</b></summary>

| Package | Version Change | Decision | Notes |
| :--- | :---: | :---: | :--- |

</details>

### Limitations & Scope
- JavaScript/TypeScript source scanned with static heuristics; dynamic evasion is possible.
- Transitive dependencies not pinned in lockfile are not analyzed.

---

## How It Works

### 1. Differential Analysis, Not Whole-Package Scans
Traditional scanners inspect entire repositories or tarballs from scratch, creating immense false-positive noise on large, complex packages. Release Sentinel inspects only the delta between the previously published release and the proposed update. This focuses analysis strictly on newly introduced files, modified lines, and changed configuration.

### 2. Dependency-Aware Scanning
Supply chain attacks frequently inject malicious behavior by adding runtime dependencies rather than modifying package source directly. When an update adds a new direct runtime dependency, Release Sentinel resolves the package as of the update timestamp:
- If the dependency has prior published versions, it is diffed against its baseline.
- If it is a brand-new, single-version package, it is inspected in full-scan mode with corroborating heuristic requirements.

### 3. Dual Policy Profiles
- **`default` (Low-Noise CI Gate)**: Requires high-confidence corroborating evidence to block (such as install-time network downloads, credential file exfiltration, or CI workflow tampering). Heuristics like standalone base64 blobs or minified code emit warnings or summary notices without blocking builds.
- **`strict` (Research Baseline)**: The frozen v1.4 research policy evaluated across academic datasets. Alerts broadly on single indicators for high-assurance audits.

### 4. Fail-Closed Live Architecture with Safety Budgets
To protect production CI against denial-of-service and evasive attacks, Release Sentinel enforces strict deterministic budgets:
- **Package Cap**: Scans up to 300 packages per update, prioritizing added packages and install hooks first.
- **Extraction Limits**: Rejects archives exceeding 5,000 files, 200 MB uncompressed size, or 25 MB single-file ceiling.
- **Linear-Time Chunking**: Files up to 25 MB are scanned in overlapping linear-time windows, preventing attackers from evading detection past initial file prefixes.

---

## Empirical Evaluation

Release Sentinel's detection efficacy and false alarm rates are continuously validated against the public [DataDog Malicious Software Packages Dataset](https://github.com/DataDog/malicious-software-packages-dataset) and real-world repository update histories.

### Malicious Recall Benchmark (1,349 Evaluation Pairs)

All metrics below are generated directly by [`scripts/verify_metrics.py`](file:///c:/My%20project/scripts/verify_metrics.py) from canonical evaluation records in [`docs/METRICS.json`](file:///c:/My%20project/docs/METRICS.json):

| Dataset Split | Pairs / Campaigns | Strict Profile Recall (v1.4) | Default Profile Recall (v0.5.0) | Lenient Campaign Recall (Default) [95% CI] |
| :--- | :---: | :---: | :---: | :---: |
| **DEV** | 857 pairs / 53 camp. | 98.95% WARN+ / 94.63% BLOCK | 98.95% WARN+ / 91.25% BLOCK | 48/53 (90.57%) [79.34%, 96.87%] |
| **VAL** | 94 pairs / 12 camp. | 100.0% WARN+ / 96.81% BLOCK | 100.0% WARN+ / 84.04% BLOCK | 12/12 (100.0%) [73.54%, 100.0%] |
| **TEST-A** (Held-Out) | 274 pairs / 70 camp. | 95.99% WARN+ / 71.90% BLOCK | 95.99% WARN+ / 18.98% BLOCK | 63/70 (90.00%) [80.48%, 95.88%] |
| **TEST-B** (Aggregate) | 124 pairs / 5 camp. | 7.26% WARN+ / 2.42% BLOCK | 7.26% WARN+ / 1.61% BLOCK | 4/5 (80.00%) [28.36%, 99.49%] |
| **ALL** | 1,349 pairs / 140 camp. | 89.99% WARN+ / 81.69% BLOCK | 89.99% WARN+ / 67.83% BLOCK | 127/140 (90.71%) [84.64%, 94.96%] |

> **Note on Test Splits**: The `default` profile maintains **100% of WARN+ detection coverage** (1,214 of 1,349 pairs; 127 of 140 campaigns) while demoting ambiguous single-signal heuristics to reduce CI noise. TEST-B represents multi-version obfuscated malware families where static diffing without install scripts requires behavioral execution.

### Real-World Replay Burden (12 Popular Repositories)

To measure production signal-to-noise ratio, Release Sentinel was replayed across **288 historical dependency updates** spanning **5,965 scanned packages** in 12 major open-source projects (`bootstrap`, `commander`, `glob`, `helmet`, `marked`, `mocha`, `nodemon`, `rimraf`, `socket.io`, `superagent`, `terser`, `winston`):

- **Per-Package Warning Rate**: 901 warned packages out of 5,965 total packages (15.10%).
- **PR Comment Gating (`comment-on: notable`)**:
  - Out of 288 updates, 162 are clean ALLOW (56.25%), 124 trigger warnings (43.06%), and 2 trigger BLOCK (0.69%).
  - Under `comment-on: notable`, PR comments are posted only for BLOCK verdicts or notable warnings (containing HIGH/CRITICAL signals, install-hook changes, or $\ge 2$ distinct medium signals).
  - This reduces noisy PR comments from 126 updates (43.75%) down to **86 updates (29.86%)** — an immediate **31.7% reduction in PR noise** without missing critical indicators.

### Attack Style Evolution Over Time

![Attack Style Over Time](docs/attack_style_over_time.png)

*Figure 1: Evolution of npm supply chain attack vectors from 2021 to 2024. Attacks have progressively shifted away from blatant install-script hooks (`preinstall`/`postinstall`) toward multi-stage credential harvesting, indirect dependency additions, and obfuscated runtime loaders.*

---

## Security Model and Limitations

### What Release Sentinel Catches
- Install-time script execution (`preinstall`, `install`, `postinstall`) added or modified in dependency updates.
- Install-time file transfers and downloads (`curl`, `wget`, `fetch`, `http.get`).
- Environment variable enumeration and credential harvesting (`.npmrc`, `~/.ssh`, `~/.aws/credentials`).
- CI/CD workflow modifications attempting to capture GitHub repository tokens or workflow secrets.
- Newly introduced runtime dependencies carrying suspicious or uninspected payloads.

### What Release Sentinel Does Not Catch
- **Pure Runtime Logic Bombs**: Deep application logic changes executed solely within user code paths without external network access or credential access.
- **Minified Build Artifacts**: Differences buried entirely inside pre-bundled, minified client bundles (e.g. webpack/rollup output) without source maps.
- **Pre-existing Compromises**: Packages that were compromised prior to the chosen baseline release.

For full technical specifications of evasion boundaries and mitigations, consult [`docs/LIMITATIONS.md`](file:///c:/My%20project/docs/LIMITATIONS.md).

---

## Reproducing Our Benchmarks

Anyone can independently verify Release Sentinel's published metrics using the public DataDog research dataset without downloading any private malware corpora.

See [`docs/REPRODUCING.md`](file:///c:/My%20project/docs/REPRODUCING.md) for step-by-step instructions on setting up sparse git checkouts and executing verification test harnesses.

---

## Roadmap

- **Lockfile Ecosystems**: Native parsing and diffing for `pnpm-lock.yaml` and Yarn (`yarn.lock` v1/v2).
- **Multi-Language Expansion**: Python supply chain analysis (`requirements.txt`, `poetry.lock`) via PyPI.
- **Custom Rule Plugins**: Extensible policy rule authoring via TOML and Rego policies.
- **IDE Extensions**: Pre-merge inline annotations in VS Code and JetBrains IDEs.

---

## License & Acknowledgments

Release Sentinel is licensed under the [MIT License](file:///c:/My%20project/LICENSE).

We gratefully acknowledge the researchers and maintainers of the [DataDog Malicious Software Packages Dataset](https://github.com/DataDog/malicious-software-packages-dataset) and the public [npm Registry](https://registry.npmjs.org) for enabling open, reproducible security research.
