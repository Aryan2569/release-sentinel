# Release Sentinel 🛡️

> **Time-aware static security gate for npm dependency updates.**

Release Sentinel compares two versions of an npm package — statically, without
executing any downloaded code — and returns an explainable **allow / warn / block**
decision backed by a list of concrete evidence items.

---

## Why?

Supply-chain attacks against npm packages typically involve:

- Adding or modifying **install-time lifecycle scripts** (`preinstall`, `postinstall`, …)
- Injecting **new binaries** via `bin` entries
- Silently swapping **dependency versions** to pull in malicious transitive packages
- Packing in **large binary blobs** that static analysis can't easily inspect

Release Sentinel surfaces all of these changes explicitly so a human (or a CI gate)
can make an informed decision before updating.

---

## Quickstart

```bash
# Install (editable, with dev extras)
pip install -e ".[dev]"

# Compare two versions of a package
sentinel diff lodash 4.17.20 4.17.21

# Analyse as of a specific point in time (reproducible)
sentinel diff express 4.18.2 4.18.3 --as-of 2024-01-15T00:00:00Z

# Machine-readable JSON output
sentinel diff chalk 5.3.0 5.4.0 --json
```

---

## Hard Rules

See [`docs/PROJECT_RULES.md`](docs/PROJECT_RULES.md) for the five inviolable rules
this project follows. The most important: **we never execute code from downloaded
packages**. We download tarballs and read them as data only.

---

## Architecture

```
registry.py   →  Download & cache tarball, verify sha512 integrity
extractor.py  →  Safe extraction: reject path-traversal, symlinks, device files
differ.py     →  Compare two release trees: scripts, deps, bin, files, sizes
engine.py     →  Map evidence → allow / warn / block (explicit rules, no ML)
cli.py        →  `sentinel diff` command (Typer + Rich output)
models.py     →  Pydantic data models: ReleaseRef, Evidence, Report
```

---

## Evidence IDs

| ID | Severity | What it means |
|----|----------|---------------|
| `install_script_added` | HIGH | A new lifecycle hook was added |
| `install_script_changed` | MEDIUM | An existing hook was modified |
| `dependency_added` | LOW | A new package was added to dependencies |
| `dependency_removed` | LOW | A package was removed from dependencies |
| `dependency_version_changed` | LOW | A version spec changed |
| `bin_entry_added` | MEDIUM | A new binary was registered |
| `bin_entry_changed` | MEDIUM | A binary's target path changed |
| `large_size_jump` | MEDIUM | Package size grew by more than 2× |
| `large_file_count_jump` | LOW | File count grew by more than 50 |
| `new_file_added` | LOW | A file is present in the new version but not the old |
| `inspection_failed` | MEDIUM | A file could not be read or parsed |

---

## Decisions Made

See [`docs/DECISIONS.md`](docs/DECISIONS.md) for a full log.

---

## Development

```bash
# Run tests (no network)
pytest -m "not network"

# Run tests including live npm registry calls
pytest

# Lint + format check
ruff check src tests
ruff format --check src tests

# Coverage
pytest --cov -m "not network"
```

---

## Limitations (v0)

- **Static analysis only** — no sandbox or runtime execution monitoring.
- **No transitive dependency analysis** — only the direct package.json diff.
- **No known-vulnerability cross-referencing** — no OSV / NVD lookup yet.
- **JavaScript code is not parsed** — we can detect that a file changed but not *how*.
- **"No evidence" ≠ "safe"** — see Rule 4. Every report includes a limitations list.

---

## Not in Scope (v0)

ML scoring, dashboard UI, sandboxed execution, live registry monitoring, PyPI support,
GitHub Action. These may be added in future versions.

---

## Malware Samples & Evaluation Data

In strict adherence to **Rule 7**, real malicious packages:
- **Must never be committed** to the repository (`*.zip` and `data/external/` are gitignored).
- **Must remain outside the repository tree** at rest (e.g., in `C:\rs-data\datadog`).
- **Must never be extracted to disk** or executed. Members are inspected in memory only.

### Re-downloading the Evaluation Dataset
Evaluation samples are retrieved from the [DataDog Malicious Software Packages Dataset](https://github.com/DataDog/malicious-software-packages-dataset) using a shallow, sparse clone:

```bash
# 1. Clone repository structure outside the project (without checking out files)
git clone --depth 1 --filter=blob:none --no-checkout https://github.com/DataDog/malicious-software-packages-dataset.git C:\rs-data\datadog

# 2. Disable protectNTFS in the clone (avoids Win32 issues with unneeded third-party package names)
git -C C:\rs-data\datadog config core.protectNTFS false

# 3. Configure sparse checkout for npm manifest and compromised packages
git -C C:\rs-data\datadog sparse-checkout set --no-cone "/samples/npm/manifest.json" "/samples/npm/compromised_lib/**"

# 4. Checkout the matching files
git -C C:\rs-data\datadog checkout HEAD
```

---

## License

MIT — see [`LICENSE`](LICENSE).

