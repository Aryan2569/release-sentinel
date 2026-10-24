# Contributing to Release Sentinel

Thank you for your interest in contributing to Release Sentinel! We welcome issues, bug reports, and pull requests.

## Development Setup

Release Sentinel requires **Python 3.12+**.

1. **Clone the repository**:
   ```bash
   git clone https://github.com/release-sentinel/release-sentinel.git
   cd release-sentinel
   ```

2. **Create and activate a virtual environment**:
   ```bash
   python -m venv .venv
   # Windows PowerShell:
   .venv\Scripts\Activate.ps1
   # Linux/macOS:
   source .venv/bin/activate
   ```

3. **Install dependencies in editable mode with development tools**:
   ```bash
   pip install --upgrade pip
   pip install -e ".[dev]"
   ```

## Running Tests and Linting

Before submitting code, ensure all tests and linters pass cleanly:

- **Linting & formatting**:
  ```bash
  ruff check .
  ```
- **Test suite**:
  ```bash
  pytest
  ```
- **Smoke test wheel build**:
  ```bash
  python -m build
  pytest tests/test_wheel_smoke.py
  ```

---

## Core Project Rules (Safety & Design)

All contributors must adhere to our seven core architectural rules:

1. **Rule 1 — Never Execute Downloaded Code**: Never run `npm install`, `node`, `npx`, or lifecycle scripts from downloaded packages. Inspect them as inert data only.
2. **Rule 2 — Safe Tarball Extraction**: In-memory extraction must enforce path traversal rejection (`..`), absolute path rejection, symlink/hardlink rejection, device file rejection, compression ratio limits, and hard file/size caps.
3. **Rule 3 — Time-Awareness Is Core**: Any function using registry metadata or advisories must accept an `as_of: datetime` cutoff and never leak information published after that timestamp.
4. **Rule 4 — Evidence, Not Verdicts**: Silence never implies safety. If a file cannot be inspected (e.g. native binary, unreadable archive, budget ceiling exceeded), record explicit limitations and evidence.
5. **Rule 5 — Write Only to Approved Directories**: Code must write only to approved locations (project folder, cache dir `~/.cache/release_sentinel`).
6. **Rule 6 — No Real Malware in the Repo**: Never commit real malware, exploit payloads, or credentials. Tests must use inert, harmless synthetic fixtures.
7. **Rule 7 — Malware Sample Handling**: Real malicious samples from external research datasets remain in encrypted ZIPs at rest, are loaded directly into memory without disk extraction, and are never committed or distributed.

---

## Pull Request Guidelines

- Ensure every new feature or bugfix includes automated unit tests.
- Maintain documentation integrity and update relevant docs (`README.md`, `docs/DECISIONS.md`).
- Follow the GitHub pull request workflow; CI checks must pass before merging.
