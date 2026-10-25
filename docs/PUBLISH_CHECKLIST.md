# Release Sentinel Maintainer Publishing Checklist

This step-by-step runbook guides a maintainer through the complete publishing workflow for **v0.5.0 (public alpha)** and **v1.6 (internal milestone)** on Windows PowerShell.

---

## 1. Prerequisites

Before starting, ensure your local environment has the required credentials and CLI tools:

1. **GitHub CLI**:
   Ensure you are logged into GitHub with release creation rights:
   ```powershell
   gh auth status
   # If not logged in:
   gh auth login
   ```

2. **PyPI API Token**:
   - Obtain an API token from [PyPI Account Settings](https://pypi.org/manage/account/token/) with upload permissions for `release-sentinel` (or TestPyPI first).
   - Install build tools and twine:
     ```powershell
     pip install --upgrade build twine
     ```

3. **Clean Working Tree**:
   Ensure all changes are committed and no untracked files linger:
   ```powershell
   git status
   ```

---

## 2. Local Verification Commands

Run the full pre-release quality gate locally:

```powershell
# 1. Run the comprehensive pre-publish audit
powershell -ExecutionPolicy Bypass -File scripts\pre_publish_check.ps1

# 2. Run the linter
ruff check .

# 3. Run the unit and integration test suite
pytest

# 4. Verify canonical metrics consistency
python scripts\verify_metrics.py

# 5. Clean and rebuild distributions
if (Test-Path dist) { Remove-Item -Recurse -Force dist }
python -m build

# 6. Run wheel smoke test in clean virtualenv
pytest tests\test_wheel_smoke.py
```

All commands must exit cleanly with code `0`.

---

## 3. Git Tagging

Both the internal tracking tag (`v1.6`) and the public semantic version tag (`v0.5.0`) point to the exact same release commit:

```powershell
# Verify current HEAD commit
git log -1 --oneline

# Create annotated git tags
git tag -a v1.6 -m "Release Sentinel internal milestone v1.6 (public alpha prep)"
git tag -a v0.5.0 -m "Release Sentinel v0.5.0 public alpha release"

# Push tags to GitHub
git push origin master
git push origin v1.6
git push origin v0.5.0
```

---

## 4. GitHub Release Creation

Create the public GitHub Release and attach the built wheel and source distribution:

```powershell
# Extract release notes from CHANGELOG.md for v0.5.0
# Create release with release assets attached
gh release create v0.5.0 dist\* `
  --title "Release Sentinel v0.5.0 (Public Alpha)" `
  --notes "Public alpha release of Release Sentinel: time-aware static security gate for npm package-lock.json dependency updates in CI. See CHANGELOG.md for details."
```

---

## 5. Publishing to PyPI

### Step A: TestPyPI (Recommended First Step)

```powershell
# Upload to TestPyPI
twine upload --repository testpypi dist/*

# Test installation from TestPyPI in an isolated shell:
pip install --no-cache-dir --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ release-sentinel==0.5.0
sentinel --version
```

### Step B: Production PyPI

Once verified on TestPyPI:

```powershell
# Upload to Production PyPI
twine upload dist/*
```

Enter your PyPI API token (`pypi-...`) when prompted.

---

## 6. Post-Publish Verification

Verify that external users can install and execute Release Sentinel seamlessly:

1. **Verify PyPI Package**:
   In a fresh PowerShell session:
   ```powershell
   pip install --no-cache-dir release-sentinel==0.5.0
   sentinel --version
   # Expected output: sentinel 0.5.0
   ```

2. **Verify GitHub Action in Demo Repo**:
   - Push a test commit or pull request to `examples/demo-repo/`.
   - Confirm that the workflow runs using `Aryan2569/release-sentinel@v0.5.0`.
   - Confirm step summary and pull request commenting behavior.
