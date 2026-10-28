# Release Sentinel: Maintainer Publishing Checklist

This step-by-step guide walks a maintainer through publishing **Release Sentinel v0.5.0 (Public Alpha)** using **Windows PowerShell**.

---

## 1. GitHub Account Configuration (Privacy First)

Before pushing any commits to GitHub, ensure your personal email address is protected from accidental leakage:

1. In your browser, open GitHub: **Settings > Emails** (`https://github.com/settings/emails`).
2. Enable these two critical protections:
   - ✅ **"Keep my email addresses private"**
   - ✅ **"Block command line pushes that expose my email"**
3. Note your GitHub-provided noreply email address displayed on that page:
   `245837888+Aryan2569@users.noreply.github.com`
4. In your terminal, verify your git author and committer configuration:
   ```powershell
   git config user.name "Aryan Kumar"
   git config user.email "245837888+Aryan2569@users.noreply.github.com"
   ```

---

## 2. Pre-Publish Quality Gate Verification

Run the entire automated verification suite locally. Every command must exit with code `0`:

```powershell
# 1. Run repository hygiene and path check
powershell -ExecutionPolicy Bypass -File scripts\pre_publish_check.ps1

# 2. Run linter
ruff check .

# 3. Run unit and integration tests (offline suite)
pytest -m "not network"

# 4. Verify evaluation metrics consistency against METRICS.json
python scripts\verify_metrics.py

# 5. Build clean source distribution and pure Python wheel
if (Test-Path dist) { Remove-Item -Recurse -Force dist }
python -m build

# 6. Run wheel installation smoke test in an isolated venv
pytest tests\test_wheel_smoke.py
```

---

## 3. Remote Setup & Staged Publishing (Private First)

> [!IMPORTANT]
> **Do NOT re-create tags with `git tag -a`**.
> Tags `v0.5.0` and `v1.0` through `v1.6` are already committed in the rewritten repository history. Re-tagging would create conflicting tag objects.
> The default branch is **`main`**.

### Step A: Create GitHub Repository as Private
Creating the repository as private first allows you to verify that GitHub Actions CI runs completely green on Ubuntu before exposing the project publicly:

```powershell
# Ensure you are logged into GitHub CLI
gh auth status

# Create a private repository
gh repo create Aryan2569/release-sentinel --private
```

### Step B: Push Main Branch and Existing Tags
```powershell
# Ensure local branch is named main
git branch -M main

# Add origin remote
git remote add origin https://github.com/Aryan2569/release-sentinel.git

# Push main branch
git push -u origin main

# Push all release and tracking tags
git push origin --tags
```

### Step C: Watch GitHub Actions CI
1. Open the repository on GitHub: `https://github.com/Aryan2569/release-sentinel/actions`.
2. Confirm the CI workflow runs and passes across all steps (hash-locked install, linter, tests, wheel smoke).
3. If any step fails on Ubuntu, address it locally, commit with your noreply email, and push.

### Step D: Make Repository Public
Once CI passes green:
1. Open **Settings > General > Danger Zone**.
2. Click **Change repository visibility** -> **Make public**.

---

## 4. Creating the Public GitHub Release

Once public, draft the GitHub Release for `v0.5.0`:

```powershell
# Publish the release with distribution artifacts attached
gh release create v0.5.0 dist/* `
  --title "Release Sentinel v0.5.0 (Public Alpha)" `
  --notes "Release Sentinel v0.5.0 (Public Alpha): A time-aware static security gate for npm package-lock.json dependency updates in CI. Consult CHANGELOG.md for release details."
```

---

## 5. Setting Up the Standalone Live Demo Repository

> [!NOTE]
> GitHub Actions workflows stored in nested directories (such as `examples/demo-repo/.github/workflows/`) **never run automatically** inside the parent repository. The demo must live in its own dedicated GitHub repository.

To set up the demo repository:

```powershell
# 1. Create a clean folder outside the project
$DEMO_DIR = "$HOME\release-sentinel-demo"
New-Item -ItemType Directory -Path $DEMO_DIR -Force
Copy-Item -Recurse -Force "examples\demo-repo\*" "$DEMO_DIR\"

# 2. Initialize git repository
cd $DEMO_DIR
git init -b main
git config user.name "Aryan Kumar"
git config user.email "245837888+Aryan2569@users.noreply.github.com"
git add -A
git commit -m "feat: initial commit for Release Sentinel live demo"

# 3. Create public demo repo and push
gh repo create Aryan2569/release-sentinel-demo --public --source=. --push
```

Verify that `.github/workflows/sentinel.yml` in the demo repository uses the release action:
```yaml
- name: Run Release Sentinel
  uses: Aryan2569/release-sentinel@v0.5.0
```

Open a test pull request in the demo repository to observe the automated PR comment.

---

## 6. Capturing Screenshots & Recording Clips

1. **Terminal Recording**:
   - Use Windows Game Bar (`Win + Alt + R`) or [VHS](https://github.com/charmbracelet/vhs) / [Asciinema](https://asciinema.org/).
   - Set console font size to 15 pt with a high-contrast dark theme.
   - Run the demo command:
     ```powershell
     sentinel demo --pair axios 1.14.0 1.14.1
     ```
2. **PR Comment Screenshot**:
   - Navigate to the test pull request in the demo repo.
   - Capture a clean crop of the `<!-- release-sentinel-pr-comment -->` rendered markdown table.

---

## 7. Appendix: Optional PyPI Upload (Not Yet)

Release Sentinel is currently distributed directly via git tag (`pip install git+https://github.com/Aryan2569/release-sentinel@v0.5.0`). Uploading to PyPI is optional and planned for later alpha stages.

When ready to publish to PyPI:
1. Verify the package name `release-sentinel` is free:
   ```powershell
   pip index versions release-sentinel
   ```
2. Validate distribution archives:
   ```powershell
   pip install twine
   twine check dist/*
   ```
3. Upload to TestPyPI first:
   ```powershell
   twine upload --repository testpypi dist/*
   ```
4. Upload to Production PyPI:
   ```powershell
   twine upload dist/*
   ```
