# Release Sentinel Demo Repository

This minimal repository demonstrates how **Release Sentinel** protects pull requests against compromised npm dependency updates using GitHub Actions.

---

## What Is Inside

- `package.json`: A standard application manifest declaring dependencies (`express`, `lodash`).
- `package-lock.json`: Standard npm v3 lockfile pinning installed package versions.
- `.github/workflows/sentinel.yml`: Configured workflow using Release Sentinel to audit lockfile changes on pull requests.

---

## Testing Locally with `sentinel check`

You can test Release Sentinel against this demo repository locally using the CLI:

1. **Install Release Sentinel**:
   ```bash
   pip install release-sentinel
   ```

2. **Simulate a dependency update**:
   Make a copy of `package-lock.json`:
   ```bash
   cp package-lock.json package-lock.json.base
   ```

   Update a package version in `package-lock.json` (for example, bump `lodash` to `4.17.21`):
   ```bash
   # Audit the diff between base and head
   sentinel check --base package-lock.json.base --head package-lock.json
   ```

3. **Observe the Verdict**:
   Release Sentinel will fetch tarball metadata in memory, compute the static diff, and report:
   ```markdown
   Verdict: ✅ ALLOW — All 1 changed package(s) passed security checks.
   ```

---

## Triggering the GitHub Action Demo in a PR

1. Fork or clone this repository to your GitHub account.
2. Update `.github/workflows/sentinel.yml` to point to the published action:
   ```yaml
   uses: <your-github-user>/release-sentinel@v0.5.0
   ```
3. Create a new branch:
   ```bash
   git checkout -b test-dependency-update
   ```
4. Modify `package-lock.json` to bump a dependency, or introduce a package with install scripts.
5. Push the branch and open a Pull Request:
   ```bash
   git add package-lock.json
   git commit -m "chore: bump dependencies"
   git push origin test-dependency-update
   ```
6. The GitHub Action will execute:
   - If findings meet the `notable` threshold or trigger `BLOCK`, an automated security comment will appear on the pull request with full evidence breakdowns and explanations.
   - Clean or non-notable updates will record audit details in `$GITHUB_STEP_SUMMARY` without cluttering the pull request conversation.
