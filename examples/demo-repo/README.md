# Release Sentinel Demo Repository

This demonstration repository illustrates how **Release Sentinel** protects pull requests against compromised npm dependency updates using GitHub Actions.

> [!NOTE]
> **Minimal Demo Manifest**: The `package-lock.json` in this repository is intentionally minimal for demonstration purposes, containing only top-level dependencies (`express`, `lodash`). In a full production application, npm generates a comprehensive dependency tree with all transitive dependencies, all of which Release Sentinel audits during pull requests.

---

## What Is Inside

- `package.json`: A standard application manifest declaring dependencies (`express`, `lodash`).
- `package-lock.json`: Minimal npm v3 lockfile pinning installed package versions.
- `index.js`: A trivial Express application using Lodash.
- `.github/workflows/sentinel.yml`: Configured workflow using Release Sentinel to audit lockfile changes on pull requests.

---

## Testing Locally with `sentinel check`

You can test Release Sentinel against this demo repository locally using the CLI:

1. **Install Release Sentinel** from the release tag:
   ```bash
   pip install git+https://github.com/Aryan2569/release-sentinel@v0.5.0
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
   Release Sentinel fetches package metadata in memory, computes the static diff, and reports:
   ```markdown
   Verdict: ✅ ALLOW — All 1 changed package(s) passed security checks.
   ```

---

## Planned Demonstration Pull Requests

When evaluating or showcasing Release Sentinel in CI, three standard pull requests demonstrate the gate's behavior:

### PR 1: Benign Upgrade (`ALLOW`, Quiet Summary)
- **Change**: Bump `lodash` from `4.17.20` to `4.17.21`.
  - Version: `"4.17.21"`
  - Resolved: `"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"`
  - Integrity: `"sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg=="`
- **Expected Outcome**:
  - Verdict: `✅ ALLOW`.
  - Gate status: **Passed** (exit code `0`).
  - PR comment: **None**. Because `comment-on: notable` is configured, clean updates do not produce noisy comments. Full audit details appear in `$GITHUB_STEP_SUMMARY`.

### PR 2: Tarball Aliasing / URL Mismatch (`BLOCK`, Security Comment)
- **Change**: Bump `lodash` to `4.17.21` in `package-lock.json`, but alter its `resolved` URL to point to a mismatched tarball (e.g. `https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz`).
- **Expected Outcome**:
  - Verdict: `🛑 BLOCK`.
  - Gate status: **Failed** (exit code `1` under `fail-on: block`).
  - PR comment: **Posted automatically**. An alert detailing `lockfile_resolved_mismatch` (`Severity.HIGH`) is posted directly to the pull request conversation, blocking merge.

### PR 3: Lifecycle Install Script Addition (`WARN`/`BLOCK`, Notable Finding)
- **Change**: Introduce an update or dependency that registers an install-time lifecycle hook (`preinstall`, `install`, `postinstall`).
- **Expected Outcome**:
  - Verdict: `⚠️ WARN` (or `🛑 BLOCK` if corroborated with network access or dynamic code).
  - Gate status: Passes under `fail-on: block` unless corroborated; fails under `fail-on: warn`.
  - PR comment: **Posted automatically**. Because `install_script_added` carries `Severity.HIGH`, it meets the `notable` threshold, surfacing a detailed evidence table to reviewers.
