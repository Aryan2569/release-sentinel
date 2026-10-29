# Release Sentinel: Known Limitations and Blind Spots

This document provides a transparent, comprehensive accounting of the known limitations, architectural boundaries, and blind spots in Release Sentinel v1.3.

---

## 1. Changed (Not New) Native Binaries, WASM, and CI Workflows

Release Sentinel's file classifier and diff engine flag the *addition* of new executable or execution-adjacent assets:
- **Native binaries**: `.node`, `.so`, `.dll`, `.dylib`, ELF/Mach-O/PE executables (`native_binary_present`).
- **WebAssembly**: `.wasm` binaries.
- **CI Workflows**: Added workflows under `.github/workflows/`, `.gitlab-ci.yml`, `.circleci/`, and anchored Azure Pipelines configurations (`ci_write`).

**Limitation**: In differential analysis (`diff` mode), if a package already legitimately contained native binaries, WebAssembly modules, or CI workflow files in its baseline version, modifications to the *content* of an existing binary or workflow file are not deep-scanned or disassembled for malicious payload insertion.

---

## 2. Non-Registry Dependency Specifications

npm allows packages to declare dependencies using alternative specifiers rather than registry version ranges:
- Git URLs: `git+https://github.com/user/repo.git#commit`
- Direct tarball URLs: `https://example.com/package.tgz`
- Local file paths: `file:../local-pkg`

- Mirror or private registries: `https://registry.yarnpkg.com`

**Limitation**: Release Sentinel interacts strictly with the official npm registry (`https://registry.npmjs.org`) by default. Packages sourced from private registries, registry mirrors (e.g., `registry.yarnpkg.com`), Git repositories, or direct tarball URLs emit an unscanned non-registry source `WARN` (`unscanned_non_registry_source`) rather than fetching archives from unverified third-party endpoints. Non-registry dependency specifications are recorded in the manifest diff but are not fetched for transitive dependency analysis.

---

## 3. `binding.gyp` Auto-Build and Transitive Dependency Lifecycle Scripts

- **`binding.gyp`**: npm automatically triggers `node-gyp rebuild` during package installation if a `binding.gyp` file exists in the package root, even if no explicit `install` or `postinstall` script is declared in `package.json`.
- **Transitive Lifecycle Scripts**: If a package adds a dependency, that dependency may itself declare install-time scripts.

**Limitation**: In accordance with Rule 1 ("Never execute downloaded package code"), Release Sentinel never runs `node-gyp` or C/C++ compilation toolchains. Transitive dependency resolution inspects direct runtime dependencies up to a depth cap of 5 packages, but does not simulate recursive lifecycle hook execution across arbitrary multi-tier dependency trees.

---

## 4. Delisted Dependency Payloads

In late-2026 attacks (including hollow-release campaigns), attackers split the malicious payload into an added runtime dependency. 

**Limitation**: Release Sentinel's automated child package inspection requires the added dependency tarball to be retrievable from the npm registry (or an offline replay cache) as of the analysis timestamp. If the dependency was unpublished, deleted, or delisted prior to scanning, the payload within the child package cannot be inspected, and the release can only be evaluated based on top-level manifest signals (`dependency_added`, `hollow_dependency_injection`).

---

## 5. Dataset Bias Toward GuardDog-Found Samples

The 1,349 malicious eval pairs in the benchmark were curated from real-world npm compromises discovered and cataloged between 2024 and late 2026 (primarily from Datadog security research datasets).

**Limitation**: Datadog's collection methodology leverages static heuristics (such as GuardDog rules) to flag candidate compromises in public registry streams. Consequently, the benchmark has inherent selection bias toward attacks that exhibit discoverable static anomalies (e.g., suspicious process execution, encoded payloads, hardcoded network endpoints, or install lifecycle hooks). Attacks that rely entirely on novel multi-stage logic evasion or social engineering without static anomalies may be underrepresented.

---

## 6. Time-Travel Cutoff (`as_of`) Semantics

- **Historical Evaluation**: In regression testing and benchmark evaluations, `as_of` is explicitly anchored to the public disclosure/discovery date of each malicious release to prevent lookahead bias.
- **Production CLI**: In live production usage, `sentinel diff` defaults `as_of` to the current system time (`datetime.now(tz=UTC)`).

**Limitation**: If an operator runs `sentinel diff` without an `--as-of` override on a release whose upstream dependency was updated *after* the target release was published, the resolver will see registry metadata published up to the current moment. Operators verifying historical incidents must supply `--as-of <ISO_TIMESTAMP>`.

---

## 7. Yarn and pnpm Lockfiles Unsupported

Release Sentinel currently parses and audits npm `package-lock.json` files across format versions 1, 2, and 3.

**Limitation**: Alternative package manager lockfiles (`yarn.lock` for Yarn Classic/Berry, and `pnpm-lock.yaml`/`pnpm-lock.yml` for pnpm) use custom non-JSON YAML or bespoke line-oriented formats. Release Sentinel detects these files and raises an explicit `UnsupportedLockfileError`. Repositories relying solely on Yarn or pnpm cannot yet be audited directly with `sentinel check`.

---

## 8. 200-Package Safety Budget Cap

In large mono-repositories or major framework upgrades, hundreds or thousands of packages can transition simultaneously in a single lockfile commit.

**Limitation**: To prevent unbounded memory consumption, prolonged execution time, or potential denial-of-service from massive dependency graph updates, `sentinel check` enforces a default safety budget cap of `--max-packages 200`. If a lockfile diff changes more than 200 packages, Release Sentinel scans the first 200 packages, skips the remainder, records an explicit budget exceeded limitation, and fails closed to `WARN`. Teams managing large dependency updates can raise this threshold using `--max-packages <N>`.

---

## 9. Dependency Resolution Depth 1

When a package update introduces new runtime dependencies, Release Sentinel resolves each added dependency and inspects it (in diff mode against its previous release if one exists, or in tightened full-scan mode if brand new).

**Limitation**: This dependency-aware inspection operates strictly at **depth 1** (up to 5 direct added runtime dependencies). It does not recursively expand or analyze transitive sub-dependencies (depth 2+). If an attacker injects a malicious payload nested multiple levels down the dependency tree inside a clean, newly added direct dependency, that transitive payload is not analyzed.


---

## 10. The Capability-Novelty Blind Spot

Release Sentinel operates differentially by design: static capability signals (`dynamic_code`, `process_exec`, `network_access`, `env_enumeration`) are baseline-subtracted. If a package already contained calls to `eval()`, `child_process.exec()`, or `http.get()` in its baseline version, adding further calls to those same APIs in an update does not trigger new capability evidence.

**Limitation**: If an attacker compromises a package that *already legitimately utilized* powerful system primitives (for example, a CLI runner that already spawned child processes, or an HTTP library that already initiated network calls), new malicious invocations of those existing capabilities will not produce evidence flags. Detection in such compromised packages relies strictly on:
- Introductions of new external hosts or unlisted public IP addresses (`hardcoded_url`, `hardcoded_ip`).
- High-entropy or base64-encoded blobs (`long_encoded_blob`, `high_entropy_string`).
- Newly added or modified install lifecycle hooks (`install_script_added`, `install_script_changed`).
- Large anomalous size jumps or mass additions of executable files (`large_size_jump`, `notable_new_file`).
- Persistence modifications (`ci_write`, `shell_profile_write`, `git_hook_write`).

---

## 11. Scripting Language Payloads (.sh, .py, .ps1, .bat)

Release Sentinel classifies files into structural categories (`FileCategory`):
- `.sh`, `.ps1`, `.bat`, `.cmd` are categorized as `FileCategory.EXECUTABLE`. When newly introduced in an update, they emit `notable_new_file` at `Severity.MEDIUM`. Furthermore, install-time script commands in `package.json` that execute shell scripts (e.g. `sh setup.sh`, `powershell -enc ...`, `cmd /c ...`) are audited by `_check_lifecycle_script_command`.
- `.py` files are categorized as `FileCategory.SCRIPT`.

**Limitation**: The deep static content scanner is specialized for JavaScript and TypeScript syntax (e.g., AST/regex matching on `process.env`, `require('child_process')`, `Buffer.from`, `eval()`). Non-JS scripts (`.sh`, `.ps1`, `.bat`, `.py`) are not parsed or scanned for language-specific constructs (such as Python `subprocess.Popen` or PowerShell `Invoke-Expression`). Detection of non-JS payloads relies on lifecycle script invocation auditing and file-addition warnings, rather than language-specific static AST parsing.

---

## 12. String-Concatenation and Dynamic-Require Evasions

Attackers may attempt static analysis evasion through dynamic property access and string obfuscation:
- Property concatenation: `global['ev' + 'al'](...)` or `window['f' + 'etch'](...)`
- Dynamic module resolution: `require(['child', 'process'].join('_'))`
- Byte array assembly: `String.fromCharCode(101, 118, 97, 108)`

**Limitation**: While Release Sentinel flags dense hex/unicode escape sequences (`obfuscated_code`), Shannon entropy spikes (`high_entropy_string`), and base64 payloads (`long_encoded_blob`), subtle string concatenation or dynamic `require()` patterns that remain short and low-entropy without triggering obfuscation thresholds can evade static string matching. Full symbolic execution and taint tracking are intentionally excluded to keep per-package analysis latency under 100 milliseconds.

---

## 13. Files Exceeding 20,000 Lines (Chunked Scanning Divergence)

For files up to 25 MB with under 20,000 lines, Release Sentinel scans individual newly modified lines and performs fine-grained Shannon entropy calculation on all string tokens.

**Limitation**: For files exceeding 20,000 lines (such as massive auto-generated parser tables or bundled distributions), Release Sentinel switches to chunked windowed scanning (1 MB overlapping chunks with 64 KB overlap). In chunked mode, critical regex signals (`dynamic_code`, `process_exec`, `network_access`, `hardcoded_url`, `credential_file_read`, `registry_token`) are thoroughly evaluated, but per-line token Shannon entropy and minified long-line calculations are skipped to prevent CPU exhaustion.

---

## 14. Absence of Live Remote GitHub Commit/Tag Validation

Supply-chain attacks such as repo-jacking or unauthorized registry publications sometimes publish npm tarballs that do not correspond to any genuine commit or tagged release in the upstream GitHub repository.

**Limitation**: Release Sentinel audits packages by inspecting npm registry metadata, tarball signatures, and extracted payload files. It does not make live out-of-band network calls to GitHub, GitLab, or Bitbucket APIs to verify whether a published version matches a signed git commit or GitHub Actions OIDC provenance attestation (`npm provenance`).

---

## 15. Lockfile Injection, Integrity Constraints, and Resolved URL Verification

npm `package-lock.json` entries specify package metadata, an integrity checksum (e.g. `sha512-...`), and a `resolved` URL indicating where npm downloads the package tarball.

**Defensive Boundary & Limitation**:
- **Resolved URL Verification**: Release Sentinel verifies that any registry-hosted `resolved` URL matches the entry's declared name and version (`https://registry.npmjs.org/<name>/-/<basename>-<version>.tgz`, with full scope handling). A mismatch produces `lockfile_resolved_mismatch` (HIGH severity / Decision.BLOCK under both `default` and `strict` profiles) to thwart lockfile injection / tarball aliasing attacks.
- **Integrity Requirement**: Entries omitting `integrity` hashes generate `lockfile_missing_integrity` (MEDIUM severity / Decision.WARN). Custom private registries with bespoke non-standard URL path formats or legacy npm v1 lockfiles lacking integrity hashes will trigger warnings.

---

## 16. Metadata Cache TTL (1-Hour Invalidation in Live Mode)

In live analysis mode, npm packument metadata is cached with a 1-hour time-to-live (`metadata_ttl_seconds = 3600`).

**Limitation**: If an attacker or maintainer publishes or unpublishes a release within the 1-hour TTL window, an existing live client instance that previously cached that package will reuse its cached packument until the TTL expires or the cache is cleared. In evaluation and benchmark modes, metadata is kept frozen to guarantee reproducible results.

---

## 17. Single Root Lockfile Unless Explicitly Given

By default, `sentinel check` operates on a single `package-lock.json` file located in the repository root or passed via `--head`.

**Limitation**: Multi-package monorepos that maintain distinct nested `package-lock.json` files in workspace subdirectories must invoke `sentinel check` individually for each lockfile path. `--base-ref` automatically resolves the repository-relative path of the target lockfile, but does not auto-discover multiple independent lockfiles in a single invocation.

---

## 18. Hash-Pinned Action Requirements and Environment Hardening

GitHub Action execution relies on strict cryptographic supply-chain pinning (`requirements-action.lock`).

**Limitation**: The action installs dependencies strictly via `pip install --require-hashes` and `pip install --no-deps`. Custom runners with modified Python environments or unlisted platforms outside standard wheel distributions must maintain a regenerated lockfile matching their specific architecture hashes.
