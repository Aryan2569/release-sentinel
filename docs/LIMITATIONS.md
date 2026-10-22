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

**Limitation**: Release Sentinel's dependency resolver interacts strictly with npm-compatible package registries via standard semantic versioning queries. Non-registry specifications are recorded in the manifest diff but are not resolved or fetched for child dependency analysis.

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
