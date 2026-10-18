# Release Sentinel — Project Rules

> **Re-read this file at the start of every session.**

## Rule 1 — Never Execute Downloaded Code

Never run `npm install`, `npx`, `node`, any package script, or any other code from
downloaded packages. Only download tarballs and read them **as data** (open files,
parse JSON, measure sizes). Execution means analysis; static inspection only.

## Rule 2 — Safe Tarball Extraction

Extract tarballs into a temporary directory with all of these checks applied:

- **Reject absolute paths** — any member whose path starts with `/` or a drive letter.
- **Reject path traversal** — any member containing `..` as a path component.
- **Reject symlinks** — `tarinfo.issym()` or `tarinfo.islnk()`.
- **Reject hardlinks** — `tarinfo.islnk()`.
- **Reject device files** — `tarinfo.isdev()`, `tarinfo.isfifo()`.
- **Apply tarfile `data` filter** (`tarfile.data_filter`) as the baseline, then add the
  above custom checks on top.
- **Cap file count** — default soft-cap at 5,000 members; hard ceiling at 10,000.
- **Cap total size** — default soft-cap at 200 MB; hard ceiling at 500 MB.
- **Soft-cap behaviour** — on hitting a cap, do not abort: extract priority files
  (package.json, install-script targets, new/changed JS files) and record the
  limitation explicitly in the report.
- Write nothing outside the designated temp directory.

## Rule 6 — No Real Malware in the Repo

Never put real malware, real exploit payloads, or real credential strings in the
repository or test fixtures. Use **harmless synthetic strings** that merely trigger
the heuristics (e.g. `"require('child_process')"` in an inert JS string literal, not
an actual payload). All test tarballs must be demonstrably harmless.

## Rule 3 — Time-Awareness Is a Core Design Rule

Any function that uses external knowledge (registry metadata, advisories, popularity
signals, etc.) **must** accept an `as_of: datetime` parameter and **must not** return
or use data published or observed after that timestamp. This makes every analysis
reproducible and auditable.

## Rule 4 — Evidence, Not Verdicts

"No suspicious evidence found" **never** means "safe". When something cannot be
inspected (binary file, extraction failure, network error), report that explicitly as
an `Evidence` item with `id="inspection_failed"`. Never silently pass an item that
could not be examined.

## Rule 5 — Write Only Inside Approved Directories

The tool may write files only to:

1. The project directory (`src/`, `tests/`, etc.)
2. The on-disk cache directory (default: `~/.cache/release_sentinel/`)

Download from the **public npm registry** (`https://registry.npmjs.org`) only.
All HTTP requests must include a descriptive `User-Agent` header and reasonable
timeouts (connect: 10 s, read: 60 s).

## Rule 7 — Malware Sample Handling

Real malicious samples are for static analysis only. They stay in their encrypted ZIPs at rest. Never extract them to disk (read members in memory only). Never execute, import, require or open them with anything that could run them. Never copy them into the project folder or commit them. When reporting, print only file paths, evidence types and snippets truncated to 120 characters. Tests use synthetic encrypted ZIPs created inside the test, never real samples.

