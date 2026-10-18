"""Diff-based content scanner for Release Sentinel (Stage 2.5).

Scans file content for suspicious patterns using package-wide capability-level diffing.
Only flags NEW capabilities whose normalized form is absent from the entire old release.

Rule 1: no code is executed. All analysis is done by regex/string matching
        on bytes read from disk.
Rule 6: patterns are generic heuristics using harmless synthetic strings
        in tests, never real malware signatures.

Stage 2.5 changes
-----------------
* Capability-level diff: matches are normalized per signal type across the whole package.
* Never line-diff minified or bundled files.
* Entropy and encoded blobs: only when the blob's hash is absent from the old release
  AND the file is outside test, fixture, data, locale, and source-map paths.
* URL/IP signals: only when the host is new to the package; ignore comments and license headers.
* Env enumeration: raised to HIGH severity for credential harvesting detection.
* Import-time payload corroboration without requiring install scripts.
"""

from __future__ import annotations

import hashlib
import logging
import math
import re
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from release_sentinel.extractor import ExtractionResult, ReleaseContents
from release_sentinel.file_classifier import FileCategory, _is_minified, classify
from release_sentinel.models import Evidence, Severity

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Maximum file size to scan for content (2 MB)
_MAX_SCAN_SIZE = 2 * 1024 * 1024

# Minimum string length for entropy check
_ENTROPY_MIN_LEN = 64

# Shannon entropy threshold (bits/char) for flagging strings
_ENTROPY_THRESHOLD = 4.5

# Minimum line length to flag as a long encoded blob
_LONG_LINE_THRESHOLD = 500

# Minimum number of distinct env-var accesses to flag bulk enumeration
_ENV_ENUM_MIN_ACCESSES = 3

# License keywords commonly found in headers
_LICENSE_KEYWORDS = (
    "license",
    "copyright",
    "spdx",
    "mit",
    "apache",
    "author",
    "contributors",
    "all rights reserved",
    "mozilla public",
    "bsd",
)

# ---------------------------------------------------------------------------
# Signal definitions
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Signal:
    """A single content-based detection pattern."""

    id: str
    severity: Severity
    pattern: re.Pattern[str]
    explanation_template: str  # may contain {match} placeholder
    legitimate_use_note: str


@dataclass(frozen=True)
class SignalMetadata:
    """Metadata for specialized detection signals."""

    id: str
    severity: Severity
    explanation_template: str
    legitimate_use_note: str


_PROCESS_EXEC_METADATA = SignalMetadata(
    id="process_exec",
    severity=Severity.MEDIUM,
    explanation_template=(
        "New code references process-execution APIs ({match}). "
        "These can run arbitrary system commands if called with untrusted input."
    ),
    legitimate_use_note=(
        "Build tools, test runners, and many CLI packages legitimately use "
        "child_process to invoke compilers, linters, or git. "
        "Review whether the call site is reachable from install-time scripts."
    ),
)

_CREDENTIAL_READ_METADATA = SignalMetadata(
    id="credential_file_read",
    severity=Severity.HIGH,
    explanation_template=(
        "New code reads a credential or configuration file path ({match}). "
        "Reading credential files from user home directories is a common "
        "exfiltration technique."
    ),
    legitimate_use_note=(
        "npm config tools and git clients legitimately read .npmrc and .gitconfig. "
        "Review whether the access is conditional on user consent and whether the "
        "data is logged or transmitted."
    ),
)


# All patterns use harmless synthetic constructs (Rule 6).
_SIGNALS: list[Signal] = [
    Signal(
        id="dynamic_code",
        severity=Severity.HIGH,
        pattern=re.compile(
            r"""(?x)
            \beval\s*\(        # eval(
            | new\s+Function\s*\(   # new Function(
            | vm\.runIn(?:New)?Context  # vm.runInContext / vm.runInNewContext
            | vm\.Script\s*\(       # vm.Script(
            """,
        ),
        explanation_template=(
            "New code uses dynamic code evaluation ({match}). "
            "This can execute arbitrary code constructed at runtime, "
            "commonly used to hide malicious payloads."
        ),
        legitimate_use_note=(
            "Template engines, sandboxes, and REPL implementations legitimately use "
            "eval or new Function. Review what data is passed to the call."
        ),
    ),
    Signal(
        id="network_access",
        severity=Severity.MEDIUM,
        pattern=re.compile(
            r"""(?x)
            require\s*\(\s*['"](?:http|https|net|dgram)['"]\s*\)  # require('http')
            | \bfetch\s*\(          # fetch(
            | \.get\s*\(\s*['"](http|https)  # .get('https…)
            | new\s+XMLHttpRequest  # new XMLHttpRequest
            | require\s*\(\s*['"](?:axios|node-fetch|got|request|superagent)['"]\s*\)
            """,
        ),
        explanation_template=(
            "New code performs or imports network-access APIs ({match}). "
            "Unexpected outbound requests from a library can exfiltrate data."
        ),
        legitimate_use_note=(
            "HTTP clients are used legitimately for API calls, CDN downloads, and "
            "update checks. Review whether the request is conditional on install-time "
            "execution, and what data is sent."
        ),
    ),
    Signal(
        id="hardcoded_url",
        severity=Severity.LOW,
        pattern=re.compile(
            r"""(?x)
            https?://(?!                              # http(s):// but NOT
              (?:(?:www\.|registry\.)?npmjs\.(?:com|org))  # npm registry (www., registry., or bare)
              | (?:www\.)?github\.com             # GitHub
              | (?:www\.)?githubusercontent\.com  # GitHub raw
              | (?:www\.)?jsdelivr\.net          # CDN
              | (?:www\.)?unpkg\.com             # CDN
              | (?:www\.)?cdnjs\.cloudflare\.com # CDN
              | localhost                        # localhost
            )
            [^\s"'`>]{20,}                       # URL must be at least 20 chars
            """,
        ),
        explanation_template=(
            "New code contains a hardcoded URL: {match}. "
            "Unexpected hard-coded URLs in library code may indicate "
            "a data-exfiltration or command-and-control endpoint."
        ),
        legitimate_use_note=(
            "Documentation links, API base URLs, and CDN references are common. "
            "URLs pointing to infrastructure not associated with the package "
            "deserve manual review."
        ),
    ),
    Signal(
        id="hardcoded_ip",
        severity=Severity.MEDIUM,
        pattern=re.compile(
            r"""(?x)
            \b(?!                        # NOT
              127\.\d+\.\d+\.\d+        # loopback
              | 0\.0\.0\.0              # any-address
              | 10\.\d+\.\d+\.\d+      # RFC1918 10.x
              | 192\.168\.\d+\.\d+     # RFC1918 192.168.x
              | 172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+  # RFC1918 172.16-31.x
            )
            (?:\d{1,3}\.){3}\d{1,3}    # any IPv4
            \b
            """,
        ),
        explanation_template=(
            "New code contains a hardcoded non-private IP address: {match}. "
            "This may be a command-and-control or exfiltration endpoint."
        ),
        legitimate_use_note=(
            "Some packages hard-code public DNS servers, NTP servers, or CDN IP ranges. "
            "Review whether the IP is associated with the package's legitimate infrastructure."
        ),
    ),
    Signal(
        id="registry_token",
        severity=Severity.HIGH,
        pattern=re.compile(
            r"""(?x)
            NPM_TOKEN                   # npm token env var
            | _authToken                # .npmrc auth token key
            | registry-token            # generic registry token
            | GITHUB_TOKEN              # GitHub Actions token
            | NPM_AUTH_TOKEN            # alternate npm token name
            | NODE_AUTH_TOKEN           # GitHub Actions npm auth
            """,
        ),
        explanation_template=(
            "New code references registry authentication tokens ({match}). "
            "Accessing publish tokens from library code is unusual and may "
            "indicate credential theft targeting CI environments."
        ),
        legitimate_use_note=(
            "Publish scripts and some monorepo tools legitimately read NPM_TOKEN "
            "or GITHUB_TOKEN. Review whether this access is in a library (unexpected) "
            "or in a dev tool (expected)."
        ),
    ),
    Signal(
        id="long_encoded_blob",
        severity=Severity.MEDIUM,
        pattern=re.compile(
            r"""(?x)
            atob\s*\(             # atob(  — base64 decode
            | Buffer\.from\s*\([^)]*['"](base64|hex)['"]  # Buffer.from('...', 'base64')
            | \\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){15,}  # long hex escape sequence
            """,
        ),
        explanation_template=(
            "New code decodes a potentially obfuscated payload ({match}). "
            "Base64/hex decode at runtime is commonly used to hide malicious strings "
            "from static analysis."
        ),
        legitimate_use_note=(
            "Image processing, binary protocol handling, and cryptographic libraries "
            "legitimately decode base64 or hex. Review what is being decoded and "
            "whether it is a constant payload."
        ),
    ),
    Signal(
        id="ci_write",
        severity=Severity.HIGH,
        pattern=re.compile(
            r"""(?x)
            ['"`.+]\.github[/\\]workflows  # GitHub Actions workflow
            | ['"`.+]\.gitlab-ci           # GitLab CI
            | ['"`.+]\.circleci            # CircleCI
            | GITHUB_ACTIONS_WORKFLOW      # env var
            """,
        ),
        explanation_template=(
            "New code references CI workflow paths ({match}). "
            "Writing to CI configuration is a persistence technique used to "
            "inject malicious steps into future builds."
        ),
        legitimate_use_note=(
            "CI configuration generators and scaffolding tools legitimately write "
            "workflow files. Review whether this is a library (unexpected) or a "
            "dev tool (may be expected)."
        ),
    ),
    Signal(
        id="shell_profile_write",
        severity=Severity.HIGH,
        pattern=re.compile(
            r"""(?x)
            ['"`.+]\.bashrc['"`]     # bash profile
            | ['"`.+]\.zshrc['"`]    # zsh profile
            | ['"`.+]\.profile['"`]  # POSIX profile
            | ['"`.+]\.bash_profile['"`]
            | ['"`.+]\.zprofile['"`]
            """,
        ),
        explanation_template=(
            "New code references shell profile files ({match}). "
            "Writing to shell profiles is a persistence technique: "
            "malicious code added to .bashrc runs on every new shell session."
        ),
        legitimate_use_note=(
            "Installer scripts for development tools legitimately modify shell profiles "
            "to add paths. Review whether this modification is transparent, documented, "
            "and user-initiated."
        ),
    ),
    Signal(
        id="git_hook_write",
        severity=Severity.HIGH,
        pattern=re.compile(
            r"""(?x)
            ['"`.+]\.git[/\\]hooks   # .git/hooks directory
            | husky\.hooks           # husky git hooks config
            """,
        ),
        explanation_template=(
            "New code references git hook paths ({match}). "
            "Writing to .git/hooks installs code that runs on every git operation "
            "and is a known persistence/exfiltration technique."
        ),
        legitimate_use_note=(
            "Tools like husky legitimately install git hooks for pre-commit checks. "
            "Review whether the hook content is visible and the package is a dev tool."
        ),
    ),
]


# ---------------------------------------------------------------------------
# Path and Classifier Helpers
# ---------------------------------------------------------------------------


def is_minified_or_bundled(
    path: Path | bytes | str | None, rel_path: str, cat: FileCategory | None = None
) -> bool:
    """Return True if the file appears to be minified or bundled."""
    if cat == FileCategory.MINIFIED:
        return True
    name = Path(rel_path).name.lower()
    if ".min." in name or ".bundle." in name or name.endswith("bundle.js"):
        return True
    return _is_minified(path)


def is_exempt_path(rel_path: str, cat: FileCategory | None = None) -> bool:
    """Return True if path is in test, fixture, data, locale, or source-map directories."""
    if cat in {FileCategory.SOURCE_MAP, FileCategory.ASSET, FileCategory.DOCUMENT}:
        return True
    rel_lower = rel_path.lower().replace("\\", "/")
    if rel_lower.endswith(".map") or ".map." in rel_lower:
        return True

    parts = [p.lower() for p in Path(rel_path).parts]
    exempt_names = {
        "test",
        "tests",
        "__tests__",
        "spec",
        "specs",
        "fixture",
        "fixtures",
        "__fixtures__",
        "mock",
        "mocks",
        "data",
        "dataset",
        "datasets",
        "locale",
        "locales",
        "i18n",
        "l10n",
        "lang",
        "languages",
    }
    if any(p in exempt_names for p in parts):
        return True

    basename = parts[-1] if parts else ""
    for suffix in [
        ".test.js",
        ".test.ts",
        ".spec.js",
        ".spec.ts",
        ".test.jsx",
        ".test.tsx",
        ".spec.jsx",
        ".spec.tsx",
        ".test.cjs",
        ".test.mjs",
        ".spec.cjs",
        ".spec.mjs",
        ".json",
        ".csv",
        ".tsv",
        ".yaml",
        ".yml",
        ".toml",
        ".xml",
    ]:
        if basename.endswith(suffix):
            return True

    return False


# ---------------------------------------------------------------------------
# Comment, Host, and API Normalization Helpers
# ---------------------------------------------------------------------------


def _read_text_safe(target: Path | bytes | str | None) -> str:
    """Read text content from *target*, capping at _MAX_SCAN_SIZE."""
    if target is None:
        return ""
    if isinstance(target, (bytes, bytearray)):
        if len(target) > _MAX_SCAN_SIZE:
            logger.debug("Skipping content scan for large in-memory bytes (%d bytes)", len(target))
            return ""
        return target.decode("utf-8", errors="replace")
    if isinstance(target, str):
        if len(target) > _MAX_SCAN_SIZE:
            return ""
        return target
    if isinstance(target, Path):
        try:
            if target.stat().st_size > _MAX_SCAN_SIZE:
                logger.debug("Skipping content scan for large file: %s", target)
                return ""
            return target.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.debug("Cannot read %s for content scan: %s", target, exc)
            return ""
    return ""


def _is_js_or_ts_file(rel_path: str) -> bool:
    """Return True if the file is JavaScript, TypeScript, or extensionless script."""
    name = Path(rel_path).name.lower()
    return name.endswith((
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".mts",
        ".cts",
        ".jsx",
        ".tsx",
    )) or "." not in name


def strip_js_comments(text: str) -> str:
    """Replace JavaScript comments (// ... and /* ... */) with spaces, preserving newlines.

    String literals ('...', "...", `...`) are preserved.
    Every newline character is preserved so line numbering remains identical to original.
    Non-newline comment characters are replaced with space (' ').
    """
    out: list[str] = []
    i = 0
    n = len(text)
    state = "NORMAL"

    while i < n:
        c = text[i]
        if state == "NORMAL":
            if c == "'":
                state = "S_QUOTE"
                out.append(c)
                i += 1
            elif c == '"':
                state = "D_QUOTE"
                out.append(c)
                i += 1
            elif c == "`":
                state = "B_QUOTE"
                out.append(c)
                i += 1
            elif c == "/":
                if i + 1 < n and text[i + 1] == "/":
                    state = "LINE_COMMENT"
                    out.append("  ")
                    i += 2
                elif i + 1 < n and text[i + 1] == "*":
                    state = "BLOCK_COMMENT"
                    out.append("  ")
                    i += 2
                else:
                    out.append(c)
                    i += 1
            else:
                out.append(c)
                i += 1
        elif state == "LINE_COMMENT":
            if c == "\n":
                out.append("\n")
                state = "NORMAL"
            else:
                out.append(" ")
            i += 1
        elif state == "BLOCK_COMMENT":
            if c == "*" and i + 1 < n and text[i + 1] == "/":
                out.append("  ")
                i += 2
                state = "NORMAL"
            elif c == "\n":
                out.append("\n")
                i += 1
            else:
                out.append(" ")
                i += 1
        elif state == "S_QUOTE":
            if c == "\\":
                out.append(c)
                if i + 1 < n:
                    out.append(text[i + 1])
                    i += 2
                else:
                    i += 1
            elif c == "'":
                out.append(c)
                state = "NORMAL"
                i += 1
            else:
                out.append(c)
                i += 1
        elif state == "D_QUOTE":
            if c == "\\":
                out.append(c)
                if i + 1 < n:
                    out.append(text[i + 1])
                    i += 2
                else:
                    i += 1
            elif c == '"':
                out.append(c)
                state = "NORMAL"
                i += 1
            else:
                out.append(c)
                i += 1
        elif state == "B_QUOTE":
            if c == "\\":
                out.append(c)
                if i + 1 < n:
                    out.append(text[i + 1])
                    i += 2
                else:
                    i += 1
            elif c == "`":
                out.append(c)
                state = "NORMAL"
                i += 1
            else:
                out.append(c)
                i += 1

    return "".join(out)


# ---------------------------------------------------------------------------
# Specialized signal matchers: process_exec and credential_file_read
# ---------------------------------------------------------------------------

_EXEC_METHODS = {
    "exec",
    "execSync",
    "execFile",
    "execFileSync",
    "spawn",
    "spawnSync",
    "fork",
}

_SPAWN_SYNC_BINDING_RE = re.compile(
    r"""process\.binding\s*\(\s*['"]spawn_sync['"]\s*\)"""
)

_DIRECT_EXEC_RE = re.compile(
    r"""require\s*\(\s*['"](?:node:)?child_process['"]\s*\)\s*(?:\.\s*|\[\s*['"])(exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)(?:['"]\s*\]|\b)\s*\("""
)

_CP_REQUIRE_NS_RE = re.compile(
    r"""(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(?:await\s+)?require\s*\(\s*['"](?:node:)?child_process['"]\s*\)"""
)

_CP_IMPORT_NS_RE = re.compile(
    r"""import\s+(?:\*\s*as\s+)?([a-zA-Z_$][a-zA-Z0-9_$]*)\s+from\s*['"](?:node:)?child_process['"]"""
)

_CP_REQUIRE_DESTRUCT_RE = re.compile(
    r"""(?:const|let|var)\s*\{\s*([^}]+)\s*\}\s*=\s*(?:await\s+)?require\s*\(\s*['"](?:node:)?child_process['"]\s*\)"""
)

_CP_IMPORT_DESTRUCT_RE = re.compile(
    r"""import\s*\{\s*([^}]+)\s*\}\s*from\s*['"](?:node:)?child_process['"]"""
)

_CP_DIRECT_METHOD_ASSIGN_RE = re.compile(
    r"""(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(?:await\s+)?require\s*\(\s*['"](?:node:)?child_process['"]\s*\)\s*(?:\.\s*|\[\s*['"])(exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)(?:['"]\s*\]|\b)"""
)


def _parse_destructure(destruct_str: str, fn_vars: dict[str, str]) -> None:
    parts = destruct_str.split(",")
    for p in parts:
        p = p.strip()
        if not p:
            continue
        m = re.split(r"\s+(?:as|:)\s+", p)
        orig = m[0].strip()
        alias = m[-1].strip()
        if orig in _EXEC_METHODS:
            fn_vars[alias] = orig


def find_process_exec_matches(text: str) -> list[tuple[int, str, str]]:
    """Scan JS text for process_exec calls.

    Returns list of (line_no, matched_text, normalized_capability).
    Never matches bare .exec( from RegExp.
    """
    matches: list[tuple[int, str, str]] = []
    lines = text.splitlines()

    # 1. Direct process.binding('spawn_sync')
    for line_no, line in enumerate(lines, 1):
        m = _SPAWN_SYNC_BINDING_RE.search(line)
        if m:
            matches.append((line_no, m.group(0), "process.binding('spawn_sync')"))

    # 2. Direct chained calls: require('child_process').execSync(...)
    for line_no, line in enumerate(lines, 1):
        for m in _DIRECT_EXEC_RE.finditer(line):
            method = m.group(1)
            matches.append((line_no, m.group(0), f"child_process.{method}"))

    # 3. Find namespaces and destructured identifiers
    ns_vars: set[str] = set()
    fn_vars: dict[str, str] = {}

    for line in lines:
        for m in _CP_REQUIRE_NS_RE.finditer(line):
            ns_vars.add(m.group(1))
        for m in _CP_IMPORT_NS_RE.finditer(line):
            ns_vars.add(m.group(1))
        for m in _CP_DIRECT_METHOD_ASSIGN_RE.finditer(line):
            fn_vars[m.group(1)] = m.group(2)
        for m in _CP_REQUIRE_DESTRUCT_RE.finditer(line):
            _parse_destructure(m.group(1), fn_vars)
        for m in _CP_IMPORT_DESTRUCT_RE.finditer(line):
            _parse_destructure(m.group(1), fn_vars)

    # 4. Check for calls using namespace vars: cp.exec(...)
    if ns_vars:
        ns_pattern = "|".join(re.escape(v) for v in ns_vars)
        methods_pattern = "|".join(_EXEC_METHODS)
        call_re = re.compile(
            rf"""\b({ns_pattern})\s*(?:\.\s*|\[\s*['"])({methods_pattern})(?:['"]\s*\]|\b)\s*\("""
        )
        for line_no, line in enumerate(lines, 1):
            for m in call_re.finditer(line):
                method = m.group(2)
                matches.append((line_no, m.group(0), f"child_process.{method}"))

    # 5. Check for calls using destructured/assigned functions: execSync(...)
    if fn_vars:
        for var_name, canonical_method in fn_vars.items():
            call_re = re.compile(rf"""(?<![\.\?])\b{re.escape(var_name)}\s*\(""")
            for line_no, line in enumerate(lines, 1):
                if "require" in line and "child_process" in line:
                    continue
                if "import" in line and "child_process" in line:
                    continue
                for m in call_re.finditer(line):
                    matches.append((line_no, m.group(0), f"child_process.{canonical_method}"))

    return matches


_FS_READ_RE = re.compile(
    r"""(?x)
    (?<![\.\?])\b(?:fs(?:\.promises)?|fsPromises|fsp)?\s*\.?\s*
    (readFile|readFileSync|createReadStream|open|openSync)\s*\(
    """
)

_CREDENTIAL_TARGETS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"""['"`.+/\\]\.npmrc['"`]?""", re.IGNORECASE), ".npmrc"),
    (re.compile(r"""['"`.+/\\]\.netrc['"`]?""", re.IGNORECASE), ".netrc"),
    (re.compile(r"""['"`.+/\\]\.ssh(?:[/\\]|['"`])""", re.IGNORECASE), ".ssh/"),
    (re.compile(r"""\b(?:id_rsa|id_ed25519|id_ecdsa)\b""", re.IGNORECASE), "id_rsa"),
    (
        re.compile(r"""['"`.+/\\]\.aws[/\\](?:credentials|config)?['"`]?""", re.IGNORECASE),
        ".aws/credentials",
    ),
    (re.compile(r"""['"`.+/\\]\.git-credentials['"`]?""", re.IGNORECASE), ".git-credentials"),
    (re.compile(r"""['"`.+/\\]\.gitconfig['"`]?""", re.IGNORECASE), ".gitconfig"),
    (
        re.compile(r"""['"`.+/\\]\.docker[/\\]config\.json['"`]?""", re.IGNORECASE),
        ".docker/config.json",
    ),
    (re.compile(r"""['"`.+/\\]\.config[/\\]gcloud['"`]?""", re.IGNORECASE), ".config/gcloud"),
    (
        re.compile(r"""(?:login\.keychain|keychain-db|\bLibrary[/\\]Keychains)""", re.IGNORECASE),
        "keychain",
    ),
    (
        re.compile(r"""(?:User\s+Data|Default)[/\\](?:Login\s+Data|Cookies)""", re.IGNORECASE),
        "browser_profile",
    ),
]


def find_credential_read_matches(text: str) -> list[tuple[int, str, str]]:
    """Scan JS text for filesystem read APIs referencing credential files.

    Returns list of (line_no, matched_text, normalized_capability).
    Never matches bare word 'credentials'.
    """
    matches: list[tuple[int, str, str]] = []
    lines = text.splitlines()

    for line_no, line in enumerate(lines, 1):
        m_api = _FS_READ_RE.search(line)
        if not m_api:
            continue

        # Look for credential target in current line OR within nearby window (previous 8 lines)
        start_win = max(0, line_no - 9)
        window_lines = lines[start_win:line_no]
        window_text = "\n".join(window_lines)

        for pat, norm_name in _CREDENTIAL_TARGETS:
            m_target = pat.search(window_text)
            if m_target:
                snippet = m_api.group(0)
                matches.append((line_no, snippet, f"fs_read:{norm_name}"))
                break

    return matches


def _extract_host(url_or_ip: str) -> str | None:
    """Extract a normalized lower-cased hostname or IP."""
    try:
        parsed = urllib.parse.urlparse(url_or_ip)
        if parsed.hostname:
            return parsed.hostname.lower()
    except (ValueError, AttributeError):
        pass
    m = re.search(r"https?://([^/:\s'\">]+)", url_or_ip, re.IGNORECASE)
    if m:
        return m.group(1).lower()
    m_ip = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", url_or_ip)
    if m_ip:
        return m_ip.group(0)
    return None


def _is_comment_line(line: str) -> bool:
    """Return True if the line starts with a comment delimiter."""
    stripped = line.strip()
    return (
        stripped.startswith("//")
        or stripped.startswith("/*")
        or stripped.startswith("*")
        or stripped.startswith("#")
        or stripped.startswith("<!--")
    )


def _is_in_comment(line: str, match_start: int, in_block_comment: bool) -> bool:
    """Return True if match_start in line is inside a comment."""
    if in_block_comment:
        return True
    if _is_comment_line(line):
        return True
    pos = 0
    while True:
        idx = line.find("//", pos)
        if idx == -1:
            break
        if idx > 0 and line[idx - 1] == ":":
            pos = idx + 2
            continue
        if match_start >= idx:
            return True
        pos = idx + 2
    return False


def _detect_license_header_lines(lines: list[str], max_lines: int = 50) -> set[int]:
    """Return line indices (1-based) that form a top-of-file license/comment header."""
    header_lines: set[int] = set()
    found_license_kw = False
    limit = min(len(lines), max_lines)

    for idx in range(limit):
        line = lines[idx]
        stripped = line.strip()
        if not stripped:
            continue
        if _is_comment_line(stripped) or stripped.startswith('"') or stripped.startswith("'"):
            line_lower = stripped.lower()
            if any(kw in line_lower for kw in _LICENSE_KEYWORDS):
                found_license_kw = True
            header_lines.add(idx + 1)
        else:
            # Code line encountered; stop header search
            break

    return header_lines if found_license_kw else set()


def _normalize_match(signal_id: str, match_text: str) -> str:
    """Normalize matched API text to a canonical capability string."""
    if signal_id == "hardcoded_url":
        host = _extract_host(match_text)
        return host or match_text.strip().lower()
    if signal_id == "hardcoded_ip":
        return match_text.strip()
    if signal_id == "process_exec":
        return match_text.strip()
    if signal_id == "network_access":
        norm = re.sub(r"\s+", "", match_text).replace('"', "'")
        return norm
    if signal_id == "dynamic_code":
        return re.sub(r"\s+", " ", match_text.strip())
    if signal_id in ("credential_file_read", "ci_write", "shell_profile_write", "git_hook_write"):
        return match_text.strip("'\"`.+ ")
    if signal_id == "registry_token":
        return match_text.strip()
    return match_text.strip()


# ---------------------------------------------------------------------------
# Release-wide Capability Extraction
# ---------------------------------------------------------------------------


@dataclass
class ReleaseCapabilities:
    """Set of capabilities and knowledge observed across an entire release."""

    normalized_keys: set[tuple[str, str]] = field(default_factory=set)
    hosts: set[str] = field(default_factory=set)
    blob_hashes: set[str] = field(default_factory=set)
    has_bulk_env_enum: bool = False
    existing_minified_paths: set[str] = field(default_factory=set)


def _scan_release_capabilities(
    release: ExtractionResult | ReleaseContents,
) -> ReleaseCapabilities:
    """Scan all files across a release and compute known capabilities, hosts, and blobs."""
    if isinstance(release, ExtractionResult):
        release = release.to_release_contents()

    caps = ReleaseCapabilities()

    for rel_path, data in release.files.items():
        cat = classify(data, rel_path)
        if cat not in {
            FileCategory.SCRIPT,
            FileCategory.OTHER,
            FileCategory.DOTFILE,
            FileCategory.MINIFIED,
        }:
            continue

        is_min = is_minified_or_bundled(data, rel_path, cat)
        if is_min:
            caps.existing_minified_paths.add(rel_path)

        is_exempt = is_exempt_path(rel_path, cat)
        raw_text = release.read_text(rel_path)
        if not raw_text:
            continue
        clean_text = strip_js_comments(raw_text) if _is_js_or_ts_file(rel_path) else raw_text

        # Specialized signals: process_exec and credential_file_read
        for _, _, norm in find_process_exec_matches(clean_text):
            caps.normalized_keys.add(("process_exec", norm))
        for _, _, norm in find_credential_read_matches(clean_text):
            caps.normalized_keys.add(("credential_file_read", norm))

        lines = clean_text.splitlines()
        env_lines: set[str] = set()

        for line in lines:
            stripped = line.strip()

            # Blobs & entropy (only in production non-minified source)
            if not is_exempt and not is_min:
                for tok in _extract_string_tokens(line):
                    if (
                        len(tok) >= _ENTROPY_MIN_LEN
                        and _shannon_entropy(tok) >= _ENTROPY_THRESHOLD
                    ):
                        h = hashlib.sha256(tok.encode("utf-8")).hexdigest()
                        caps.blob_hashes.add(h)
                if len(line) > _LONG_LINE_THRESHOLD:
                    h = hashlib.sha256(line.encode("utf-8")).hexdigest()
                    caps.blob_hashes.add(h)

            # Env access
            if re.search(r"process\.env\b", line):
                env_lines.add(stripped[:80])

            # Signals
            for signal in _SIGNALS:
                for m in signal.pattern.finditer(line):
                    match_text = m.group(0)
                    if signal.id == "hardcoded_url":
                        host = _extract_host(match_text)
                        if host:
                            caps.hosts.add(host)
                            caps.normalized_keys.add(("hardcoded_url", host))
                    elif signal.id == "hardcoded_ip":
                        ip = match_text.strip()
                        caps.hosts.add(ip)
                        caps.normalized_keys.add(("hardcoded_ip", ip))
                    elif signal.id == "long_encoded_blob":
                        if not is_exempt:
                            h = hashlib.sha256(match_text.encode("utf-8")).hexdigest()
                            caps.blob_hashes.add(h)
                            caps.normalized_keys.add(("long_encoded_blob", h))
                    else:
                        norm = _normalize_match(signal.id, match_text)
                        caps.normalized_keys.add((signal.id, norm))

        if len(env_lines) >= _ENV_ENUM_MIN_ACCESSES:
            caps.has_bulk_env_enum = True
            caps.normalized_keys.add(("env_enumeration", "process.env"))

    return caps


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_new_content(
    old: ExtractionResult | ReleaseContents,
    new: ExtractionResult | ReleaseContents,
    install_script_targets: set[str],
) -> list[Evidence]:
    """Scan files for newly introduced suspicious patterns.

    Computes package-wide capability differences:
    - Normalizes matches by (signal_type, matched_API/host) across the WHOLE package.
    - Flags only matches whose normalized capability is new (absent from old release).
    - Never line-diffs minified or bundled files.
    - Suppresses entropy and encoded blobs in tests/fixtures/data/locales/source-maps
      and for pre-existing blobs.
    - Suppresses URLs/IPs whose host exists in old package or appears in comments/licenses.
    """
    if isinstance(old, ExtractionResult):
        old = old.to_release_contents()
    if isinstance(new, ExtractionResult):
        new = new.to_release_contents()

    old_caps = _scan_release_capabilities(old)
    old_file_paths = set(old.files.keys())

    evidence: list[Evidence] = []

    for rel_path, data in new.files.items():
        cat = classify(data, rel_path)
        if cat not in {
            FileCategory.SCRIPT,
            FileCategory.OTHER,
            FileCategory.DOTFILE,
            FileCategory.MINIFIED,
        }:
            continue

        is_min = is_minified_or_bundled(data, rel_path, cat)
        is_exempt = is_exempt_path(rel_path, cat)
        is_install_target = rel_path in install_script_targets
        was_previously_minified = rel_path in old_caps.existing_minified_paths

        raw_text = new.read_text(rel_path)
        if not raw_text:
            continue
        clean_text = strip_js_comments(raw_text) if _is_js_or_ts_file(rel_path) else raw_text

        seen_signals: set[str] = set()

        # Specialized signals: process_exec and credential_file_read
        for _, snippet, norm in find_process_exec_matches(clean_text):
            if ("process_exec", norm) not in old_caps.normalized_keys:
                if "process_exec" not in seen_signals:
                    seen_signals.add("process_exec")
                    sev = _escalate_if_install_target(Severity.MEDIUM, is_install_target)
                    evidence.append(
                        Evidence(
                            id="process_exec",
                            severity=sev,
                            file=rel_path,
                            explanation=_PROCESS_EXEC_METADATA.explanation_template.format(match=snippet),
                            legitimate_use_note=_PROCESS_EXEC_METADATA.legitimate_use_note,
                        )
                    )

        for _, snippet, norm in find_credential_read_matches(clean_text):
            if ("credential_file_read", norm) not in old_caps.normalized_keys:
                if "credential_file_read" not in seen_signals:
                    seen_signals.add("credential_file_read")
                    sev = _escalate_if_install_target(Severity.HIGH, is_install_target)
                    evidence.append(
                        Evidence(
                            id="credential_file_read",
                            severity=sev,
                            file=rel_path,
                            explanation=_CREDENTIAL_READ_METADATA.explanation_template.format(match=snippet),
                            legitimate_use_note=_CREDENTIAL_READ_METADATA.legitimate_use_note,
                        )
                    )

        # Never line-diff minified or bundled files!
        if is_min:
            inspect_lines = clean_text.splitlines()
        elif rel_path in old_file_paths:
            old_raw = old.read_text(rel_path)
            old_clean = strip_js_comments(old_raw) if _is_js_or_ts_file(rel_path) else old_raw
            old_lines_set = set(old_clean.splitlines())
            inspect_lines = [ln for ln in clean_text.splitlines() if ln not in old_lines_set]
        else:
            inspect_lines = clean_text.splitlines()

        if not inspect_lines:
            continue

        license_header_lines = _detect_license_header_lines(inspect_lines)
        in_block_comment = False
        env_access_lines: set[str] = set()

        for line_no, line in enumerate(inspect_lines, 1):
            stripped = line.strip()

            # Track block comment state
            if "/*" in line:
                in_block_comment = True
            if "*/" in line:
                in_block_comment = False

            is_license = line_no in license_header_lines

            # Bulk env enumeration tracking
            if re.search(r"process\.env\b", line):
                env_access_lines.add(stripped[:80])

            # Entropy and long-line blobs:
            # Only when blob is new AND file is outside test/fixture/data/locale/source-map.
            # Never treat minified files from old release as long-line blobs.
            if not is_exempt and not was_previously_minified:
                # String entropy
                for tok in _extract_string_tokens(line):
                    if (
                        len(tok) >= _ENTROPY_MIN_LEN
                        and _shannon_entropy(tok) >= _ENTROPY_THRESHOLD
                    ):
                        h = hashlib.sha256(tok.encode("utf-8")).hexdigest()
                        if h not in old_caps.blob_hashes:
                            if "high_entropy_string" not in seen_signals:
                                seen_signals.add("high_entropy_string")
                                sev = _escalate_if_install_target(
                                    Severity.MEDIUM, is_install_target
                                )
                                evidence.append(
                                    Evidence(
                                        id="high_entropy_string",
                                        severity=sev,
                                        file=rel_path,
                                        explanation=(
                                            "File contains a new high-entropy string "
                                            f"(Shannon entropy >= 4.5 bits/char): {tok[:60]!r}."
                                        ),
                                        legitimate_use_note=(
                                            "Cryptographic constants, pre-computed lookup "
                                            "tables, and compression codecs contain naturally "
                                            "high-entropy strings."
                                        ),
                                    )
                                )
                                break

                # Long line blob (in non-minified files or newly added unclassified files)
                if len(line) > _LONG_LINE_THRESHOLD:
                    h = hashlib.sha256(line.encode("utf-8")).hexdigest()
                    if h not in old_caps.blob_hashes:
                        if "long_encoded_blob" not in seen_signals:
                            seen_signals.add("long_encoded_blob")
                            sev = _escalate_if_install_target(Severity.MEDIUM, is_install_target)
                            evidence.append(
                                Evidence(
                                    id="long_encoded_blob",
                                    severity=sev,
                                    file=rel_path,
                                    explanation=(
                                        f"File contains a new long line ({len(line)} chars). "
                                        "Extremely long single lines are a common obfuscation "
                                        "technique."
                                    ),
                                    legitimate_use_note=(
                                        "Minified JavaScript, base64-encoded assets, and "
                                        "auto-generated tables often produce long lines."
                                    ),
                                )
                            )

            # Signal inspection
            for signal in _SIGNALS:
                if signal.id in seen_signals:
                    continue

                m = signal.pattern.search(line)
                if not m:
                    continue
                match_text = m.group(0)

                if signal.id == "hardcoded_url":
                    if _is_in_comment(line, m.start(), in_block_comment) or is_license:
                        continue
                    host = _extract_host(match_text)
                    if not host or host in old_caps.hosts:
                        continue
                    seen_signals.add("hardcoded_url")
                    sev = _escalate_if_install_target(signal.severity, is_install_target)
                    evidence.append(
                        Evidence(
                            id="hardcoded_url",
                            severity=sev,
                            file=rel_path,
                            explanation=signal.explanation_template.format(match=match_text),
                            legitimate_use_note=signal.legitimate_use_note,
                        )
                    )

                elif signal.id == "hardcoded_ip":
                    if _is_in_comment(line, m.start(), in_block_comment) or is_license:
                        continue
                    ip = match_text.strip()
                    if ip in old_caps.hosts:
                        continue
                    seen_signals.add("hardcoded_ip")
                    sev = _escalate_if_install_target(signal.severity, is_install_target)
                    evidence.append(
                        Evidence(
                            id="hardcoded_ip",
                            severity=sev,
                            file=rel_path,
                            explanation=signal.explanation_template.format(match=match_text),
                            legitimate_use_note=signal.legitimate_use_note,
                        )
                    )

                elif signal.id == "long_encoded_blob":
                    if is_exempt:
                        continue
                    h = hashlib.sha256(match_text.encode("utf-8")).hexdigest()
                    if h in old_caps.blob_hashes:
                        continue
                    seen_signals.add("long_encoded_blob")
                    sev = _escalate_if_install_target(signal.severity, is_install_target)
                    evidence.append(
                        Evidence(
                            id="long_encoded_blob",
                            severity=sev,
                            file=rel_path,
                            explanation=signal.explanation_template.format(match=match_text),
                            legitimate_use_note=signal.legitimate_use_note,
                        )
                    )

                else:
                    norm = _normalize_match(signal.id, match_text)
                    if (signal.id, norm) in old_caps.normalized_keys:
                        continue
                    seen_signals.add(signal.id)
                    sev = _escalate_if_install_target(signal.severity, is_install_target)
                    evidence.append(
                        Evidence(
                            id=signal.id,
                            severity=sev,
                            file=rel_path,
                            explanation=signal.explanation_template.format(match=match_text),
                            legitimate_use_note=signal.legitimate_use_note,
                        )
                    )

        # Bulk environment enumeration
        if len(env_access_lines) >= _ENV_ENUM_MIN_ACCESSES:
            if not old_caps.has_bulk_env_enum and "env_enumeration" not in seen_signals:
                seen_signals.add("env_enumeration")
                # Escalated to HIGH: bulk reading env vars is credential harvesting indicator
                sev = _escalate_if_install_target(Severity.HIGH, is_install_target)
                evidence.append(
                    Evidence(
                        id="env_enumeration",
                        severity=sev,
                        file=rel_path,
                        explanation=(
                            f"File accesses process.env in {len(env_access_lines)} "
                            "distinct new lines. Bulk reading of environment variables is "
                            "sometimes used to collect credentials for exfiltration."
                        ),
                        legitimate_use_note=(
                            "Configuration-heavy packages (build tools, frameworks) commonly "
                            "read multiple env vars. Review whether any sensitive vars "
                            "(tokens, passwords, private keys) are read."
                        ),
                    )
                )

    return evidence


# ---------------------------------------------------------------------------
# Internal utilities
# ---------------------------------------------------------------------------


def _read_lines_safe(path: Path) -> list[str]:
    """Read text lines from *path*, capping at _MAX_SCAN_SIZE."""
    try:
        if path.stat().st_size > _MAX_SCAN_SIZE:
            logger.debug("Skipping content scan for large file: %s", path)
            return []
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        logger.debug("Cannot read %s for content scan: %s", path, exc)
        return []


def _get_added_lines(old_path: Path, new_path: Path) -> list[str]:
    """Return lines present in *new_path* but not in *old_path*."""
    old_lines = set(_read_lines_safe(old_path))
    new_lines = _read_lines_safe(new_path)
    return [ln for ln in new_lines if ln not in old_lines]


def _escalate_if_install_target(sev: Severity, is_install_target: bool) -> Severity:
    """Return severity escalated by one level if this file is an install-script target."""
    if not is_install_target:
        return sev
    _order: list[Severity] = [
        Severity.INFO,
        Severity.LOW,
        Severity.MEDIUM,
        Severity.HIGH,
        Severity.CRITICAL,
    ]
    idx = _order.index(sev)
    return _order[min(idx + 1, len(_order) - 1)]


def _shannon_entropy(s: str) -> float:
    """Compute the Shannon entropy of a string in bits per character."""
    if not s:
        return 0.0
    freq: dict[str, int] = defaultdict(int)
    for ch in s:
        freq[ch] += 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


_STRING_RE = re.compile(
    r"""'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)"|`((?:[^`\\]|\\.)*)`"""
)


def _extract_string_tokens(line: str) -> list[str]:
    """Extract string literal content from a single source line."""
    tokens: list[str] = []
    for m in _STRING_RE.finditer(line):
        tok = m.group(1) or m.group(2) or m.group(3)
        if tok and len(tok) >= _ENTROPY_MIN_LEN:
            tokens.append(tok)
    return tokens
