"""Sanitization and injection hardening for PR comments, summaries, and CLI output.

Ensures untrusted values from npm packages (names, versions, paths, descriptions,
scripts, and evidence explanations) cannot:
1. Break Markdown table formatting or breakout of code fences
2. Ping GitHub users via @mentions or link issues via #123
3. Inject HTML / scripts or fake PR comment markers
4. Inject GitHub Actions workflow commands (::set-output, ::error, etc.)
5. Exceed GitHub PR comment size limits (65,536 chars)
"""

from __future__ import annotations

import re

# GitHub PR comments hard limit is 65,536 chars.
# We cap total comment size at 60 KB (61,440 chars) to stay safely under.
MAX_COMMENT_CHARS: int = 61_440
MAX_FIELD_CHARS: int = 300
TRUNCATION_NOTE: str = "\n\n... [Report truncated to stay within GitHub PR comment limits]"
COMMENT_MARKER: str = "<!-- release-sentinel-pr-comment -->"

_MENTION_RE = re.compile(r"@([a-zA-Z0-9_-]+)")
_ISSUE_RE = re.compile(r"#([0-9]+)")
_CONSECUTIVE_BACKTICKS_RE = re.compile(r"`+")


def defang_urls(text: str) -> str:
    """Defang URLs and hostnames in untrusted text so they cannot be parsed as links.

    Converts:
    - https:// -> hxxps://, http:// -> hxxp://, ftp:// -> fxp://
    - Dots in hostnames/domains to [.] (e.g. evil.example -> evil[.]example)
    - mailto: and bare email domains to [.]
    - www. domains to www[.]
    """
    if not text:
        return text

    # Defang scheme URLs: https://, http://, ftp://
    def _replace_url(match: re.Match[str]) -> str:
        proto = match.group(1)
        rest = match.group(2)
        lower_proto = proto.lower()
        if lower_proto == "https":
            new_proto = "hxxps"
        elif lower_proto == "http":
            new_proto = "hxxp"
        elif lower_proto == "ftp":
            new_proto = "fxp"
        else:
            new_proto = proto

        # Split authority from path/query
        parts = rest.split("/", 1)
        host = parts[0].replace(".", "[.]")
        if len(parts) > 1:
            return f"{new_proto}://{host}/{parts[1]}"
        return f"{new_proto}://{host}"

    text = re.sub(
        r"\b(https?|ftp)://([^\s)\]>\"'`]+)",
        _replace_url,
        text,
        flags=re.IGNORECASE,
    )

    # Defang mailto:
    def _replace_mailto(match: re.Match[str]) -> str:
        target = match.group(1).replace(".", "[.]")
        return f"mailto\u200b:{target}"

    text = re.sub(
        r"\bmailto:([^\s)\]>\"'`]+)",
        _replace_mailto,
        text,
        flags=re.IGNORECASE,
    )

    # Defang www.
    def _replace_www(match: re.Match[str]) -> str:
        return match.group(0).replace(".", "[.]")

    text = re.sub(r"\bwww\.[a-zA-Z0-9_.-]+\b", _replace_www, text, flags=re.IGNORECASE)

    # Defang bare emails: user@domain.tld
    def _replace_email(match: re.Match[str]) -> str:
        user = match.group(1)
        domain = match.group(2).replace(".", "[.]")
        return f"{user}@{domain}"

    text = re.sub(
        r"\b([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]*[a-zA-Z]{2,})\b",
        _replace_email,
        text,
    )

    return text


def defang_gha_commands(text: str) -> str:
    """Defang lines starting with '::' to prevent GitHub Actions workflow command injection.

    GitHub Actions interprets lines starting with '::' as commands (e.g. ::error::,
    ::set-output::). Prepending a zero-width space prevents GHA from executing them.
    """
    if not text:
        return text
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    for line in lines:
        if line.startswith("::"):
            out.append("\u200b" + line)
        else:
            out.append(line)
    return "".join(out)


def sanitize_untrusted_text(
    text: str,
    max_length: int = MAX_FIELD_CHARS,
    collapse_newlines: bool = True,
    escape_html: bool = True,
    escape_markdown: bool = True,
) -> str:
    """Sanitize untrusted text from packages before embedding into Markdown or reports.

    Escapes Markdown metacharacters (\\ ` * _ [ ] ( ) ! # > | ~) and HTML (< > &),
    defangs URLs (hxxps://...), neutralizes @mentions and #issues, and collapses
    newlines to prevent layout breakout.
    """
    if not text:
        return ""

    s = text

    # Defang URLs before character escaping
    s = defang_urls(s)

    # Defang GHA commands
    s = defang_gha_commands(s)

    # HTML escaping (<, >, &)
    if escape_html:
        s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    else:
        # Defang comment marker and HTML comments even if HTML escaping is off
        s = s.replace(COMMENT_MARKER, "&lt;!-- release-sentinel-pr-comment --&gt;")
        s = s.replace("<!--", "&lt;!--")

    # Neutralize @mentions and #issue references using zero-width spaces
    s = _MENTION_RE.sub(lambda m: f"@\u200b{m.group(1)}", s)
    s = _ISSUE_RE.sub(lambda m: f"#\u200b{m.group(1)}", s)

    # Collapse newlines and tabs into single spaces for table/summary safety
    if collapse_newlines:
        s = re.sub(r"[\r\n\t]+", " ", s)
        s = s.replace("|", "/")
        s = re.sub(r" +", " ", s).strip()

    # Markdown metacharacters escaping
    if escape_markdown:
        # Backslash first so subsequent backslashes are not re-escaped
        s = s.replace("\\", "\\\\")
        for char in ("`", "*", "_", "[", "]", "(", ")", "!", "#", "~"):
            s = s.replace(char, "\\" + char)
        # Defang bullet lists and horizontal rules / setext underlines
        s = re.sub(r"(^|\n)(\s*)-(\s+)", r"\1\2\\-\3", s)
        s = re.sub(r"-{3,}", lambda m: "\\-" * len(m.group(0)), s)
        # Escape ordered list markers like '1. item'
        s = re.sub(r"(^|\n)(\s*\d+)\.(\s+)", r"\1\2\\.\3", s)
        if not collapse_newlines:
            s = s.replace("|", "\\|")
        if not escape_html:
            s = s.replace(">", "\\>")
        # Preserve defanged HTML comments and neutralized tokens
        s = s.replace("&lt;\\!--", "&lt;!--")
        s = re.sub(r"(@\u200b[a-zA-Z0-9]+)\\+(_)", r"\1\2", s)
        s = re.sub(r"\\+(#\u200b[0-9]+)", r"\1", s)
    elif collapse_newlines:
        # If markdown escaping is disabled (e.g. for code spans), still protect pipes
        s = s.replace("|", "\\|")

    # Cap length
    if len(s) > max_length:
        s = s[: max_length - 3] + "..."

    return s


def render_code_span(text: str, max_length: int = MAX_FIELD_CHARS) -> str:
    """Render untrusted text inside a Markdown inline code span safely.

    Calculates the longest backtick sequence and wraps with a delimiter longer
    than any internal backtick run, ensuring the untrusted text cannot break out.
    """
    if not text:
        return "`—`"

    sanitized = sanitize_untrusted_text(
        text, max_length=max_length, collapse_newlines=True, escape_markdown=False
    )
    if not sanitized:
        return "`—`"

    # Find longest sequence of backticks in sanitized
    runs = _CONSECUTIVE_BACKTICKS_RE.findall(sanitized)
    max_run = max((len(r) for r in runs), default=0)

    if max_run == 0:
        return f"`{sanitized}`"

    # Need a delimiter strictly longer than the longest backtick run inside
    fence = "`" * (max_run + 1)
    # CommonMark requires a space if the code begins or ends with a backtick
    if sanitized.startswith("`") or sanitized.endswith("`"):
        return f"{fence} {sanitized} {fence}"
    return f"{fence}{sanitized}{fence}"


def render_fenced_code_block(text: str, lang: str = "") -> str:
    """Render untrusted multiline text inside a Markdown fenced code block safely.

    Uses a fence strictly longer than any backtick run inside.
    """
    if not text:
        return "```\n```"

    runs = _CONSECUTIVE_BACKTICKS_RE.findall(text)
    max_run = max((len(r) for r in runs), default=0)
    fence = "`" * max(3, max_run + 1)
    return f"{fence}{lang}\n{text}\n{fence}"


def cap_comment_size(comment: str, max_chars: int = MAX_COMMENT_CHARS) -> str:
    """Cap a full Markdown comment string so it never exceeds GitHub's limit.

    If comment exceeds max_chars:
    1. Cuts cleanly at a line boundary.
    2. Detects open <details> tags and unclosed code fences (```) and closes them cleanly.
    3. Appends TRUNCATION_NOTE.
    Guarantees len(result) <= max_chars.
    """
    if len(comment) <= max_chars:
        return comment

    cutoff = max_chars - len(TRUNCATION_NOTE)
    if cutoff < 0:
        return TRUNCATION_NOTE[:max_chars]

    # If there are no newlines at all, fall back to simple slice + note
    if "\n" not in comment[:cutoff]:
        return comment[:cutoff] + TRUNCATION_NOTE

    # Reserve budget for closing tags (``` + multiple </details>) and TRUNCATION_NOTE
    reserve_budget = len(TRUNCATION_NOTE) + 200
    preliminary_cutoff = max(0, max_chars - reserve_budget)

    prefix = comment[:preliminary_cutoff]
    last_nl = prefix.rfind("\n")
    if last_nl > 0:
        truncated = prefix[:last_nl]
    else:
        truncated = prefix

    closers: list[str] = []
    # Check unclosed code fences: lines starting with ```
    fence_count = len(re.findall(r"^```", truncated, re.MULTILINE))
    if fence_count % 2 != 0:
        closers.append("```")

    # Check unclosed <details> tags
    open_details = len(re.findall(r"(?i)<details\b", truncated))
    closed_details = len(re.findall(r"(?i)</details>", truncated))
    unclosed = open_details - closed_details
    if unclosed > 0:
        for _ in range(unclosed):
            closers.append("</details>")

    closing_text = ""
    if closers:
        closing_text = "\n" + "\n".join(closers)

    result = truncated + closing_text + TRUNCATION_NOTE
    if len(result) > max_chars:
        avail = max_chars - len(TRUNCATION_NOTE)
        result = comment[:max(0, avail)] + TRUNCATION_NOTE

    return result
