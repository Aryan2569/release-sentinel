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
) -> str:
    """Sanitize untrusted text from packages before embedding into Markdown or reports."""
    if not text:
        return ""

    s = text

    # Strip or defang the comment marker so untrusted fields cannot fake it
    s = s.replace(COMMENT_MARKER, "&lt;!-- release-sentinel-pr-comment --&gt;")

    # Defang HTML comment openers
    s = s.replace("<!--", "&lt;!--")

    # Escape HTML tags
    if escape_html:
        s = s.replace("<", "&lt;").replace(">", "&gt;")

    # Neutralize @mentions and #issue references using zero-width spaces
    s = _MENTION_RE.sub(lambda m: f"@\u200b{m.group(1)}", s)
    s = _ISSUE_RE.sub(lambda m: f"#\u200b{m.group(1)}", s)

    # Collapse newlines and tabs into single spaces for table/summary safety
    if collapse_newlines:
        s = re.sub(r"[\r\n\t]+", " ", s)
        # Also replace raw pipe characters to prevent breaking Markdown tables
        s = s.replace("|", "/")
        s = re.sub(r" +", " ", s).strip()

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

    sanitized = sanitize_untrusted_text(text, max_length=max_length, collapse_newlines=True)
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

    If comment exceeds max_chars, it is cleanly truncated with TRUNCATION_NOTE.
    """
    if len(comment) <= max_chars:
        return comment

    cutoff = max_chars - len(TRUNCATION_NOTE)
    if cutoff < 0:
        return TRUNCATION_NOTE[:max_chars]

    return comment[:cutoff] + TRUNCATION_NOTE
