"""Tests for comment, summary, and CLI output injection hardening."""

from __future__ import annotations

import io
from datetime import UTC, datetime
from unittest.mock import patch

from release_sentinel.cli import (
    _render_markdown,
    _safe_print,
    format_lockfile_markdown,
)
from release_sentinel.lockfile import LockfileDiffReport, find_matching_pr_comment_id
from release_sentinel.models import Decision, Evidence, ReleaseRef, Report, Severity
from release_sentinel.sanitizer import (
    MAX_COMMENT_CHARS,
    TRUNCATION_NOTE,
    cap_comment_size,
    defang_gha_commands,
    render_code_span,
    sanitize_untrusted_text,
)


def _make_report(
    pkg_name: str,
    old_v: str,
    new_v: str,
    evidence: list[Evidence],
    decision: Decision = Decision.WARN,
) -> Report:
    return Report(
        old_release=ReleaseRef(
            name=pkg_name,
            version=old_v,
            published_at=datetime(2024, 1, 1, tzinfo=UTC),
        ),
        new_release=ReleaseRef(
            name=pkg_name,
            version=new_v,
            published_at=datetime(2024, 1, 2, tzinfo=UTC),
        ),
        decision=decision,
        evidence=evidence,
        limitations=["JavaScript/TypeScript source scanned with static heuristics."],
        as_of=datetime(2024, 6, 1, tzinfo=UTC),
        generated_at=datetime(2024, 6, 2, tzinfo=UTC),
    )


class TestUntrustedSanitization:
    def test_strip_mentions_and_issue_references(self):
        text = "Hello @octocat and pinging @user_123, see issue #456 and #1."
        sanitized = sanitize_untrusted_text(text)
        assert "@\u200boctocat" in sanitized
        assert "@\u200buser_123" in sanitized
        assert "#\u200b456" in sanitized
        assert "#\u200b1" in sanitized
        assert "@octocat" not in sanitized
        assert "#456" not in sanitized

    def test_escape_html_tags_and_comment_openers(self):
        hostile = (
            "<script>alert(1)</script> and <!-- hidden comment --> and <img src=x onerror=alert(1)>"
        )
        sanitized = sanitize_untrusted_text(hostile)
        assert "<script>" not in sanitized
        assert "&lt;script&gt;" in sanitized
        assert "<!--" not in sanitized
        assert "&lt;!--" in sanitized

    def test_defang_pr_comment_marker(self):
        marker = "Malicious text <!-- release-sentinel-pr-comment --> injected"
        sanitized = sanitize_untrusted_text(marker)
        assert "<!-- release-sentinel-pr-comment -->" not in sanitized
        assert "&lt;!-- release-sentinel-pr-comment --&gt;" in sanitized

    def test_collapse_newlines_and_table_pipes(self):
        table_breaker = "multi\n\nline\r\n\ttext | with | pipes"
        sanitized = sanitize_untrusted_text(table_breaker, collapse_newlines=True)
        assert "\n" not in sanitized
        assert "\r" not in sanitized
        assert "\t" not in sanitized
        assert "|" not in sanitized
        assert "/" in sanitized

    def test_length_cap_per_field(self):
        long_string = "a" * 1000
        sanitized = sanitize_untrusted_text(long_string, max_length=300)
        assert len(sanitized) == 300
        assert sanitized.endswith("...")


class TestCodeSpanRendering:
    def test_normal_text(self):
        assert render_code_span("lodash") == "`lodash`"

    def test_single_backtick(self):
        # A single backtick inside must be wrapped by 2 backticks
        rendered = render_code_span("`")
        assert rendered.startswith("``")
        assert rendered.endswith("``")
        assert " ` " in rendered

    def test_triple_backticks(self):
        rendered = render_code_span("```")
        assert rendered.startswith("````")
        assert rendered.endswith("````")

    def test_ten_consecutive_backticks(self):
        ten = "`" * 10
        rendered = render_code_span(ten)
        assert rendered.startswith("`" * 11)
        assert rendered.endswith("`" * 11)


class TestGhaCommandDefanging:
    def test_defang_gha_commands(self):
        text = "::error::fake workflow command\n::set-output name=token::secret\nnormal output"
        defanged = defang_gha_commands(text)
        lines = defanged.splitlines()
        for line in lines[:2]:
            assert not line.startswith("::")
            assert line.startswith("\u200b::")
        assert lines[2] == "normal output"

    def test_safe_print_defangs_stdout(self):
        f = io.StringIO()
        with patch("sys.stdout", f):
            _safe_print("::error title=hacked::bad command")
        output = f.getvalue()
        assert not output.startswith("::")
        assert output.startswith("\u200b::")


class TestCommentSizeCapping:
    def test_cap_comment_under_limit_unchanged(self):
        comment = "Normal comment under limit"
        assert cap_comment_size(comment, max_chars=100) == comment

    def test_cap_comment_over_limit_truncated(self):
        comment = "X" * 70_000
        capped = cap_comment_size(comment, max_chars=60_000)
        assert len(capped) == 60_000
        assert capped.endswith(TRUNCATION_NOTE)

    def test_render_markdown_with_1000_items(self):
        evs = [
            Evidence(
                id=f"ev_{i}",
                severity=Severity.HIGH,
                file=f"file_{i}.js",
                explanation=f"Very long explanation {i} " + "A" * 100,
                legitimate_use_note="Legitimate build step",
            )
            for i in range(1000)
        ]
        rep = _make_report("big-pkg", "1.0.0", "1.0.1", evs, Decision.BLOCK)
        md = _render_markdown(rep, evs)
        assert len(md) <= MAX_COMMENT_CHARS
        assert len(md) < 65_536
        assert TRUNCATION_NOTE in md

    def test_format_lockfile_markdown_with_1000_items(self):
        flagged = [
            {
                "package": f"@scope/evil_{i}",
                "old_version": "1.0.0",
                "new_version": "1.0.1",
                "decision": "BLOCK",
                "evidence": ["install_script_added", "eval_expression"],
                "evidence_details": [
                    {
                        "id": "install_script_added",
                        "severity": "HIGH",
                        "explanation": f"Hostile script {i} " + "B" * 100,
                        "legitimate_use_note": "Legit note " + "C" * 100,
                    }
                ],
            }
            for i in range(1000)
        ]
        lock_report = LockfileDiffReport(
            base_source="package-lock.json",
            head_source="package-lock.json",
            total_packages_scanned=1000,
            decision=Decision.BLOCK,
            package_results=flagged,
            limitations=["JavaScript/TypeScript source scanned with static heuristics."],
        )
        md = format_lockfile_markdown(lock_report)
        assert len(md) <= MAX_COMMENT_CHARS
        assert len(md) < 65_536
        assert TRUNCATION_NOTE in md


class TestHostileMarkdownFixtures:
    def test_hostile_package_name_and_tags(self):
        ev = [
            Evidence(
                id="install_script_added",
                severity=Severity.HIGH,
                file="path/to/\n| table_breaker |",
                explanation="Backtick ` test and <!-- release-sentinel-pr-comment --> injection",
                legitimate_use_note="Build process",
            )
        ]
        rep = _make_report("@octocat/malicious#123<script>alert(1)</script>", "1.0.0", "1.0.1", ev)
        md = _render_markdown(rep, ev)

        # Confirm HTML tag escaped
        assert "<script>" not in md
        assert "&lt;script&gt;" in md
        # Confirm @octocat and #123 neutralized
        assert "@octocat" not in md
        assert "@\u200boctocat" in md
        assert "#123" not in md
        assert "#\u200b123" in md
        # Confirm marker in explanation was neutralized
        # The report should have exactly 0 unescaped release-sentinel-pr-comment in evidence body
        assert "&lt;!-- release-sentinel-pr-comment --&gt;" in md

    def test_action_comment_author_matching(self):
        import json

        data = [
            {
                "id": 101,
                "user": {"login": "attacker"},
                "body": "Fake <!-- release-sentinel-pr-comment --> injected by attacker",
            },
            {
                "id": 202,
                "user": {"login": "github-actions[bot]"},
                "body": "Real <!-- release-sentinel-pr-comment --> from bot",
            },
        ]
        marker = "<!-- release-sentinel-pr-comment -->"
        # Real function with list of dicts
        assert find_matching_pr_comment_id(data, marker=marker) == "202"
        # Real function with JSON string input (like stdin in action.yml)
        assert find_matching_pr_comment_id(json.dumps(data), marker=marker) == "202"
        # Actor matching
        actor_data = [
            {
                "id": 303,
                "user": {"login": "ci-actor"},
                "body": "<!-- release-sentinel-pr-comment -->",
            }
        ]
        assert find_matching_pr_comment_id(actor_data, marker=marker, actor="ci-actor") == "303"
        assert find_matching_pr_comment_id(actor_data, marker=marker, actor="other-actor") is None

    def test_commonmark_hostile_fixtures_contain_no_injected_elements(self):
        from markdown_it import MarkdownIt

        md = MarkdownIt("commonmark").enable(["table", "linkify", "strikethrough"])
        md.options["linkify"] = True
        hostiles = [
            "![x](https://evil.example/p.png)",
            "[click](https://evil.example)",
            "https://evil.example/x",
            "<https://evil.example/x>",
            "\n# Fake heading\n| a | b |",
            "*bold*",
            "_italic_",
            "<script>alert(1)</script>",
            "@octocat",
            "#123",
            "<!-- release-sentinel-pr-comment -->",
            "::error::fake",
            "www.evil.example",
            "user@evil.example",
            "mailto:x@evil.example",
            "~~strike~~",
            "- [ ] task",
            "1. item",
            "> quote",
            "---",
            "A" * 1000,
        ]

        forbidden = [
            "<a",
            "<img",
            "<del",
            "<s",
            "<strike",
            "<input",
            "<table>",
            "<blockquote",
            "<ul",
            "<ol",
            "<hr",
        ]
        for level in range(1, 7):
            forbidden.append(f"<h{level}")

        for h in hostiles:
            sanitized = sanitize_untrusted_text(h)
            html = md.render(sanitized)
            for tag in forbidden:
                assert tag not in html, f"Forbidden tag {tag} produced for fixture {h!r}: {html}"
            assert "@octocat" not in html, f"Mention preserved without defanging for {h}: {html}"

    def test_full_markdown_rendering_hostile_containment(self):
        from markdown_it import MarkdownIt

        md = MarkdownIt("commonmark").enable(["table", "linkify", "strikethrough"])
        md.options["linkify"] = True
        ev = [
            Evidence(
                id="install_script_added",
                severity=Severity.HIGH,
                file="path/to/\n| table_breaker |",
                explanation="![img](https://evil.example/x.png) and [click](https://evil.example)",
                legitimate_use_note="*bold* and <script>bad()</script>",
            )
        ]
        rep = _make_report(
            "bad-pkg#123",
            "1.0.0",
            "1.0.1",
            ev,
            decision=Decision.BLOCK,
        )
        rep.limitations = [
            "\n# Injected Heading\n| a | b |\n[evil](https://evil.example)",
        ]

        rendered = _render_markdown(rep, ev)
        html = md.render(rendered)

        # Confirm evil.example is NOT in HTML and evil[.]example IS in HTML
        assert "evil.example" not in html
        assert "evil[.]example" in html
        assert 'href="https://evil.example"' not in html
        assert "<img" not in html
        assert "<script" not in html
        # Confirm no extra headings were created in limitations
        assert "<h1>" not in html

        # Also verify lockfile markdown rendering defangs hostile URLs
        lock_rep = LockfileDiffReport(
            base_source="package-lock.json",
            head_source="package-lock.json",
            total_packages_scanned=1,
            decision=Decision.BLOCK,
            package_results=[
                {
                    "package": "@scope/evil-pkg",
                    "old_version": "1.0.0",
                    "new_version": "1.0.1",
                    "decision": "BLOCK",
                    "evidence": ["install_script_added"],
                    "evidence_details": [
                        {
                            "id": "install_script_added",
                            "severity": "HIGH",
                            "explanation": "Hostile url https://evil.example/payload",
                            "legitimate_use_note": "Docs at https://evil.example/safe",
                        }
                    ],
                }
            ],
            limitations=["\n# Heading\n| a | b |\n[evil](https://evil.example)"],
        )
        lock_md = format_lockfile_markdown(lock_rep)
        lock_html = md.render(lock_md)
        assert "evil.example" not in lock_html
        assert "evil[.]example" in lock_html

    def test_cap_comment_line_boundary_and_unclosed_tags(self):
        unclosed_comment = (
            "<details>\n<summary>Test</summary>\n```js\n"
            + ("const some_variable_name = 12345;\n" * 500)
        )
        capped = cap_comment_size(unclosed_comment, max_chars=1000)

        assert len(capped) <= 1000
        assert capped.endswith(TRUNCATION_NOTE)
        # Check clean closure of fence and details
        assert "```\n</details>" in capped
        # Verify line boundary cut: no partial word like 'const some_varia'
        lines = capped.splitlines()
        # The line right before closing markers / note should be a full statement
        data_lines = [line for line in lines if "const" in line]
        assert all(line == "const some_variable_name = 12345;" for line in data_lines)
