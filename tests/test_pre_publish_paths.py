"""Test that no forbidden local paths, URIs, or test-root references exist in tracked text files."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

FORBIDDEN_PATTERNS = {
    "file_uri": re.compile(r"file:///"),
    "my_project_encoded": re.compile(r"My%20project"),
    "my_project_plain": re.compile(r"My project"),
    "c_slash": re.compile(r"(?i)\bc:/"),
    "c_backslash": re.compile(r"(?i)\bc:\\"),
    "rs_data": re.compile(r"rs-data"),
    "release_sentinel_dev": re.compile(r"release-sentinel\.dev"),
    "maintainers_at": re.compile(r"maintainers@"),
    "old_personal_email": re.compile(r"aryan25kumar69@gmail\.com"),
}

EXCLUDED_FILES = {
    "scripts/pre_publish_check.ps1",
    "scripts/history_audit.ps1",
    "tests/test_pre_publish_paths.py",
}


def test_no_forbidden_paths_in_tracked_files():
    tracked = subprocess.check_output(
        ["git", "ls-files"], text=True, encoding="utf-8"
    ).splitlines()

    violations = []
    for f in tracked:
        if f in EXCLUDED_FILES:
            continue
        p = Path(f)
        if not p.is_file():
            continue
        try:
            content = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        for p_name, pat in FORBIDDEN_PATTERNS.items():
            matches = pat.findall(content)
            if not matches:
                continue

            # docs/REPRODUCING.md allows rs-data for the documented RS_SAMPLES_ROOT variable
            if f == "docs/REPRODUCING.md" and p_name == "rs_data":
                continue

            violations.append(f"{f}: found {p_name} matches: {matches[:3]}")

    msg = "Forbidden paths detected in tracked text files:\n" + "\n".join(violations)
    assert not violations, msg

def test_no_control_characters_in_tracked_text_files():
    tracked = subprocess.check_output(
        ["git", "ls-files"], text=True, encoding="utf-8"
    ).splitlines()

    binary_exts = {".png", ".jpg", ".jpeg", ".ico", ".pdf", ".zip", ".tar", ".gz", ".tgz", ".pyc"}
    violations = []

    for f in tracked:
        p_file = Path(f)
        if p_file.suffix.lower() in binary_exts or not p_file.is_file():
            continue
        try:
            file_content = p_file.read_text(encoding="utf-8")
        except Exception:
            continue

        for line_no, line in enumerate(file_content.splitlines(), 1):
            for col_no, char in enumerate(line, 1):
                code = ord(char)
                is_ctrl = (code < 32 and code not in (9, 10, 13)) or code == 127
                is_c1_or_replacement = (128 <= code <= 159) or code == 0xFFFD
                if is_ctrl or is_c1_or_replacement:
                    violations.append(
                        f"{f}:{line_no}:{col_no} (code {hex(code)}, char {repr(char)})"
                    )

    msg = "Control characters or U+FFFD detected in tracked text files:\n" + "\n".join(violations)
    assert not violations, msg
