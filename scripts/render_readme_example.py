"""Generate the canonical GitHub PR markdown comment examples for the README."""

from __future__ import annotations

import sys
from pathlib import Path

src_path = str(Path(__file__).resolve().parent.parent / "src")
if src_path not in sys.path:
    sys.path.insert(0, src_path)

from release_sentinel.cli import format_lockfile_markdown
from release_sentinel.lockfile import LockfileDiffReport
from release_sentinel.models import Decision, Severity


def generate_example() -> str:
    """Build the canonical LockfileDiffReport for axios 1.14.0 -> 1.14.1 (WARN) and render markdown."""
    report = LockfileDiffReport(
        base_source="package-lock.json",
        head_source="package-lock.json",
        total_packages_scanned=1,
        decision=Decision.WARN,
        package_results=[
            {
                "package": "axios",
                "old_version": "1.14.0",
                "new_version": "1.14.1",
                "change_type": "upgrade",
                "decision": "WARN",
                "evidence": ["install_script_present", "dependency_added"],
                "evidence_details": [
                    {
                        "id": "install_script_present",
                        "severity": Severity.HIGH.name,
                        "file": "node_modules/plain-crypto-js/package.json",
                        "explanation": "[dep: plain-crypto-js@4.2.1] Lifecycle script 'postinstall' references script target 'setup.js' that is missing from the package.",
                        "legitimate_use_note": "Broken or incomplete package packaging.",
                    },
                    {
                        "id": "dependency_added",
                        "severity": Severity.LOW.name,
                        "file": "package.json",
                        "explanation": "New dependencies added: 'plain-crypto-js' @ '^4.2.1'. This introduces a new transitive dependency tree.",
                        "legitimate_use_note": "New dependencies are common in feature releases. Check whether the added package is well-maintained.",
                    },
                ],
                "limitations": [],
                "status": "ok",
            }
        ],
        limitations=[
            "JavaScript/TypeScript source scanned with static heuristics; dynamic evasion is possible.",
            "Every changed lockfile entry (including transitive dependencies) is scanned.",
        ],
    )
    return format_lockfile_markdown(report)


def generate_block_example() -> str:
    """Build canonical LockfileDiffReport for 2025 install hook wave (camp_0048 BLOCK) and render markdown."""
    report = LockfileDiffReport(
        base_source="package-lock.json",
        head_source="package-lock.json",
        total_packages_scanned=1,
        decision=Decision.BLOCK,
        package_results=[
            {
                "package": "@ahmedhfarag/ngx-perfect-scrollbar",
                "old_version": "20.0.19",
                "new_version": "20.0.20",
                "change_type": "upgrade",
                "decision": "BLOCK",
                "evidence": ["install_script_network", "install_script_added"],
                "evidence_details": [
                    {
                        "id": "install_script_network",
                        "severity": Severity.CRITICAL.name,
                        "file": "package.json",
                        "explanation": "Added lifecycle hook 'preinstall' downloads executable content from external network endpoints.",
                        "legitimate_use_note": "Precompiled platform binary downloads during installation.",
                    },
                    {
                        "id": "install_script_added",
                        "severity": Severity.HIGH.name,
                        "file": "package.json",
                        "explanation": "New lifecycle hook 'preinstall' was added to package manifest.",
                        "legitimate_use_note": "Build compilation or asset preparation hooks.",
                    },
                ],
                "limitations": [],
                "status": "ok",
            }
        ],
        limitations=[
            "JavaScript/TypeScript source scanned with static heuristics; dynamic evasion is possible.",
            "Every changed lockfile entry (including transitive dependencies) is scanned.",
        ],
    )
    return format_lockfile_markdown(report)


def main() -> None:
    warn_example_md = generate_example()
    out_warn = Path("docs/example_comment.md")
    out_warn.write_text(warn_example_md + "\n", encoding="utf-8")
    print(f"Generated {out_warn} ({len(warn_example_md)} chars)")

    block_example_md = generate_block_example()
    out_block = Path("docs/example_block_comment.md")
    out_block.write_text(block_example_md + "\n", encoding="utf-8")
    print(f"Generated {out_block} ({len(block_example_md)} chars)")


if __name__ == "__main__":
    main()
