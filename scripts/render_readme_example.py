"""Generate the canonical GitHub PR markdown comment example for the README."""

from __future__ import annotations

from pathlib import Path

from release_sentinel.cli import format_lockfile_markdown
from release_sentinel.lockfile import LockfileDiffReport
from release_sentinel.models import Decision, Severity


def generate_example() -> str:
    """Build the canonical LockfileDiffReport for axios 1.14.0 -> 1.14.1 and render markdown."""
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


def main() -> None:
    example_md = generate_example()
    out_path = Path("docs/example_comment.md")
    out_path.write_text(example_md + "\n", encoding="utf-8")
    print(f"Generated {out_path} ({len(example_md)} chars)")


if __name__ == "__main__":
    main()
