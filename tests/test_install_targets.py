"""Tests for Stage 5g Part 4: Install-target parsing and missing target check."""

from __future__ import annotations

import json

from release_sentinel.differ import (
    _extract_install_script_targets,
    analyze_release,
    compare_releases,
)
from release_sentinel.extractor import ReleaseContents
from release_sentinel.models import Severity


class TestInstallTargetParsing:
    def test_node_with_leading_flags(self):
        pkg = {
            "name": "test-pkg",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "node --no-warnings -r ./register.js scripts/setup.js",
            },
        }
        targets = _extract_install_script_targets(pkg)
        assert "register.js" in targets
        assert "scripts/setup.js" in targets
        assert "--no-warnings" not in targets

    def test_sh_bash_zsh_invocations(self):
        pkg = {
            "name": "test-pkg",
            "version": "1.0.0",
            "scripts": {
                "preinstall": "sh -e scripts/pre.sh && bash setup.sh && zsh ./run.zsh",
            },
        }
        targets = _extract_install_script_targets(pkg)
        assert "scripts/pre.sh" in targets
        assert "setup.sh" in targets
        assert "run.zsh" in targets
        assert "-e" not in targets

    def test_direct_executable(self):
        pkg = {
            "name": "test-pkg",
            "version": "1.0.0",
            "scripts": {
                "install": "./bin/install.sh",
            },
        }
        targets = _extract_install_script_targets(pkg)
        assert "bin/install.sh" in targets

    def test_python_invocations(self):
        pkg = {
            "name": "test-pkg",
            "version": "1.0.0",
            "scripts": {
                "prepare": "python -u build.py && python3 scripts/generate.py",
            },
        }
        targets = _extract_install_script_targets(pkg)
        assert "build.py" in targets
        assert "scripts/generate.py" in targets
        assert "-u" not in targets

    def test_extensionless_node_target(self):
        pkg = {
            "name": "test-pkg",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "node scripts/setup",
            },
        }
        targets = _extract_install_script_targets(pkg)
        assert "scripts/setup" in targets
        assert "scripts/setup.js" in targets
        assert "scripts/setup.cjs" in targets
        assert "scripts/setup.mjs" in targets

    def test_script_indirection_depth_3(self):
        pkg = {
            "name": "test-pkg",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "npm run step1",
                "step1": "yarn step2",
                "step2": "pnpm run step3",
                "step3": "node final.js",
            },
        }
        targets = _extract_install_script_targets(pkg)
        assert "final.js" in targets

    def test_script_indirection_cycle_protection(self):
        pkg = {
            "name": "test-pkg",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "npm run loop1",
                "loop1": "yarn loop2",
                "loop2": "pnpm run loop1",
            },
        }
        targets = _extract_install_script_targets(pkg)
        # Does not crash or recurse infinitely; returns empty
        assert targets == set()


class TestMissingScriptTargetCheck:
    def test_no_false_missing_when_extension_omitted(self):
        pkg = {
            "name": "test-pkg",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "node scripts/setup",
            },
        }
        # In the release, scripts/setup.js is present
        rel = ReleaseContents(
            files={
                "package.json": json.dumps(pkg).encode("utf-8"),
                "scripts/setup.js": b"console.log('clean');",
            }
        )
        evs = analyze_release(rel)
        missing_evs = [
            e for e in evs if e.id == "install_script_present" and "missing" in e.explanation
        ]
        assert not missing_evs

    def test_no_false_missing_when_flags_present(self):
        pkg = {
            "name": "test-pkg",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "node --no-warnings -r ./hook.js scripts/setup.js",
            },
        }
        rel = ReleaseContents(
            files={
                "package.json": json.dumps(pkg).encode("utf-8"),
                "hook.js": b"// hook",
                "scripts/setup.js": b"// setup",
            }
        )
        evs = analyze_release(rel)
        missing_evs = [
            e for e in evs if e.id == "install_script_present" and "missing" in e.explanation
        ]
        assert not missing_evs

    def test_missing_target_correctly_reported(self):
        pkg = {
            "name": "test-pkg",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "node non_existent.js",
            },
        }
        rel = ReleaseContents(
            files={
                "package.json": json.dumps(pkg).encode("utf-8"),
            }
        )
        evs = analyze_release(rel)
        missing_evs = [
            e for e in evs if e.id == "install_script_present" and "missing" in e.explanation
        ]
        assert len(missing_evs) == 1
        assert "non_existent.js" in missing_evs[0].explanation
        assert missing_evs[0].severity == Severity.HIGH

    def test_evasion_sh_file_flagged_notable_new_file(self):
        old_pkg = {"name": "test-pkg", "version": "1.0.0"}
        new_pkg = {
            "name": "test-pkg",
            "version": "1.0.1",
            "scripts": {"postinstall": "sh x.sh"},
        }
        old_rel = ReleaseContents(
            files={"package.json": json.dumps(old_pkg).encode("utf-8")}
        )
        new_rel = ReleaseContents(
            files={
                "package.json": json.dumps(new_pkg).encode("utf-8"),
                "x.sh": b"#!/bin/sh\necho hello",
            }
        )
        evs = compare_releases(old_rel, new_rel)
        notable = [e for e in evs if e.id == "notable_new_file" and e.file == "x.sh"]
        assert len(notable) == 1
        assert notable[0].severity == Severity.HIGH
