"""Tests for the content scanner (content_scanner.py).

All test strings are harmless synthetic fragments that merely trigger
the heuristics (Rule 6 — no real malware in the repo).

Positive tests: newly introduced pattern → evidence emitted.
Negative tests: same pattern present in old version → no evidence.
"""

from __future__ import annotations

import time
from pathlib import Path

from release_sentinel.content_scanner import (
    _shannon_entropy,
    find_credential_read_matches,
    scan_new_content,
)
from release_sentinel.extractor import ExtractionResult, FileEntry
from release_sentinel.policy import decide

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_result(tmp_path: Path, tag: str, files: dict[str, str]) -> ExtractionResult:
    """Build an ExtractionResult from a {rel_path: content} dict without a real tarball."""
    root = tmp_path / tag
    root.mkdir(parents=True, exist_ok=True)
    entries: list[FileEntry] = []
    total = 0
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        data = content.encode()
        p.write_bytes(data)
        entries.append(FileEntry(rel_path=rel, abs_path=p, size=len(data)))
        total += len(data)
    return ExtractionResult(root=root, files=entries, total_size=total)


def _scan(
    old_files: dict[str, str],
    new_files: dict[str, str],
    tmp_path: Path,
    install_targets: set[str] | None = None,
) -> list:
    old = _make_result(tmp_path / "old", "old", old_files)
    new = _make_result(tmp_path / "new", "new", new_files)
    return scan_new_content(old, new, install_targets or set())


# ---------------------------------------------------------------------------
# Positive tests — newly introduced patterns
# ---------------------------------------------------------------------------


class TestProcessExec:
    def test_child_process_exec_flagged(self, tmp_path: Path):
        ev = _scan(
            {"index.js": "const x = 1;"},
            {"index.js": "const cp = require('child_process');\ncp.exec('ls');"},
            tmp_path,
        )
        assert any(e.id == "process_exec" for e in ev)

    def test_child_process_execSync_flagged(self, tmp_path: Path):
        ev = _scan(
            {"index.js": ""},
            {"index.js": "const { execSync } = require('child_process');\nexecSync('ls');"},
            tmp_path,
        )
        assert any(e.id == "process_exec" for e in ev)

    def test_child_process_spawn_flagged(self, tmp_path: Path):
        ev = _scan(
            {"run.js": ""},
            {"run.js": "const cp = require('node:child_process');\ncp.spawn('sh');"},
            tmp_path,
        )
        assert any(e.id == "process_exec" for e in ev)

    def test_direct_execFile_flagged(self, tmp_path: Path):
        ev = _scan(
            {"run.js": ""},
            {"run.js": "require('child_process').execFile('bin', []);"},
            tmp_path,
        )
        assert any(e.id == "process_exec" for e in ev)

    def test_process_binding_spawn_sync_flagged(self, tmp_path: Path):
        ev = _scan(
            {"run.js": ""},
            {"run.js": "process.binding('spawn_sync');"},
            tmp_path,
        )
        assert any(e.id == "process_exec" for e in ev)

    def test_esm_import_child_process_flagged(self, tmp_path: Path):
        ev = _scan(
            {"run.js": ""},
            {"run.js": "import { fork } from 'child_process';\nfork('sub.js');"},
            tmp_path,
        )
        assert any(e.id == "process_exec" for e in ev)

    # Negative tests
    def test_regexp_exec_not_flagged(self, tmp_path: Path):
        """RegExp.prototype.exec must NEVER be flagged as process_exec."""
        ev = _scan(
            {"run.js": ""},
            {"run.js": "const re = /abc/;\nconst match = re.exec('abcdef');"},
            tmp_path,
        )
        assert not any(e.id == "process_exec" for e in ev)

    def test_bare_exec_call_not_flagged(self, tmp_path: Path):
        """A bare .exec() call without child_process must not be flagged."""
        ev = _scan(
            {"run.js": ""},
            {"run.js": "const runner = new TaskRunner();\nrunner.exec();"},
            tmp_path,
        )
        assert not any(e.id == "process_exec" for e in ev)

    def test_require_child_process_without_execution_not_flagged(self, tmp_path: Path):
        """Requiring child_process without calling execution APIs is not process_exec."""
        ev = _scan(
            {"run.js": ""},
            {"run.js": "const cp = require('child_process');\n// no calls"},
            tmp_path,
        )
        assert not any(e.id == "process_exec" for e in ev)


class TestDynamicCode:
    def test_eval_flagged(self, tmp_path: Path):
        ev = _scan(
            {"lib.js": ""},
            {"lib.js": "eval(userInput);"},
            tmp_path,
        )
        assert any(e.id == "dynamic_code" for e in ev)

    def test_new_function_flagged(self, tmp_path: Path):
        ev = _scan(
            {"lib.js": ""},
            {"lib.js": "const fn = new Function('return 42');"},
            tmp_path,
        )
        assert any(e.id == "dynamic_code" for e in ev)


class TestNetworkAccess:
    def test_require_http_flagged(self, tmp_path: Path):
        ev = _scan(
            {"net.js": ""},
            {"net.js": "const http = require('http');"},
            tmp_path,
        )
        assert any(e.id == "network_access" for e in ev)

    def test_fetch_flagged(self, tmp_path: Path):
        ev = _scan(
            {"req.js": ""},
            {"req.js": "fetch('https://example.com/data');"},
            tmp_path,
        )
        assert any(e.id == "network_access" for e in ev)


class TestHardcodedUrl:
    def test_external_url_flagged(self, tmp_path: Path):
        ev = _scan(
            {"cfg.js": ""},
            {"cfg.js": "const url = 'https://telemetry.example-corp.com/collect';"},
            tmp_path,
        )
        assert any(e.id == "hardcoded_url" for e in ev)

    def test_npm_registry_url_not_flagged(self, tmp_path: Path):
        """npm registry URLs are excluded from hardcoded URL detection."""
        ev = _scan(
            {"cfg.js": ""},
            {"cfg.js": "const reg = 'https://registry.npmjs.com/package';"},
            tmp_path,
        )
        assert not any(e.id == "hardcoded_url" for e in ev)


class TestHardcodedIp:
    def test_public_ip_flagged(self, tmp_path: Path):
        ev = _scan(
            {"net.js": ""},
            {"net.js": "const host = '203.0.113.42';"},
            tmp_path,
        )
        assert any(e.id == "hardcoded_ip" for e in ev)

    def test_loopback_not_flagged(self, tmp_path: Path):
        ev = _scan(
            {"net.js": ""},
            {"net.js": "const host = '127.0.0.1';"},
            tmp_path,
        )
        assert not any(e.id == "hardcoded_ip" for e in ev)

    def test_private_rfc1918_not_flagged(self, tmp_path: Path):
        ev = _scan(
            {"net.js": ""},
            {"net.js": "const host = '192.168.1.1';"},
            tmp_path,
        )
        assert not any(e.id == "hardcoded_ip" for e in ev)


class TestCredentialFileRead:
    def test_npmrc_reference_flagged(self, tmp_path: Path):
        ev = _scan(
            {"read.js": ""},
            {"read.js": "fs.readFileSync('.npmrc', 'utf8');"},
            tmp_path,
        )
        assert any(e.id == "credential_file_read" for e in ev)

    def test_ssh_dir_reference_flagged(self, tmp_path: Path):
        ev = _scan(
            {"read.js": ""},
            {"read.js": "const key = readFile('.ssh/id_rsa');"},
            tmp_path,
        )
        assert any(e.id == "credential_file_read" for e in ev)

    def test_aws_credentials_flagged(self, tmp_path: Path):
        ev = _scan(
            {"read.js": ""},
            {"read.js": "fs.createReadStream('.aws/credentials');"},
            tmp_path,
        )
        assert any(e.id == "credential_file_read" for e in ev)

    def test_netrc_promises_flagged(self, tmp_path: Path):
        ev = _scan(
            {"read.js": ""},
            {"read.js": "await fs.promises.readFile('.netrc');"},
            tmp_path,
        )
        assert any(e.id == "credential_file_read" for e in ev)

    def test_nearby_path_construction_flagged(self, tmp_path: Path):
        code = (
            "const p = path.join(os.homedir(), '.npmrc');\n"
            "const data = fs.readFileSync(p, 'utf8');\n"
        )
        ev = _scan({"read.js": ""}, {"read.js": code}, tmp_path)
        assert any(e.id == "credential_file_read" for e in ev)

    # Negative tests
    def test_fetch_credentials_option_not_flagged(self, tmp_path: Path):
        """Fetch credentials option ('include') must NOT be flagged as credential_file_read."""
        ev = _scan(
            {"req.js": ""},
            {"req.js": "fetch('https://example.com/api', { credentials: 'include' });"},
            tmp_path,
        )
        assert not any(e.id == "credential_file_read" for e in ev)

    def test_xhr_with_credentials_not_flagged(self, tmp_path: Path):
        """XHR withCredentials must NOT be flagged as credential_file_read."""
        ev = _scan(
            {"req.js": ""},
            {"req.js": "const xhr = new XMLHttpRequest();\nxhr.withCredentials = true;"},
            tmp_path,
        )
        assert not any(e.id == "credential_file_read" for e in ev)

    def test_bare_credentials_word_not_flagged(self, tmp_path: Path):
        """Bare word 'credentials' must NOT be flagged as credential_file_read."""
        code = "const credentials = { user: 'admin', pass: 'secret' };\nconsole.log(credentials);"
        ev = _scan({"config.js": ""}, {"config.js": code}, tmp_path)
        assert not any(e.id == "credential_file_read" for e in ev)

    def test_regular_file_read_not_flagged(self, tmp_path: Path):
        """Reading regular files (like package.json) is not credential_file_read."""
        ev = _scan(
            {"read.js": ""},
            {"read.js": "fs.readFileSync('package.json', 'utf8');"},
            tmp_path,
        )
        assert not any(e.id == "credential_file_read" for e in ev)


class TestCommentsIgnored:
    def test_eval_in_line_comment_ignored(self, tmp_path: Path):
        """eval( inside a line comment is ignored."""
        ev = _scan(
            {"lib.js": ""},
            {"lib.js": "// eval('malicious code');\nconst x = 1;"},
            tmp_path,
        )
        assert not any(e.id == "dynamic_code" for e in ev)

    def test_eval_in_block_comment_ignored(self, tmp_path: Path):
        """eval( inside a block comment is ignored."""
        ev = _scan(
            {"lib.js": ""},
            {"lib.js": "/* eval('malicious code'); */\nconst x = 1;"},
            tmp_path,
        )
        assert not any(e.id == "dynamic_code" for e in ev)

    def test_eval_in_multiline_block_comment_ignored(self, tmp_path: Path):
        """eval( inside a multi-line block comment is ignored."""
        code = "/*\n * eval('malicious code');\n */\nconst x = 1;\n"
        ev = _scan({"lib.js": ""}, {"lib.js": code}, tmp_path)
        assert not any(e.id == "dynamic_code" for e in ev)

    def test_url_in_comment_ignored(self, tmp_path: Path):
        """URLs inside comments are ignored."""
        code = "// https://evil-c2-tracker.org/steal-payload\nconst x = 1;\n"
        ev = _scan({"lib.js": ""}, {"lib.js": code}, tmp_path)
        assert not any(e.id == "hardcoded_url" for e in ev)

    def test_code_with_comment_still_flags_real_code(self, tmp_path: Path):
        """Code on the same line before a comment still fires."""
        code = "eval('safe'); // trailing comment\n"
        ev = _scan({"lib.js": ""}, {"lib.js": code}, tmp_path)
        assert any(e.id == "dynamic_code" for e in ev)


class TestRegistryToken:
    def test_npm_token_flagged(self, tmp_path: Path):
        ev = _scan(
            {"pub.js": ""},
            {"pub.js": "const tok = process.env.NPM_TOKEN;"},
            tmp_path,
        )
        assert any(e.id == "registry_token" for e in ev)

    def test_auth_token_flagged(self, tmp_path: Path):
        ev = _scan(
            {"pub.js": ""},
            {"pub.js": "config['_authToken'] = token;"},
            tmp_path,
        )
        assert any(e.id == "registry_token" for e in ev)


class TestLongEncodedBlob:
    def test_atob_flagged(self, tmp_path: Path):
        ev = _scan(
            {"decode.js": ""},
            {"decode.js": "const data = atob(encodedPayload);"},
            tmp_path,
        )
        assert any(e.id == "long_encoded_blob" for e in ev)

    def test_buffer_from_base64_flagged(self, tmp_path: Path):
        ev = _scan(
            {"decode.js": ""},
            {"decode.js": "Buffer.from(data, 'base64');"},
            tmp_path,
        )
        assert any(e.id == "long_encoded_blob" for e in ev)

    def test_very_long_line_flagged(self, tmp_path: Path):
        """A line > 500 chars triggers long_encoded_blob even without explicit decode."""
        long_line = "const x = '" + "A" * 510 + "';"
        ev = _scan(
            {"min.js": ""},
            {"min.js": long_line},
            tmp_path,
        )
        assert any(e.id == "long_encoded_blob" for e in ev)


class TestCiWrite:
    def test_github_workflow_path_flagged(self, tmp_path: Path):
        ev = _scan(
            {"setup.js": ""},
            {"setup.js": "fs.writeFile('.github/workflows/ci.yml', content);"},
            tmp_path,
        )
        assert any(e.id == "ci_write" for e in ev)


class TestShellProfileWrite:
    def test_bashrc_reference_flagged(self, tmp_path: Path):
        ev = _scan(
            {"setup.js": ""},
            {"setup.js": "fs.appendFileSync('.bashrc', cmd);"},
            tmp_path,
        )
        assert any(e.id == "shell_profile_write" for e in ev)


class TestGitHookWrite:
    def test_git_hooks_path_flagged(self, tmp_path: Path):
        ev = _scan(
            {"install.js": ""},
            {"install.js": "cp('hook', '.git/hooks/pre-commit');"},
            tmp_path,
        )
        assert any(e.id == "git_hook_write" for e in ev)


class TestEnvEnumeration:
    def test_three_distinct_env_accesses_flagged(self, tmp_path: Path):
        code = (
            "const a = process.env.A;\n"
            "const b = process.env.B;\n"
            "const c = process.env.C;\n"
        )
        ev = _scan({"env.js": ""}, {"env.js": code}, tmp_path)
        assert any(e.id == "env_enumeration" for e in ev)

    def test_below_threshold_env_accesses_not_flagged(self, tmp_path: Path):
        code = "const a = process.env.PORT || 3000;\nconst b = process.env.HOST;\n"
        ev = _scan({"env.js": ""}, {"env.js": code}, tmp_path)
        assert not any(e.id == "env_enumeration" for e in ev)


# ---------------------------------------------------------------------------
# Negative tests — patterns present in BOTH versions → no new evidence
# ---------------------------------------------------------------------------


class TestNewOnlyDiff:
    def test_pattern_in_old_not_flagged(self, tmp_path: Path):
        """If the suspicious line is in old too, it must not be flagged."""
        same_line = "const cp = require('child_process');\ncp.execSync('ls');"
        ev = _scan(
            {"index.js": same_line},
            {"index.js": same_line + "\n// unchanged"},
            tmp_path,
        )
        # The require + exec is not new → no process_exec evidence
        assert not any(e.id == "process_exec" for e in ev)

    def test_network_pattern_in_old_not_flagged(self, tmp_path: Path):
        code = "const http = require('http');\nfetch('https://example.com');"
        ev = _scan({"net.js": code}, {"net.js": code + "\nconst x = 1;"}, tmp_path)
        assert not any(e.id == "network_access" for e in ev)

    def test_credentials_pattern_in_old_not_flagged(self, tmp_path: Path):
        code = "const x = fs.readFileSync('.npmrc');"
        ev = _scan({"sec.js": code}, {"sec.js": code + "\nconst y = 2;"}, tmp_path)
        assert not any(e.id == "credential_file_read" for e in ev)

    def test_ci_write_pattern_in_old_not_flagged(self, tmp_path: Path):
        code = "const p = '.github/workflows/deploy.yml';"
        ev = _scan({"ci.js": code}, {"ci.js": code + "\n// log"}, tmp_path)
        assert not any(e.id == "ci_write" for e in ev)

    def test_profile_and_hook_in_old_not_flagged(self, tmp_path: Path):
        code = "const b = '.bashrc';\nconst h = '.git/hooks';"
        ev = _scan({"setup.js": code}, {"setup.js": code + "\n// same"}, tmp_path)
        ids = {e.id for e in ev}
        assert "shell_profile_write" not in ids
        assert "git_hook_write" not in ids

    def test_only_new_lines_flagged(self, tmp_path: Path):
        """Old file has child_process exec, new adds eval — only eval should be flagged."""
        ev = _scan(
            {"index.js": "const cp = require('child_process');\ncp.execSync('ls');"},
            {"index.js": "const cp = require('child_process');\ncp.execSync('ls');\neval(code);"},
            tmp_path,
        )
        ids = {e.id for e in ev}
        assert "dynamic_code" in ids
        # child_process.execSync is in old → not newly introduced
        assert "process_exec" not in ids

    def test_entirely_new_file_all_lines_scanned(self, tmp_path: Path):
        """A file that's new → all its lines are scanned."""
        ev = _scan(
            {},
            {"new.js": "const cp = require('child_process');\ncp.execSync('ls');"},
            tmp_path,
        )
        assert any(e.id == "process_exec" for e in ev)

    def test_no_evidence_for_unchanged_file(self, tmp_path: Path):
        content = "const x = 1;\nconst y = 2;\n"
        ev = _scan({"util.js": content}, {"util.js": content}, tmp_path)
        assert ev == []


# ---------------------------------------------------------------------------
# Install-script target escalation
# ---------------------------------------------------------------------------


class TestInstallTargetEscalation:
    def test_medium_signal_escalates_to_high_for_install_target(self, tmp_path: Path):
        """network_access (MEDIUM) in an install-script target → HIGH."""
        ev = _scan(
            {"postinstall.js": ""},
            {"postinstall.js": "const http = require('http');"},
            tmp_path,
            install_targets={"postinstall.js"},
        )
        network_evs = [e for e in ev if e.id == "network_access"]
        assert network_evs, "Expected network_access evidence"
        assert network_evs[0].severity.value == "HIGH"

    def test_signal_in_non_install_file_stays_medium(self, tmp_path: Path):
        """Same signal in a non-install file stays at MEDIUM."""
        ev = _scan(
            {"other.js": ""},
            {"other.js": "const http = require('http');"},
            tmp_path,
            install_targets=set(),
        )
        network_evs = [e for e in ev if e.id == "network_access"]
        assert network_evs
        assert network_evs[0].severity.value == "MEDIUM"


# ---------------------------------------------------------------------------
# Ignorable files — no content scan
# ---------------------------------------------------------------------------


class TestIgnorableFiles:
    def test_png_not_scanned(self, tmp_path: Path):
        """Image files should not be scanned for text patterns."""
        # A PNG with some text that matches a signal pattern — still not flagged
        fake_png_with_text = b"\x89PNG\r\n\x1a\n" + b"eval(bad)" * 10
        old_root = tmp_path / "old"
        new_root = tmp_path / "new"
        old_root.mkdir()
        new_root.mkdir()
        p = new_root / "logo.png"
        p.write_bytes(fake_png_with_text)
        from release_sentinel.extractor import ExtractionResult, FileEntry
        old = ExtractionResult(root=old_root, files=[], total_size=0)
        new = ExtractionResult(
            root=new_root,
            files=[FileEntry(rel_path="logo.png", abs_path=p, size=len(fake_png_with_text))],
            total_size=len(fake_png_with_text),
        )
        evidence = scan_new_content(old, new, set())
        assert not any(e.id == "dynamic_code" for e in evidence)


# ---------------------------------------------------------------------------
# Entropy helper
# ---------------------------------------------------------------------------


class TestShannonEntropy:
    def test_high_entropy_random_string(self):
        """A string of varied chars should have high entropy."""
        s = "aB3!xZ9@qW2#eR4$tY5^"
        assert _shannon_entropy(s) > 3.0

    def test_low_entropy_repeated_char(self):
        assert _shannon_entropy("aaaaaaaaaaaaaaaa") < 1.0

    def test_empty_string(self):
        assert _shannon_entropy("") == 0.0


# ---------------------------------------------------------------------------
# Stage 4a: Robustness and Timeout Fixes
# ---------------------------------------------------------------------------


class TestTimeoutFixes:
    def test_pathological_regex_backtracking_completes_fast(self):
        """Pathological regex input with spaces after 'fs' must finish in <0.05s."""
        pathological = "fs" + " " * 200_000 + "x"
        t0 = time.perf_counter()
        matches = find_credential_read_matches(pathological)
        elapsed = time.perf_counter() - t0

        assert matches == []
        assert elapsed < 0.1, f"Pathological regex took too long: {elapsed:.4f}s"

    def test_synthetic_large_single_line_file_finishes_fast(self, tmp_path: Path):
        """A 1.5 MB single-line minified file must scan in < 1.5 seconds."""
        single_line = "var a=1;function foo(x){return x+2;}" * 40_000  # ~1.44 MB single line
        t0 = time.perf_counter()
        ev = _scan(
            {"bundle.js": "var a=1;"},
            {"bundle.js": single_line},
            tmp_path,
        )
        elapsed = time.perf_counter() - t0

        assert elapsed < 1.5, f"Scan of 1.44 MB single line took {elapsed:.4f}s"
        assert not any(e.id == "inspection_incomplete" for e in ev)

    def test_oversized_file_triggers_inspection_incomplete_and_cheap_checks(self, tmp_path: Path):
        """A file exceeding PER_FILE_SIZE_BUDGET (2 MB) triggers inspection_incomplete."""
        oversized_content = "var x = 1;\n" * 250_000  # ~2.75 MB
        t0 = time.perf_counter()
        ev = _scan(
            {"big.js": "var x = 1;\n"},
            {"big.js": oversized_content},
            tmp_path,
            install_targets={"big.js"},
        )
        elapsed = time.perf_counter() - t0

        assert elapsed < 1.0, f"Oversized file handling took {elapsed:.4f}s"
        incomplete_ev = [e for e in ev if e.id == "inspection_incomplete"]
        assert len(incomplete_ev) == 1
        assert "exceeded resource budget" in incomplete_ev[0].explanation
        assert "size changed from" in incomplete_ev[0].explanation
        assert "is an install-script target" in incomplete_ev[0].explanation

        # Test policy fail-closed behavior
        decision, limitations = decide(ev)
        assert decision.value in ("WARN", "BLOCK")
        assert any("Inspection incomplete" in lim for lim in limitations)

    def test_time_budget_triggers_gracefully(self, tmp_path: Path, monkeypatch):
        """Per-file time budget triggers gracefully if processing time exceeds budget."""
        monkeypatch.setattr("release_sentinel.content_scanner.PER_FILE_TIME_BUDGET", 0.00001)

        ev = _scan(
            {"lib.js": "var a = 1;"},
            {"lib.js": "var a = 2;\n" * 500},
            tmp_path,
        )

        incomplete_ev = [e for e in ev if e.id == "inspection_incomplete"]
        assert len(incomplete_ev) == 1
        assert "processing time exceeded" in incomplete_ev[0].explanation

