"""Tests for the file type classifier (file_classifier.py).

Rule 6: no real malware. We test with inert synthetic bytes/content.
"""

from __future__ import annotations

from pathlib import Path

from release_sentinel.file_classifier import (
    FileCategory,
    classify,
    is_ignorable,
    is_notable,
)


def _make_file(tmp_path: Path, name: str, content: bytes = b"x") -> tuple[Path, str]:
    """Create a temp file with given bytes. Returns (abs_path, rel_path)."""
    p = tmp_path / name
    p.write_bytes(content)
    return p, name


class TestExtensionClassification:
    def test_js_is_script(self, tmp_path: Path):
        abs_p, rel = _make_file(tmp_path, "index.js", b"module.exports = {}")
        assert classify(abs_p, rel) == FileCategory.SCRIPT

    def test_ts_is_script(self, tmp_path: Path):
        abs_p, rel = _make_file(tmp_path, "lib.ts", b"export const x = 1")
        assert classify(abs_p, rel) == FileCategory.SCRIPT

    def test_sh_is_executable(self, tmp_path: Path):
        abs_p, rel = _make_file(tmp_path, "build.sh", b"#!/bin/sh\necho hi")
        assert classify(abs_p, rel) == FileCategory.EXECUTABLE

    def test_bat_is_executable(self, tmp_path: Path):
        abs_p, rel = _make_file(tmp_path, "run.bat", b"@echo off")
        assert classify(abs_p, rel) == FileCategory.EXECUTABLE

    def test_node_is_native_binary(self, tmp_path: Path):
        abs_p, rel = _make_file(tmp_path, "binding.node", b"\x7fELF" + b"\x00" * 60)
        assert classify(abs_p, rel) == FileCategory.NATIVE_BINARY

    def test_dll_is_native_binary(self, tmp_path: Path):
        abs_p, rel = _make_file(tmp_path, "native.dll", b"MZ" + b"\x00" * 60)
        assert classify(abs_p, rel) == FileCategory.NATIVE_BINARY

    def test_png_is_asset(self, tmp_path: Path):
        abs_p, rel = _make_file(tmp_path, "logo.png", b"\x89PNG\r\n\x1a\n")
        assert classify(abs_p, rel) == FileCategory.ASSET

    def test_woff2_is_asset(self, tmp_path: Path):
        abs_p, rel = _make_file(tmp_path, "font.woff2", b"wOF2")
        assert classify(abs_p, rel) == FileCategory.ASSET

    def test_md_is_document(self, tmp_path: Path):
        abs_p, rel = _make_file(tmp_path, "README.md", b"# Hello")
        assert classify(abs_p, rel) == FileCategory.DOCUMENT

    def test_map_is_source_map(self, tmp_path: Path):
        abs_p, rel = _make_file(tmp_path, "index.js.map", b'{"version":3}')
        assert classify(abs_p, rel) == FileCategory.SOURCE_MAP

    def test_json_is_other(self, tmp_path: Path):
        abs_p, rel = _make_file(tmp_path, "data.json", b'{"a":1}')
        assert classify(abs_p, rel) == FileCategory.OTHER

    def test_css_is_other(self, tmp_path: Path):
        abs_p, rel = _make_file(tmp_path, "style.css", b"body{}")
        assert classify(abs_p, rel) == FileCategory.OTHER


class TestDotfileClassification:
    def test_npmrc_is_dotfile(self, tmp_path: Path):
        abs_p, rel = _make_file(tmp_path, ".npmrc", b"registry=https://example.com")
        assert classify(abs_p, rel) == FileCategory.DOTFILE

    def test_env_is_dotfile(self, tmp_path: Path):
        abs_p, rel = _make_file(tmp_path, ".env", b"SECRET=x")
        assert classify(abs_p, rel) == FileCategory.DOTFILE

    def test_gitignore_is_safe_not_dotfile(self, tmp_path: Path):
        """Known safe dotfiles should NOT be classified as DOTFILE."""
        abs_p, rel = _make_file(tmp_path, ".gitignore", b"node_modules/")
        # .gitignore is a safe dotfile → classified as OTHER (no extension match)
        cat = classify(abs_p, rel)
        assert cat != FileCategory.DOTFILE

    def test_editorconfig_is_safe(self, tmp_path: Path):
        abs_p, rel = _make_file(tmp_path, ".editorconfig", b"[*]\nindent_size = 2")
        cat = classify(abs_p, rel)
        assert cat != FileCategory.DOTFILE


class TestMagicByteClassification:
    def test_elf_binary_detected_by_magic(self, tmp_path: Path):
        """File with no recognised extension but ELF magic → NATIVE_BINARY."""
        elf_bytes = b"\x7fELF" + b"\x00" * 60
        abs_p, rel = _make_file(tmp_path, "native_addon", elf_bytes)
        assert classify(abs_p, rel) == FileCategory.NATIVE_BINARY

    def test_pe_binary_detected_by_magic(self, tmp_path: Path):
        """File with no recognised extension but PE (MZ) magic → NATIVE_BINARY."""
        pe_bytes = b"MZ" + b"\x00" * 60
        abs_p, rel = _make_file(tmp_path, "binary_no_ext", pe_bytes)
        assert classify(abs_p, rel) == FileCategory.NATIVE_BINARY

    def test_macho_binary_detected_by_magic(self, tmp_path: Path):
        """Mach-O magic bytes → NATIVE_BINARY."""
        macho = b"\xfe\xed\xfa\xce" + b"\x00" * 60
        abs_p, rel = _make_file(tmp_path, "dylib_no_ext", macho)
        assert classify(abs_p, rel) == FileCategory.NATIVE_BINARY

    def test_wasm_detected_by_magic(self, tmp_path: Path):
        wasm = b"\x00asm" + b"\x01\x00\x00\x00"
        abs_p, rel = _make_file(tmp_path, "module", wasm)
        assert classify(abs_p, rel) == FileCategory.NATIVE_BINARY

    def test_text_file_no_magic_match(self, tmp_path: Path):
        abs_p, rel = _make_file(tmp_path, "readme", b"just text content")
        cat = classify(abs_p, rel)
        assert cat == FileCategory.OTHER


class TestMinifiedDetection:
    def test_long_line_js_is_minified(self, tmp_path: Path):
        long_line = "x" * 600
        abs_p, rel = _make_file(tmp_path, "bundle.js", long_line.encode())
        assert classify(abs_p, rel) == FileCategory.MINIFIED

    def test_normal_js_is_script(self, tmp_path: Path):
        normal = "const x = 1;\nconst y = 2;\n"
        abs_p, rel = _make_file(tmp_path, "lib.js", normal.encode())
        assert classify(abs_p, rel) == FileCategory.SCRIPT

    def test_long_line_other_is_minified(self, tmp_path: Path):
        long_line = "x" * 600
        abs_p, rel = _make_file(tmp_path, "bundle.css", long_line.encode())
        assert classify(abs_p, rel) == FileCategory.MINIFIED

    def test_long_line_extensionless_is_minified(self, tmp_path: Path):
        long_line = "x" * 600
        abs_p, rel = _make_file(tmp_path, "bundle", long_line.encode())
        assert classify(abs_p, rel) == FileCategory.MINIFIED


class TestIsIgnorableAndNotable:
    def test_asset_is_ignorable(self):
        assert is_ignorable(FileCategory.ASSET) is True

    def test_document_is_ignorable(self):
        assert is_ignorable(FileCategory.DOCUMENT) is True

    def test_source_map_is_ignorable(self):
        assert is_ignorable(FileCategory.SOURCE_MAP) is True

    def test_script_not_ignorable(self):
        assert is_ignorable(FileCategory.SCRIPT) is False

    def test_native_binary_is_notable(self):
        assert is_notable(FileCategory.NATIVE_BINARY) is True

    def test_executable_is_notable(self):
        assert is_notable(FileCategory.EXECUTABLE) is True

    def test_dotfile_is_notable(self):
        assert is_notable(FileCategory.DOTFILE) is True

    def test_minified_is_notable(self):
        assert is_notable(FileCategory.MINIFIED) is True

    def test_script_not_notable(self):
        assert is_notable(FileCategory.SCRIPT) is False

    def test_asset_not_notable(self):
        assert is_notable(FileCategory.ASSET) is False
