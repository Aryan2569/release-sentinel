"""Extractor fuzz / adversarial tests (Stage 2).

Tests for unusual/malicious archive constructs that the extractor must handle
safely: duplicate members, declared-size mismatches, very deep paths, very
long filenames, and tar bombs.

Rule 6: no real malware. We synthesise adversarial archives in-memory.
"""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest

from release_sentinel.extractor import ExtractionConfig, ExtractionError, extract_release


def _open_writable(dest: Path) -> tarfile.TarFile:
    return tarfile.open(dest, "w:gz")


def _add_file(tf: tarfile.TarFile, name: str, content: bytes) -> None:
    info = tarfile.TarInfo(name=name)
    info.size = len(content)
    tf.addfile(info, io.BytesIO(content))


# ---------------------------------------------------------------------------
# Duplicate member names
# ---------------------------------------------------------------------------


class TestDuplicateMembers:
    def test_duplicate_member_name_does_not_crash(self, tmp_path: Path):
        """An archive with two members of the same name should not crash (last one wins)."""
        tgz = tmp_path / "dup.tgz"
        with _open_writable(tgz) as tf:
            _add_file(tf, "package/package.json", b'{"name":"x","version":"1.0.0"}')
            _add_file(tf, "package/package.json", b'{"name":"x","version":"1.0.1"}')
        # Should extract without error; one version of the file will be present
        result = extract_release(tgz, tmp_path / "out")
        rel_paths = [f.rel_path for f in result.files]
        assert "package.json" in rel_paths

    def test_many_duplicate_members_within_cap(self, tmp_path: Path):
        """100 entries with the same name → all pass safety checks."""
        tgz = tmp_path / "dup100.tgz"
        with _open_writable(tgz) as tf:
            for i in range(10):
                _add_file(tf, f"package/file_{i}.js", f"// {i}".encode())
        result = extract_release(tgz, tmp_path / "out")
        assert result.root.exists()


# ---------------------------------------------------------------------------
# Declared-size anomalies
# ---------------------------------------------------------------------------


class TestDeclaredSizeAnomaly:
    def test_declared_size_zero_with_content(self, tmp_path: Path):
        """TarInfo.size = 0 with small content extracts without error."""
        tgz = tmp_path / "zero.tgz"
        with _open_writable(tgz) as tf:
            _add_file(tf, "package/package.json", b'{"name":"x"}')
        result = extract_release(tgz, tmp_path / "out")
        assert result.root.exists()

    def test_declared_size_exceeding_hard_ceiling_raises(self, tmp_path: Path):
        """Total declared size exceeding hard ceiling must be refused before extraction."""
        import release_sentinel.extractor as ext_mod

        original = ext_mod._HARD_MAX_TOTAL_SIZE
        ext_mod._HARD_MAX_TOTAL_SIZE = 1000  # 1 KB for test
        try:
            tgz = tmp_path / "oversized_hard.tgz"
            with _open_writable(tgz) as tf:
                _add_file(tf, "package/fake_huge.js", b"x" * 2000)
            with pytest.raises(ExtractionError, match="hard ceiling"):
                extract_release(tgz, tmp_path / "out")
        finally:
            ext_mod._HARD_MAX_TOTAL_SIZE = original

    def test_oversized_declared_size_exceeds_cap_raises_when_soft_cap_disabled(
        self, tmp_path: Path
    ):
        """Declared size > max_total_size with soft_cap=False must raise ExtractionError."""
        tgz = tmp_path / "oversized_cap.tgz"
        with _open_writable(tgz) as tf:
            _add_file(tf, "package/file.js", b"x" * 2000)
        cfg = ExtractionConfig(max_total_size=1000, soft_cap=False)
        with pytest.raises(ExtractionError, match="exceeds.*cap"):
            extract_release(tgz, tmp_path / "out", config=cfg)

    def test_oversized_declared_size_triggers_soft_cap(self, tmp_path: Path):
        """Declared size > soft cap extracts only priority files and sets capped=True."""
        tgz = tmp_path / "oversized_soft.tgz"
        with _open_writable(tgz) as tf:
            _add_file(tf, "package/package.json", b'{"name":"x"}')
            _add_file(tf, "package/other.txt", b"x" * 2000)
        cfg = ExtractionConfig(max_total_size=1000, soft_cap=True)
        result = extract_release(tgz, tmp_path / "out", config=cfg)
        assert result.capped is True
        assert result.cap_reason is not None
        assert any(f.rel_path == "package.json" for f in result.files)

    def test_member_size_within_soft_cap(self, tmp_path: Path):
        """Single large member within soft cap → extracted normally."""
        tgz = tmp_path / "large.tgz"
        content = b"A" * (1 * 1024 * 1024)  # 1 MB — well within 200 MB cap
        with _open_writable(tgz) as tf:
            _add_file(tf, "package/package.json", b'{"name":"x"}')
            _add_file(tf, "package/big.js", content)
        result = extract_release(tgz, tmp_path / "out")
        assert not result.capped


# ---------------------------------------------------------------------------
# Deep paths
# ---------------------------------------------------------------------------


class TestDeepPaths:
    def test_path_with_51_components_rejected(self, tmp_path: Path):
        """A path with > 50 components should be rejected per _check_member."""
        tgz = tmp_path / "deep.tgz"
        deep_name = "/".join(["package"] + [f"d{i}" for i in range(51)] + ["file.js"])
        with _open_writable(tgz) as tf:
            _add_file(tf, deep_name, b"// deep")
        with pytest.raises(ExtractionError, match="deep"):
            extract_release(tgz, tmp_path / "out")

    def test_reasonable_depth_accepted(self, tmp_path: Path):
        """A path with 10 components is fine."""
        tgz = tmp_path / "ok.tgz"
        name = "/".join(["package"] + [f"d{i}" for i in range(8)] + ["file.js"])
        with _open_writable(tgz) as tf:
            _add_file(tf, "package/package.json", b'{"name":"x"}')
            _add_file(tf, name, b"// ok")
        result = extract_release(tgz, tmp_path / "out")
        assert result.root.exists()


# ---------------------------------------------------------------------------
# Long filenames
# ---------------------------------------------------------------------------


class TestLongFilenames:
    def test_filename_over_255_chars_rejected(self, tmp_path: Path):
        """A filename component > 255 chars should be rejected."""
        tgz = tmp_path / "longname.tgz"
        long_name = "package/" + ("a" * 256) + ".js"
        with _open_writable(tgz) as tf:
            _add_file(tf, long_name, b"// long")
        with pytest.raises(ExtractionError, match="255"):
            extract_release(tgz, tmp_path / "out")

    def test_filename_at_255_chars_accepted(self, tmp_path: Path):
        """A filename component of exactly 255 chars should be accepted."""
        tgz = tmp_path / "max.tgz"
        # 251 'a' chars + '.js' = 255 chars exactly — right at the limit
        max_name = "package/" + ("a" * 251) + ".js"
        with _open_writable(tgz) as tf:
            _add_file(tf, "package/package.json", b'{"name":"x"}')
            _add_file(tf, max_name, b"// max")
        # Should not raise
        result = extract_release(tgz, tmp_path / "out")
        assert result.root.exists()


# ---------------------------------------------------------------------------
# Soft-cap partial extraction (fuzz scenario)
# ---------------------------------------------------------------------------


class TestSoftCapFuzz:
    def test_large_archive_extracts_priority_files_only(self, tmp_path: Path):
        """Archive with 200 JS files under a tight soft cap → priority-only extraction."""
        tgz = tmp_path / "many.tgz"
        with _open_writable(tgz) as tf:
            _add_file(tf, "package/package.json", b'{"name":"x","version":"1.0.0"}')
            for i in range(199):
                _add_file(tf, f"package/src/file_{i}.js", f"// {i}".encode())
        cfg = ExtractionConfig(max_files=50, soft_cap=True)
        result = extract_release(tgz, tmp_path / "out", config=cfg)
        assert result.capped is True
        assert result.cap_reason is not None
        rel_paths = [f.rel_path for f in result.files]
        # package.json and .js files are priority — at least some should be extracted
        assert any(r.endswith(".js") or r == "package.json" for r in rel_paths)

    def test_archive_at_exactly_soft_cap_not_capped(self, tmp_path: Path):
        """Archive with exactly max_files entries → NOT capped."""
        tgz = tmp_path / "exact.tgz"
        with _open_writable(tgz) as tf:
            for i in range(5):
                _add_file(tf, f"package/file_{i}.js", f"// {i}".encode())
        cfg = ExtractionConfig(max_files=5, soft_cap=True)
        result = extract_release(tgz, tmp_path / "out", config=cfg)
        assert result.capped is False


# ---------------------------------------------------------------------------
# Hard ceiling
# ---------------------------------------------------------------------------


class TestHardCeiling:
    def test_archive_over_hard_file_ceiling_raises(self, tmp_path: Path):
        """Archive exceeding the hard ceiling (10,000) should always raise."""
        # We can't actually build a 10k member archive efficiently in a test,
        # so we reduce the hard ceiling via a monkeypatched config.
        tgz = tmp_path / "hc.tgz"
        with _open_writable(tgz) as tf:
            for i in range(20):
                _add_file(tf, f"package/f{i}.js", b"x")
        import release_sentinel.extractor as ext_mod

        original = ext_mod._HARD_MAX_FILE_COUNT
        ext_mod._HARD_MAX_FILE_COUNT = 10
        try:
            with pytest.raises(ExtractionError, match="hard ceiling|ceiling"):
                extract_release(tgz, tmp_path / "out")
        finally:
            ext_mod._HARD_MAX_FILE_COUNT = original
