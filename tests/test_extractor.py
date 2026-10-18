"""Tests for safe tarball extraction (extractor.py).

All tests use synthetic tarballs built in memory.  No network calls.
"""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest
from tests.conftest import make_tarball

from release_sentinel.extractor import ExtractionError, extract_release


class TestExtractRelease:
    def test_basic_extraction(self, tmp_path: Path, old_tarball: Path):
        result = extract_release(old_tarball, tmp_path / "out")
        assert result.root.exists()
        rel_paths = [f.rel_path for f in result.files]
        assert "package.json" in rel_paths
        assert "index.js" in rel_paths

    def test_total_size_is_nonzero(self, tmp_path: Path, old_tarball: Path):
        result = extract_release(old_tarball, tmp_path / "out")
        assert result.total_size > 0

    def test_file_count(self, tmp_path: Path, old_tarball: Path):
        result = extract_release(old_tarball, tmp_path / "out")
        assert len(result.files) == 2  # package.json + index.js


class TestPathTraversalRejection:
    def _make_bad_tarball(self, dest: Path, member_name: str) -> Path:
        dest.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(dest, "w:gz") as tf:
            data = b"evil content"
            info = tarfile.TarInfo(name=member_name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        return dest

    def test_path_traversal_rejected(self, tmp_path: Path):
        tgz = self._make_bad_tarball(tmp_path / "bad.tgz", "package/../../etc/passwd")
        with pytest.raises(ExtractionError, match="traversal"):
            extract_release(tgz, tmp_path / "out")

    def test_absolute_path_rejected(self, tmp_path: Path):
        tgz = self._make_bad_tarball(tmp_path / "bad_abs.tgz", "/etc/passwd")
        with pytest.raises(ExtractionError, match="absolute"):
            extract_release(tgz, tmp_path / "out")


class TestSymlinkRejection:
    def _make_symlink_tarball(self, dest: Path) -> Path:
        dest.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(dest, "w:gz") as tf:
            # Regular file first
            data = b"legit"
            info = tarfile.TarInfo(name="package/legit.js")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
            # Symlink
            link = tarfile.TarInfo(name="package/evil_link")
            link.type = tarfile.SYMTYPE
            link.linkname = "/etc/passwd"
            tf.addfile(link)
        return dest

    def test_symlink_rejected(self, tmp_path: Path):
        tgz = self._make_symlink_tarball(tmp_path / "sym.tgz")
        with pytest.raises(ExtractionError, match="symlink"):
            extract_release(tgz, tmp_path / "out")


class TestHardlinkRejection:
    def _make_hardlink_tarball(self, dest: Path) -> Path:
        dest.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(dest, "w:gz") as tf:
            data = b"legit"
            info = tarfile.TarInfo(name="package/legit.js")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
            link = tarfile.TarInfo(name="package/hard_link")
            link.type = tarfile.LNKTYPE
            link.linkname = "package/legit.js"
            tf.addfile(link)
        return dest

    def test_hardlink_rejected(self, tmp_path: Path):
        tgz = self._make_hardlink_tarball(tmp_path / "hard.tgz")
        with pytest.raises(ExtractionError, match="hardlink"):
            extract_release(tgz, tmp_path / "out")


class TestFileCap:
    def test_file_count_hard_cap_aborts(self, tmp_path: Path):
        """501 files with soft_cap=False → ExtractionError."""
        tgz = tmp_path / "big.tgz"
        files = {f"file_{i}.js": f"// {i}" for i in range(501)}
        make_tarball(tgz, files)
        from release_sentinel.extractor import ExtractionConfig

        cfg = ExtractionConfig(max_files=500, soft_cap=False)
        with pytest.raises(ExtractionError, match="members|files"):
            extract_release(tgz, tmp_path / "out", config=cfg)

    def test_file_count_soft_cap_partial_extraction(self, tmp_path: Path):
        """Many files with soft_cap=True → capped=True, priority files extracted."""
        tgz = tmp_path / "big.tgz"
        files = {f"file_{i}.js": f"// {i}" for i in range(499)}
        files["package.json"] = '{"name":"x","version":"1.0.0"}'
        make_tarball(tgz, files)
        from release_sentinel.extractor import ExtractionConfig

        cfg = ExtractionConfig(max_files=100, soft_cap=True)
        result = extract_release(tgz, tmp_path / "out", config=cfg)
        assert result.capped is True
        assert result.cap_reason is not None
        rel_paths = [f.rel_path for f in result.files]
        assert "package.json" in rel_paths


class TestSizeCap:
    def test_total_size_hard_cap_aborts(self, tmp_path: Path):
        """51 MB with soft_cap=False → ExtractionError."""
        tgz = tmp_path / "huge.tgz"
        big_content = b"x" * (51 * 1024 * 1024)
        with tarfile.open(tgz, "w:gz") as tf:
            info = tarfile.TarInfo(name="package/big.bin")
            info.size = len(big_content)
            tf.addfile(info, io.BytesIO(big_content))
        from release_sentinel.extractor import ExtractionConfig

        cfg = ExtractionConfig(max_total_size=50 * 1024 * 1024, soft_cap=False)
        with pytest.raises(ExtractionError, match="size"):
            extract_release(tgz, tmp_path / "out", config=cfg)

