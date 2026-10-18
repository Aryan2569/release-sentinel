"""Tests for the npm registry client (registry.py).

Network-free tests use a mock httpx.Client.
Network tests are marked @pytest.mark.network and skipped by default.
Run with: pytest -m network
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest

from release_sentinel.registry import (
    IntegrityError,
    NpmRegistryClient,
    VersionNotFoundError,
    _filter_metadata_by_time,
    _parse_npm_time,
    _verify_integrity,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_fake_packument(versions: list[str], base_ts: str = "2024-01-01T00:00:00Z") -> dict:
    """Build a minimal packument with the given versions published 1 day apart."""
    from datetime import timedelta

    base = datetime.fromisoformat(base_ts.replace("Z", "+00:00"))
    time_map = {"created": base_ts}
    versions_map = {}
    for i, v in enumerate(versions):
        ts = (base + timedelta(days=i)).isoformat().replace("+00:00", "Z")
        time_map[v] = ts
        versions_map[v] = {
            "name": "test-pkg",
            "version": v,
            "dist": {
                "tarball": f"https://registry.npmjs.org/test-pkg/-/test-pkg-{v}.tgz",
                "integrity": "sha512-AAAA==",
            },
            "scripts": {},
            "dependencies": {},
        }
    time_map["modified"] = time_map[versions[-1]]
    return {"name": "test-pkg", "time": time_map, "versions": versions_map}


def make_fake_tarball_bytes(name: str = "pkg", version: str = "1.0.0") -> bytes:
    """Create a minimal in-memory tarball and return its bytes."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        pkg_json = json.dumps({"name": name, "version": version}).encode()
        info = tarfile.TarInfo(name="package/package.json")
        info.size = len(pkg_json)
        tf.addfile(info, io.BytesIO(pkg_json))
    return buf.getvalue()


def make_mock_http_client(packument: dict, tarball_bytes: bytes) -> httpx.Client:
    """Return a mock httpx.Client that returns *packument* for metadata requests
    and *tarball_bytes* for tarball download requests."""
    mock = MagicMock(spec=httpx.Client)

    def get_side_effect(url: str, **kwargs):
        resp = MagicMock(spec=httpx.Response)
        resp.raise_for_status.return_value = None
        if "/-/" in url or url.endswith(".tgz"):
            resp.content = tarball_bytes
            resp.json.side_effect = ValueError("binary response")
        else:
            resp.json.return_value = packument
            resp.content = json.dumps(packument).encode()
        return resp

    mock.get.side_effect = get_side_effect
    return mock


# ---------------------------------------------------------------------------
# Unit tests (no network)
# ---------------------------------------------------------------------------


class TestFilterMetadataByTime:
    def test_future_versions_filtered(self):
        packument = make_fake_packument(["1.0.0", "1.0.1", "1.0.2"])
        # 1.0.0 published 2024-01-01T00:00:00Z, 1.0.1 published 2024-01-02T00:00:00Z
        # as_of is noon on 2024-01-01 — only 1.0.0 should be visible
        as_of = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
        filtered = _filter_metadata_by_time(packument, as_of)
        assert "1.0.0" in filtered["versions"]
        assert "1.0.1" not in filtered["versions"]
        assert "1.0.2" not in filtered["versions"]

    def test_all_versions_included_when_as_of_is_future(self):
        packument = make_fake_packument(["1.0.0", "1.0.1", "1.0.2"])
        as_of = datetime(2030, 1, 1, tzinfo=UTC)
        filtered = _filter_metadata_by_time(packument, as_of)
        assert set(filtered["versions"].keys()) == {"1.0.0", "1.0.1", "1.0.2"}

    def test_no_versions_before_as_of(self):
        packument = make_fake_packument(["1.0.0"])
        as_of = datetime(2020, 1, 1, tzinfo=UTC)
        filtered = _filter_metadata_by_time(packument, as_of)
        assert filtered["versions"] == {}

    def test_naive_as_of_treated_as_utc(self):
        packument = make_fake_packument(["1.0.0"])
        as_of = datetime(2030, 1, 1)  # no tzinfo
        filtered = _filter_metadata_by_time(packument, as_of)
        assert "1.0.0" in filtered["versions"]


class TestParseNpmTime:
    def test_z_suffix(self):
        dt = _parse_npm_time("2024-01-15T12:00:00Z")
        assert dt.tzinfo is not None
        assert dt.year == 2024

    def test_offset_suffix(self):
        dt = _parse_npm_time("2024-01-15T12:00:00+00:00")
        assert dt.year == 2024


class TestVerifyIntegrity:
    def test_valid_sha512(self, tmp_path: Path):
        data = b"hello integrity"
        path = tmp_path / "test.tgz"
        path.write_bytes(data)
        digest = base64.b64encode(hashlib.sha512(data).digest()).decode()
        _verify_integrity(path, f"sha512-{digest}")  # should not raise

    def test_bad_hash_raises(self, tmp_path: Path):
        data = b"hello"
        path = tmp_path / "test.tgz"
        path.write_bytes(data)
        with pytest.raises(IntegrityError, match="failed"):
            _verify_integrity(path, "sha512-AAAAAAAAAAAAAAAA==")

    def test_bad_format_raises(self, tmp_path: Path):
        path = tmp_path / "test.tgz"
        path.write_bytes(b"x")
        with pytest.raises(IntegrityError, match="Unrecognised"):
            _verify_integrity(path, "md5-abc123")


class TestNpmRegistryClientMocked:
    def _make_client(
        self, tmp_path: Path, packument: dict, tarball_bytes: bytes
    ) -> NpmRegistryClient:
        mock_http = make_mock_http_client(packument, tarball_bytes)
        return NpmRegistryClient(cache_dir=tmp_path / "cache", http_client=mock_http)

    def test_get_release_ref_returns_correct_version(self, tmp_path: Path):
        packument = make_fake_packument(["1.0.0", "1.0.1"])
        tarball = make_fake_tarball_bytes()
        client = self._make_client(tmp_path, packument, tarball)
        ref = client.get_release_ref("test-pkg", "1.0.0", datetime(2030, 1, 1, tzinfo=UTC))
        assert ref.version == "1.0.0"
        assert ref.name == "test-pkg"

    def test_version_after_as_of_raises(self, tmp_path: Path):
        packument = make_fake_packument(["1.0.0", "1.0.1", "1.0.2"])
        tarball = make_fake_tarball_bytes()
        client = self._make_client(tmp_path, packument, tarball)
        # as_of is before 1.0.1 was published (day 1 = 2024-01-02)
        as_of = datetime(2024, 1, 1, 12, tzinfo=UTC)
        with pytest.raises(VersionNotFoundError):
            client.get_release_ref("test-pkg", "1.0.1", as_of)

    def test_download_tarball_uses_cache_on_second_call(self, tmp_path: Path):
        packument = make_fake_packument(["1.0.0"])
        tarball_bytes = make_fake_tarball_bytes()

        # Patch integrity verification to skip (fake hash)
        with patch("release_sentinel.registry._verify_integrity"):
            client = self._make_client(tmp_path, packument, tarball_bytes)
            as_of = datetime(2030, 1, 1, tzinfo=UTC)
            path1 = client.download_tarball("test-pkg", "1.0.0", as_of, tmp_path / "dl1")
            # Second call should hit cache (same mock, but get() called only for metadata)
            path2 = client.download_tarball("test-pkg", "1.0.0", as_of, tmp_path / "dl2")
            # No additional tarball download (only metadata re-check)
            assert path1.name == path2.name

    def test_metadata_cached_to_disk(self, tmp_path: Path):
        packument = make_fake_packument(["1.0.0"])
        tarball_bytes = make_fake_tarball_bytes()
        client = self._make_client(tmp_path, packument, tarball_bytes)
        as_of = datetime(2030, 1, 1, tzinfo=UTC)
        client.get_metadata("test-pkg", as_of)
        cache_file = tmp_path / "cache" / "test-pkg" / "packument.json"
        assert cache_file.exists()

    def test_shasum_fallback_when_integrity_absent(self, tmp_path: Path):
        packument = make_fake_packument(["1.0.0"])
        tarball_bytes = make_fake_tarball_bytes()
        # Compute real SHA-1
        expected_sha1 = hashlib.sha1(tarball_bytes).hexdigest()  # noqa: S324
        # Remove integrity, add shasum
        packument["versions"]["1.0.0"]["dist"] = {
            "tarball": "https://registry.npmjs.org/test-pkg/-/test-pkg-1.0.0.tgz",
            "shasum": expected_sha1,
        }
        client = self._make_client(tmp_path, packument, tarball_bytes)
        as_of = datetime(2030, 1, 1, tzinfo=UTC)
        p = client.download_tarball("test-pkg", "1.0.0", as_of, tmp_path / "dl_shasum")
        assert p.exists()

    def test_shasum_mismatch_raises_integrity_error(self, tmp_path: Path):
        packument = make_fake_packument(["1.0.0"])
        tarball_bytes = make_fake_tarball_bytes()
        packument["versions"]["1.0.0"]["dist"] = {
            "tarball": "https://registry.npmjs.org/test-pkg/-/test-pkg-1.0.0.tgz",
            "shasum": "0123456789abcdef0123456789abcdef01234567",
        }
        client = self._make_client(tmp_path, packument, tarball_bytes)
        as_of = datetime(2030, 1, 1, tzinfo=UTC)
        with pytest.raises(IntegrityError, match="shasum check failed"):
            client.download_tarball("test-pkg", "1.0.0", as_of, tmp_path / "dl_fail")


# ---------------------------------------------------------------------------
# Network tests (skipped by default)
# ---------------------------------------------------------------------------


@pytest.mark.network
def test_real_registry_fetch_is_time_filtered(tmp_path: Path):
    """Fetch real metadata for 'is-odd' and verify as_of filtering."""
    client = NpmRegistryClient(cache_dir=tmp_path / "cache")
    # Use a very early as_of — should see no versions
    as_of_early = datetime(2010, 1, 1, tzinfo=UTC)
    meta = client.get_metadata("is-odd", as_of_early)
    assert meta["versions"] == {}, "Expected no versions before 2010"

    # Use a recent as_of — should see at least one version
    as_of_recent = datetime(2030, 1, 1, tzinfo=UTC)
    meta_recent = client.get_metadata("is-odd", as_of_recent)
    assert len(meta_recent["versions"]) > 0


@pytest.mark.network
def test_real_tarball_download_and_integrity(tmp_path: Path):
    """Download a real tarball, verify integrity, and check it can be extracted."""
    from release_sentinel.extractor import extract_release

    client = NpmRegistryClient(cache_dir=tmp_path / "cache")
    as_of = datetime(2030, 1, 1, tzinfo=UTC)
    tgz = client.download_tarball("is-odd", "3.0.1", as_of, tmp_path / "dl")
    assert tgz.exists()
    result = extract_release(tgz, tmp_path / "extracted")
    assert result.root.exists()
    rel_paths = [f.rel_path for f in result.files]
    assert "package.json" in rel_paths
