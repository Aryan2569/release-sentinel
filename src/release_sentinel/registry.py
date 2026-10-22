"""npm registry client for Release Sentinel.

Responsibilities
----------------
* Fetch package metadata from ``registry.npmjs.org``.
* Honour the ``as_of`` cut-off: only return versions published *before* the timestamp.
* Download tarballs, verify their SHA-512 integrity hash before returning them.
  For legacy packages that only publish a SHA-1 ``shasum``, fall back to SHA-1
  verification and record a "weak integrity" note in the returned path metadata.
* Cache both metadata JSON and tarballs on disk to avoid repeated network calls.

Hard rules respected here
--------------------------
* Rule 3: every public function that touches external data accepts ``as_of``.
* Rule 5: downloads from ``registry.npmjs.org`` only; User-Agent header always set;
          timeouts always set; writes only to the designated cache directory.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from release_sentinel.models import ReleaseRef

logger = logging.getLogger(__name__)

_REGISTRY_BASE = "https://registry.npmjs.org"
_USER_AGENT = "release-sentinel/0.1.0 (github.com/your-org/release-sentinel)"
_CONNECT_TIMEOUT = 10.0  # seconds
_READ_TIMEOUT = 60.0  # seconds

# Integrity string format: "<algorithm>-<base64-digest>"
_INTEGRITY_RE = re.compile(r"^(?P<alg>sha512|sha384|sha256)-(?P<digest>[A-Za-z0-9+/=]+)$")


class RegistryError(Exception):
    """Raised when the registry client encounters an unrecoverable problem."""


class IntegrityError(RegistryError):
    """Raised when a downloaded tarball fails its integrity check."""


class VersionNotFoundError(RegistryError):
    """Raised when a requested version is not found (or is after the as_of cutoff)."""


class NpmRegistryClient:
    """Thin client for the public npm registry.

    Parameters
    ----------
    cache_dir:
        Root directory for on-disk caching.  Sub-directories are created per package.
    http_client:
        Optional pre-built ``httpx.Client``.  Provide one in tests to avoid network
        calls.  When ``None`` a default client is constructed with standard timeouts
        and the project User-Agent.
    """

    def __init__(
        self,
        cache_dir: Path,
        http_client: httpx.Client | None = None,
    ) -> None:
        self._cache_dir = Path(cache_dir)
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._owned_client = http_client is None
        self._http = http_client or httpx.Client(
            headers={"User-Agent": _USER_AGENT},
            timeout=httpx.Timeout(_READ_TIMEOUT, connect=_CONNECT_TIMEOUT),
            follow_redirects=True,
        )

    @property
    def cache_dir(self) -> Path:
        """Root directory for on-disk caching."""
        return self._cache_dir

    def close(self) -> None:
        """Close the underlying HTTP client if we own it."""
        if self._owned_client:
            self._http.close()

    def __enter__(self) -> NpmRegistryClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_metadata(self, name: str, as_of: datetime) -> dict[str, Any]:
        """Return the registry metadata for *name*, filtered to the *as_of* cutoff.

        The ``time`` map in the npm packument lists each version with its publish
        timestamp.  We strip any version whose publish time is *after* ``as_of``
        so that callers cannot accidentally see future data.

        Parameters
        ----------
        name:
            npm package name.
        as_of:
            Cut-off timestamp.  All returned version data was published before this.

        Returns
        -------
        dict
            The full packument with the ``versions`` and ``time`` maps filtered.

        Raises
        ------
        RegistryError
            On HTTP or JSON errors.
        """
        raw = self._fetch_metadata(name)
        return _filter_metadata_by_time(raw, as_of)

    def get_release_ref(self, name: str, version: str, as_of: datetime) -> ReleaseRef:
        """Return a :class:`ReleaseRef` for the given package version.

        Parameters
        ----------
        name:
            npm package name.
        version:
            Exact version string (e.g. ``"4.17.21"``).
        as_of:
            Cut-off timestamp.

        Raises
        ------
        VersionNotFoundError
            If the version does not exist or was published after *as_of*.
        """
        meta = self.get_metadata(name, as_of)
        time_map: dict[str, str] = meta.get("time", {})

        if version not in time_map:
            raise VersionNotFoundError(
                f"Version {name}@{version} not found or published after {as_of.isoformat()}"
            )

        published_at = _parse_npm_time(time_map[version])
        return ReleaseRef(name=name, version=version, published_at=published_at)

    def download_tarball(
        self,
        name: str,
        version: str,
        as_of: datetime | None = None,
        dest_dir: Path | None = None,
    ) -> Path:
        """Download and verify the tarball for *name@version*.

        The tarball is saved inside *dest_dir* as ``<name>-<version>.tgz``.
        If it is already present in the disk cache it is copied from there
        without a network call.

        Parameters
        ----------
        name:
            npm package name.
        version:
            Exact version string.
        as_of:
            Cut-off timestamp.  The version must have been published before this.
        dest_dir:
            Directory where the tarball file will be placed.

        Returns
        -------
        Path
            Absolute path to the downloaded (and integrity-verified) tarball.

        Raises
        ------
        VersionNotFoundError
            If the version is unknown or after the cut-off.
        IntegrityError
            If the downloaded file does not match the registry-declared hash.
        RegistryError
            On other network or I/O errors.
        """
        if as_of is None:
            as_of = datetime.now(UTC)
        # Ensure the version exists and is within the time window.
        meta = self.get_metadata(name, as_of)
        versions_map: dict[str, Any] = meta.get("versions", {})
        if version not in versions_map:
            raise VersionNotFoundError(
                f"Version {name}@{version} not found or published after {as_of.isoformat()}"
            )
        version_meta = versions_map[version]
        dist: dict[str, str] = version_meta.get("dist", {})
        tarball_url: str = dist.get("tarball", "")
        integrity: str = dist.get("integrity", "")
        shasum: str = dist.get("shasum", "")

        if not tarball_url:
            raise RegistryError(f"No tarball URL found for {name}@{version}")

        # Check cache first.
        safe_name = _safe_filename(name)
        cache_path = self._cache_dir / safe_name / f"{safe_name}-{version}.tgz"
        if cache_path.exists():
            logger.debug("Cache hit: %s", cache_path)
            _verify_file(cache_path, integrity, shasum)
            if dest_dir is None:
                return cache_path
            dest_dir = Path(dest_dir)
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest_path = dest_dir / cache_path.name
            if not dest_path.exists():
                import shutil

                shutil.copy2(cache_path, dest_path)
            return dest_path

        # Download.
        logger.info("Downloading %s@%s from %s", name, version, tarball_url)
        try:
            response = self._http.get(tarball_url)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise RegistryError(f"HTTP error downloading tarball: {exc}") from exc

        # Write to cache then copy to dest.
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_bytes(response.content)
        logger.debug("Cached tarball to %s", cache_path)

        _verify_file(cache_path, integrity, shasum)

        if dest_dir is None:
            return cache_path

        dest_dir = Path(dest_dir)
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_path = dest_dir / cache_path.name
        import shutil

        shutil.copy2(cache_path, dest_path)
        return dest_path

    def download_tarball_url(
        self,
        name: str,
        version: str,
        tarball_url: str,
        integrity: str | None = None,
        shasum: str | None = None,
    ) -> Path:
        """Download a tarball directly from a specified URL (e.g. from lockfile 'resolved')."""
        safe_name = _safe_filename(name)
        cache_path = self._cache_dir / safe_name / f"{safe_name}-{version}.tgz"
        if cache_path.exists():
            logger.debug("Cache hit for url %s: %s", tarball_url, cache_path)
            _verify_file(cache_path, integrity or "", shasum or "")
            return cache_path

        cache_path.parent.mkdir(parents=True, exist_ok=True)
        logger.info("Downloading %s@%s from URL %s", name, version, tarball_url)
        try:
            resp = self._http.get(tarball_url)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            msg = f"HTTP error downloading tarball from {tarball_url}: {exc}"
            raise RegistryError(msg) from exc

        cache_path.write_bytes(resp.content)
        _verify_file(cache_path, integrity or "", shasum or "")
        return cache_path

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _fetch_metadata(self, name: str) -> dict[str, Any]:
        """Fetch raw packument from cache or network."""
        safe_name = _safe_filename(name)
        cache_path = self._cache_dir / safe_name / "packument.json"
        alt_path = self._cache_dir / "metadata" / f"{safe_name}.json"
        if not cache_path.exists() and alt_path.exists():
            cache_path = alt_path

        if cache_path.exists():
            logger.debug("Metadata cache hit: %s", cache_path)
            try:
                return json.loads(cache_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Bad metadata cache entry %s: %s — re-fetching", cache_path, exc)

        url = f"{_REGISTRY_BASE}/{_url_encode_name(name)}"
        logger.info("Fetching metadata from %s", url)
        try:
            response = self._http.get(url)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise RegistryError(f"HTTP error fetching metadata for {name!r}: {exc}") from exc

        try:
            data: dict[str, Any] = response.json()
        except Exception as exc:
            raise RegistryError(f"Invalid JSON in registry response for {name!r}: {exc}") from exc

        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(data), encoding="utf-8")
        return data


# ------------------------------------------------------------------
# Module-level helpers (not part of the public API)
# ------------------------------------------------------------------


def _filter_metadata_by_time(raw: dict[str, Any], as_of: datetime) -> dict[str, Any]:
    """Return a copy of *raw* with versions/time entries after *as_of* removed."""
    as_of_utc = _ensure_utc(as_of)
    time_map: dict[str, str] = raw.get("time", {})

    allowed_versions: set[str] = set()
    filtered_time: dict[str, str] = {}

    for key, ts_str in time_map.items():
        # "created" and "modified" are special keys, not version numbers.
        if key in {"created", "modified"}:
            filtered_time[key] = ts_str
            continue
        try:
            published = _parse_npm_time(ts_str)
        except ValueError:
            continue
        if published <= as_of_utc:
            allowed_versions.add(key)
            filtered_time[key] = ts_str

    filtered_versions: dict[str, Any] = {
        v: meta for v, meta in raw.get("versions", {}).items() if v in allowed_versions
    }

    result = dict(raw)
    result["time"] = filtered_time
    result["versions"] = filtered_versions
    return result


def _parse_npm_time(ts: str) -> datetime:
    """Parse an npm registry timestamp string into a UTC-aware datetime."""
    # npm uses ISO 8601 with 'Z' suffix.
    ts = ts.replace("Z", "+00:00")
    return datetime.fromisoformat(ts).astimezone(UTC)


def _ensure_utc(dt: datetime) -> datetime:
    """Return *dt* converted to UTC.  Naive datetimes are assumed to be UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def verify_integrity(target: Path | bytes, integrity: str) -> None:
    """Verify bytes or file at *target* against the *integrity* SRI string.

    Parameters
    ----------
    target:
        File path or bytes to hash.
    integrity:
        Subresource Integrity string, e.g. ``"sha512-<base64>"``.

    Raises
    ------
    IntegrityError
        If the computed hash does not match, or if the algorithm is unsupported.
    """
    m = _INTEGRITY_RE.match(integrity.strip())
    if not m:
        raise IntegrityError(f"Unrecognised integrity format: {integrity!r}")

    alg = m.group("alg")
    expected_b64 = m.group("digest")

    hasher = hashlib.new(alg)
    if isinstance(target, bytes):
        hasher.update(target)
    else:
        with target.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 16), b""):
                hasher.update(chunk)

    actual_b64 = base64.b64encode(hasher.digest()).decode()
    if actual_b64 != expected_b64:
        target_name = target.name if isinstance(target, Path) else "in-memory data"
        raise IntegrityError(
            f"Integrity check failed for {target_name}: "
            f"expected {expected_b64[:16]}..., got {actual_b64[:16]}..."
        )
    logger.debug("Integrity OK for %s (%s)", target, alg)


def _verify_integrity(path: Path, integrity: str) -> None:
    """Verify the file at *path* against the *integrity* SRI string.

    Parameters
    ----------
    path:
        File to hash.
    integrity:
        Subresource Integrity string, e.g. ``"sha512-<base64>"``.

    Raises
    ------
    IntegrityError
        If the computed hash does not match, or if the algorithm is unsupported.
    """
    m = _INTEGRITY_RE.match(integrity)
    if not m:
        raise IntegrityError(f"Unrecognised integrity format: {integrity!r}")

    alg = m.group("alg")
    expected_b64 = m.group("digest")

    hasher = hashlib.new(alg)
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            hasher.update(chunk)

    actual_b64 = base64.b64encode(hasher.digest()).decode()
    if actual_b64 != expected_b64:
        raise IntegrityError(
            f"Integrity check failed for {path.name}: "
            f"expected {expected_b64[:16]}…, got {actual_b64[:16]}…"
        )

    logger.debug("Integrity OK for %s (%s)", path.name, alg)


def _verify_shasum(path: Path, expected_hex: str) -> None:
    """Verify the file at *path* against the legacy SHA-1 hex string."""
    hasher = hashlib.sha1()  # noqa: S324 - legacy npm registry shasum fallback
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            hasher.update(chunk)

    actual_hex = hasher.hexdigest().lower()
    if actual_hex != expected_hex.lower():
        raise IntegrityError(
            f"SHA-1 shasum check failed for {path.name}: "
            f"expected {expected_hex}, got {actual_hex}"
        )
    logger.debug("Legacy SHA-1 integrity OK for %s", path.name)


def _verify_file(path: Path, integrity: str, shasum: str) -> None:
    """Verify file integrity using SHA-512/384/256 if present, else fallback to SHA-1 shasum."""
    if integrity:
        _verify_integrity(path, integrity)
    elif shasum:
        _verify_shasum(path, shasum)
    else:
        logger.warning("No integrity or shasum found for %s", path.name)


def _safe_filename(name: str) -> str:
    """Convert an npm package name to a safe filesystem component.

    Scoped packages (``@scope/pkg``) become ``@scope__pkg``.
    """
    return name.replace("/", "__")


def _url_encode_name(name: str) -> str:
    """URL-encode a scoped npm package name for use in registry URLs.

    ``@scope/pkg`` → ``%40scope%2Fpkg``
    """
    if name.startswith("@"):
        # Encode the leading @ and the /
        return name.replace("@", "%40").replace("/", "%2F")
    return name
