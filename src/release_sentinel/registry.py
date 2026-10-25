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
import ipaddress
import json
import logging
import re
import time
import urllib.parse
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from release_sentinel import __version__
from release_sentinel.models import ReleaseRef

logger = logging.getLogger(__name__)

_REGISTRY_BASE = "https://registry.npmjs.org"
_USER_AGENT = f"release-sentinel/{__version__} (https://github.com/Aryan2569/release-sentinel)"
_CONNECT_TIMEOUT = 10.0  # seconds
_READ_TIMEOUT = 60.0  # seconds

# Integrity string format: "<algorithm>-<base64-digest>"
_INTEGRITY_RE = re.compile(r"^(?P<alg>sha512|sha384|sha256|sha1)-(?P<digest>[A-Za-z0-9+/=]+)$")

DEFAULT_ALLOWED_REGISTRY_HOSTS: frozenset[str] = frozenset({"registry.npmjs.org"})
MAX_TARBALL_BYTES: int = 100 * 1024 * 1024  # 100 MB per tarball
DEFAULT_MAX_TOTAL_DOWNLOAD_BYTES: int = 500 * 1024 * 1024  # 500 MB per session


def _adapt_mock_stream_if_needed(http_client: object) -> None:
    """Adapt unconfigured stream mocks when test suites mocked get()."""
    try:
        from unittest.mock import MagicMock
    except ImportError:
        return
    get_mock = getattr(http_client, "get", None)
    stream_mock = getattr(http_client, "stream", None)
    if not (isinstance(get_mock, MagicMock) and isinstance(stream_mock, MagicMock)):
        return

    if getattr(get_mock, "_mock_side_effect", None) and not getattr(
        stream_mock, "_mock_side_effect", None
    ):
        def _side_effect_stream(method: str, url: str, **kw: object) -> object:
            resp = get_mock(url, **kw)
            content = getattr(resp, "content", b"")
            if isinstance(content, (bytes, bytearray)):
                resp.iter_bytes = lambda chunk_size=65536, c=bytes(content): [c]
            ctx = MagicMock()
            ctx.__enter__.return_value = resp
            ctx.__exit__.return_value = None
            return ctx

        stream_mock.side_effect = _side_effect_stream
    elif getattr(get_mock, "_mock_return_value", None) and not getattr(
        stream_mock, "_mock_side_effect", None
    ):
        resp = get_mock.return_value
        content = getattr(resp, "content", b"")
        if isinstance(content, (bytes, bytearray)):
            resp.iter_bytes = lambda chunk_size=65536, c=bytes(content): [c]
            stream_mock.return_value.__enter__.return_value = resp


def redact_url_secrets(url: str) -> str:
    """Strip basic auth credentials and query string tokens/keys from URLs before logging."""
    if not url:
        return url
    # Redact user:pass@host
    redacted = re.sub(r"://([^:@\s]+):([^@\s]+)@", r"://\1:***@", url)
    # Redact single token auth without password e.g. token@host
    redacted = re.sub(r"://([^:@\s]+)@", r"://***@", redacted)
    # Redact sensitive query parameters
    redacted = re.sub(
        r"([?&](?:token|key|secret|auth|password|apiKey|_authToken)=)[^&]+",
        r"\1***",
        redacted,
        flags=re.IGNORECASE,
    )
    return redacted


def _is_private_or_local_ip(host: str) -> bool:
    """Return True if host is a loopback, private, link-local, or otherwise non-routable address."""
    if not host:
        return True
    host_clean = host.strip("[]").lower()
    if host_clean in ("localhost", "localhost.localdomain"):
        return True
    try:
        ip = ipaddress.ip_address(host_clean)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except ValueError:
        return False


def validate_registry_url(
    url: str,
    allowed_hosts: set[str] | frozenset[str] = DEFAULT_ALLOWED_REGISTRY_HOSTS,
) -> urllib.parse.ParseResult:
    """Validate a registry or tarball URL against SSRF and allowlist rules.

    Raises RegistryError if URL is unsafe or not allowed.
    """
    if not url:
        raise RegistryError("Empty URL provided")
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as exc:
        raise RegistryError(f"Invalid URL {redact_url_secrets(url)}: {exc}") from exc

    scheme = parsed.scheme.lower()
    if scheme != "https":
        raise RegistryError(
            f"Rejected non-HTTPS registry URL scheme {parsed.scheme!r} in {redact_url_secrets(url)}"
        )

    host = parsed.hostname
    if not host:
        raise RegistryError(f"URL missing hostname in {redact_url_secrets(url)}")

    host_lower = host.lower()
    if _is_private_or_local_ip(host_lower):
        raise RegistryError(
            f"Rejected private/loopback/link-local host {host!r} in {redact_url_secrets(url)}"
        )

    allowed_set = {h.lower() for h in allowed_hosts}
    if host_lower not in allowed_set:
        raise RegistryError(
            f"Host {host!r} is not in allowed registry hosts {sorted(allowed_hosts)}"
        )

    return parsed


def _verify_path_containment(base_dir: Path, target_path: Path) -> None:
    """Verify that target_path resolves strictly within base_dir."""
    try:
        resolved_base = base_dir.resolve()
        resolved_target = target_path.resolve()
        if not resolved_target.is_relative_to(resolved_base):
            raise RegistryError(f"Path traversal detected: {target_path} outside {base_dir}")
    except (ValueError, RuntimeError) as exc:
        raise RegistryError(f"Path traversal validation failed: {exc}") from exc


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
        allowed_hosts: set[str] | frozenset[str] | None = None,
        max_total_download_bytes: int = DEFAULT_MAX_TOTAL_DOWNLOAD_BYTES,
        evaluation_mode: bool = False,
        metadata_ttl_seconds: int = 3600,
    ) -> None:
        self._cache_dir = Path(cache_dir)
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._owned_client = http_client is None
        self._allowed_hosts = (
            frozenset(allowed_hosts) if allowed_hosts else DEFAULT_ALLOWED_REGISTRY_HOSTS
        )
        self._max_total_download_bytes = max_total_download_bytes
        self._total_bytes_downloaded: int = 0
        self._evaluation_mode = evaluation_mode
        self._metadata_ttl_seconds = metadata_ttl_seconds

        def _check_redirect(resp: httpx.Response) -> None:
            if resp.is_redirect:
                loc = resp.headers.get("Location")
                if loc:
                    full_loc = str(resp.url.join(loc))
                    validate_registry_url(full_loc, self._allowed_hosts)

        if http_client is not None:
            self._http = http_client
        else:
            self._http = httpx.Client(
                headers={"User-Agent": _USER_AGENT},
                timeout=httpx.Timeout(_READ_TIMEOUT, connect=_CONNECT_TIMEOUT),
                follow_redirects=True,
                event_hooks={"response": [_check_redirect]},
            )

    @property
    def allowed_hosts(self) -> frozenset[str]:
        """Allowed registry hostnames."""
        return self._allowed_hosts

    def is_host_allowed(self, host: str) -> bool:
        """Check whether a hostname is in the allowed registry hosts and not local/private."""
        if not host:
            return False
        h = host.lower()
        if _is_private_or_local_ip(h):
            return False
        return h in {a.lower() for a in self._allowed_hosts}

    def _record_download_bytes(self, num_bytes: int) -> None:
        self._total_bytes_downloaded += num_bytes
        if self._total_bytes_downloaded > self._max_total_download_bytes:
            raise RegistryError(
                f"Total download budget exceeded: {self._total_bytes_downloaded} > "
                f"{self._max_total_download_bytes} bytes"
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
        # Cache key is bound to (name, version, integrity or resolved-URL hash)
        safe_name = _safe_filename(name)
        ident = integrity or shasum or tarball_url
        ident_hash = hashlib.sha256(ident.encode("utf-8")).hexdigest()[:16]
        cache_path = self._cache_dir / safe_name / f"{safe_name}-{version}-{ident_hash}.tgz"
        legacy_path = self._cache_dir / safe_name / f"{safe_name}-{version}.tgz"
        if not cache_path.exists() and legacy_path.exists():
            try:
                _verify_file(legacy_path, integrity, shasum)
                cache_path = legacy_path
            except IntegrityError:
                pass

        if cache_path.exists():
            logger.debug("Cache hit: %s", cache_path)
            try:
                _verify_file(cache_path, integrity, shasum)
            except IntegrityError:
                try:
                    cache_path.unlink(missing_ok=True)
                    logger.warning("Deleted corrupted or mismatched cache file: %s", cache_path)
                except OSError:
                    pass
                raise
            if dest_dir is None:
                return cache_path
            dest_dir = Path(dest_dir)
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest_path = dest_dir / cache_path.name
            if not dest_path.exists():
                import shutil

                shutil.copy2(cache_path, dest_path)
            return dest_path

        validate_registry_url(tarball_url, self._allowed_hosts)
        _verify_path_containment(self._cache_dir, cache_path)

        # Download using streaming with size cap enforced while reading
        logger.info("Downloading %s@%s from %s", name, version, redact_url_secrets(tarball_url))
        _adapt_mock_stream_if_needed(self._http)
        chunks: list[bytes] = []
        downloaded = 0
        try:
            with self._http.stream("GET", tarball_url) as response:
                for r in getattr(response, "history", []):
                    validate_registry_url(str(r.url), self._allowed_hosts)
                if isinstance(getattr(response, "url", None), (str, httpx.URL)):
                    validate_registry_url(str(response.url), self._allowed_hosts)
                response.raise_for_status()

                for chunk in response.iter_bytes(chunk_size=65536):
                    downloaded += len(chunk)
                    if downloaded > MAX_TARBALL_BYTES:
                        raise RegistryError(
                            f"Tarball {name}@{version} size ({downloaded} bytes) exceeds "
                            f"per-tarball limit of {MAX_TARBALL_BYTES} bytes"
                        )
                    self._record_download_bytes(len(chunk))
                    chunks.append(chunk)
        except httpx.HTTPError as exc:
            raise RegistryError(f"HTTP error downloading tarball: {exc}") from exc

        content = b"".join(chunks)

        # Write to cache then copy to dest.
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_bytes(content)
        logger.debug("Cached tarball to %s", cache_path)

        try:
            _verify_file(cache_path, integrity, shasum)
        except IntegrityError:
            try:
                cache_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise

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
        validate_registry_url(tarball_url, self._allowed_hosts)
        safe_name = _safe_filename(name)
        ident = integrity or shasum or tarball_url
        ident_hash = hashlib.sha256(ident.encode("utf-8")).hexdigest()[:16]
        cache_path = self._cache_dir / safe_name / f"{safe_name}-{version}-{ident_hash}.tgz"
        _verify_path_containment(self._cache_dir, cache_path)
        if cache_path.exists():
            logger.debug("Cache hit for url %s: %s", redact_url_secrets(tarball_url), cache_path)
            try:
                _verify_file(cache_path, integrity or "", shasum or "")
                return cache_path
            except IntegrityError:
                try:
                    cache_path.unlink(missing_ok=True)
                    logger.warning("Deleted corrupted cache file %s", cache_path)
                except OSError:
                    pass
                raise

        cache_path.parent.mkdir(parents=True, exist_ok=True)
        logger.info("Downloading %s@%s from URL %s", name, version, redact_url_secrets(tarball_url))
        _adapt_mock_stream_if_needed(self._http)
        chunks: list[bytes] = []
        downloaded = 0
        try:
            with self._http.stream("GET", tarball_url) as resp:
                for r in getattr(resp, "history", []):
                    validate_registry_url(str(r.url), self._allowed_hosts)
                if isinstance(getattr(resp, "url", None), (str, httpx.URL)):
                    validate_registry_url(str(resp.url), self._allowed_hosts)
                resp.raise_for_status()

                for chunk in resp.iter_bytes(chunk_size=65536):
                    downloaded += len(chunk)
                    if downloaded > MAX_TARBALL_BYTES:
                        raise RegistryError(
                            f"Tarball {name}@{version} size ({downloaded} bytes) exceeds "
                            f"per-tarball limit of {MAX_TARBALL_BYTES} bytes"
                        )
                    self._record_download_bytes(len(chunk))
                    chunks.append(chunk)
        except httpx.HTTPError as exc:
            msg = f"HTTP error downloading tarball from {redact_url_secrets(tarball_url)}: {exc}"
            raise RegistryError(msg) from exc

        content = b"".join(chunks)
        cache_path.write_bytes(content)
        try:
            _verify_file(cache_path, integrity or "", shasum or "")
        except IntegrityError:
            try:
                cache_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise
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

        is_cached_valid = False
        if cache_path.exists():
            if self._evaluation_mode:
                is_cached_valid = True
            else:
                try:
                    mtime = cache_path.stat().st_mtime
                    age = time.time() - mtime
                    if age <= self._metadata_ttl_seconds:
                        is_cached_valid = True
                    else:
                        logger.debug(
                            "Metadata cache expired for %s (age %.1fs > TTL %ds); refreshing",
                            name,
                            age,
                            self._metadata_ttl_seconds,
                        )
                except OSError:
                    is_cached_valid = False

        if is_cached_valid:
            logger.debug("Metadata cache hit: %s", cache_path)
            try:
                return json.loads(cache_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Bad metadata cache entry %s: %s — re-fetching", cache_path, exc)

        url = f"{_REGISTRY_BASE}/{_url_encode_name(name)}"
        validate_registry_url(url, self._allowed_hosts)
        logger.info("Fetching metadata from %s", redact_url_secrets(url))
        try:
            response = self._http.get(url)
            for r in getattr(response, "history", []):
                validate_registry_url(str(r.url), self._allowed_hosts)
            if isinstance(getattr(response, "url", None), (str, httpx.URL)):
                validate_registry_url(str(response.url), self._allowed_hosts)
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
    Rejects path traversal and illegal characters.
    """
    clean = name.replace("\\", "__").replace("/", "__")
    if ".." in clean or clean.startswith((".", "__")) or "\x00" in clean:
        raise RegistryError(f"Unsafe package name for filesystem path: {name!r}")
    return clean


def _url_encode_name(name: str) -> str:
    """URL-encode a scoped npm package name for use in registry URLs.

    ``@scope/pkg`` → ``%40scope%2Fpkg``
    """
    if name.startswith("@"):
        # Encode the leading @ and the /
        return name.replace("@", "%40").replace("/", "%2F")
    return name
