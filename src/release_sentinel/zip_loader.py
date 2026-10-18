"""In-memory loader for encrypted ZIP archives (Release Sentinel Stage 3a).

Hard rules enforced here (Rule 2 and Rule 7):
- Rule 7: Real malicious samples stay in their encrypted ZIPs at rest.
          Never extract them to disk (read members in memory only).
          Never write sample contents to disk or temp directories.
- Rule 2:
  - Reject absolute paths (starting with / or Windows drive letter).
  - Reject path traversal (components containing "..").
  - Reject symlinks.
  - Hard ceilings: abort at 10 000 members or 500 MB.
  - Zip bomb check: member uncompressed-to-compressed ratio check.
  - Soft-cap mode: if caps are exceeded, extract only priority files.
"""

from __future__ import annotations

import io
import logging
import zipfile
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from release_sentinel.extractor import (
    _HARD_MAX_FILE_COUNT,
    _HARD_MAX_TOTAL_SIZE,
    _PRIORITY_PATTERNS,
    _WINDOWS_ABS_RE,
    ExtractionConfig,
    ExtractionError,
    ReleaseContents,
)

logger = logging.getLogger(__name__)

# Zip bomb ratio threshold: uncompressed / compressed ratio > 100 for files > 1 MB
_ZIP_BOMB_MAX_RATIO = 100.0
_ZIP_BOMB_MIN_SIZE = 1024 * 1024  # 1 MB


def _check_zip_info(info: zipfile.ZipInfo) -> None:
    """Apply safety checks to a single zip member header."""
    name = info.filename

    # Symlink check in zip (Unix S_IFLNK is 0o120000 in upper 16 bits of external_attr)
    if (info.external_attr >> 16) & 0o170000 == 0o120000:
        raise ExtractionError(f"Refusing symlink in zip archive: {name!r}")

    # Absolute path check
    norm_name = name.replace("\\", "/")
    posix_name = PurePosixPath(norm_name)
    if posix_name.is_absolute() or norm_name.startswith("/"):
        raise ExtractionError(f"Refusing absolute path in zip archive: {name!r}")
    if _WINDOWS_ABS_RE.match(norm_name):
        raise ExtractionError(f"Refusing Windows absolute path in zip archive: {name!r}")

    # Path traversal check
    for part in posix_name.parts:
        if part == "..":
            raise ExtractionError(f"Path traversal detected in zip member: {name!r}")

    # Excessive depth check
    if len(posix_name.parts) > 50:
        raise ExtractionError(f"Refusing excessively deep path in zip: {name!r}")

    # Component length check
    for part in posix_name.parts:
        if len(part) > 255:
            raise ExtractionError(f"Refusing member with filename component > 255 chars: {name!r}")

    # Zip bomb ratio check
    if info.compress_size > 0 and info.file_size > _ZIP_BOMB_MIN_SIZE:
        ratio = info.file_size / info.compress_size
        if ratio > _ZIP_BOMB_MAX_RATIO:
            raise ExtractionError(
                f"Zip bomb detected in member {name!r}: "
                f"expansion ratio {ratio:.1f} exceeds {_ZIP_BOMB_MAX_RATIO}"
            )


def _find_package_prefix(infolist: list[zipfile.ZipInfo]) -> str:
    """Detect package root directory prefix inside the archive.

    DataDog npm archives are typically structured as:
      tmp/<id>/<pkg>/package/...
    or:
      package/...
    Returns the prefix to strip, e.g. "tmp/xxx/pkg/package/" or "package/",
    or "" if files are at root.
    """
    for info in infolist:
        fn = info.filename.replace("\\", "/")
        if fn.endswith("/package/package.json"):
            idx = fn.rfind("/package/package.json")
            return fn[: idx + len("/package/")]
        elif fn == "package/package.json":
            return "package/"

    # Fallback: look for any package.json
    for info in infolist:
        fn = info.filename.replace("\\", "/")
        if fn.endswith("package.json"):
            parts = fn.rsplit("package.json", 1)
            return parts[0]

    return ""


def load_zip_release(
    zip_source: Path | str | bytes | BinaryIO,
    password: bytes = b"infected",
    config: ExtractionConfig | None = None,
) -> ReleaseContents:
    """Safely load an encrypted (or unencrypted) zip archive into memory.

    Parameters
    ----------
    zip_source:
        Path to a .zip file, raw bytes, or an open binary stream.
    password:
        Decryption password (defaults to b"infected" for DataDog dataset).
    config:
        Extraction limits and soft-cap settings.

    Returns
    -------
    ReleaseContents:
        In-memory representation mapping package-relative paths to bytes.
        Never writes any member to disk.
    """
    if config is None:
        config = ExtractionConfig()

    if isinstance(zip_source, (bytes, bytearray)):
        zf = zipfile.ZipFile(io.BytesIO(zip_source), mode="r")
    elif isinstance(zip_source, (str, Path)):
        zf = zipfile.ZipFile(str(zip_source), mode="r")
    else:
        zf = zipfile.ZipFile(zip_source, mode="r")

    with zf:
        zf.setpassword(password)
        infolist = zf.infolist()

        # Hard ceiling on member count
        if len(infolist) > _HARD_MAX_FILE_COUNT:
            raise ExtractionError(
                f"Zip archive has {len(infolist)} members; hard ceiling is {_HARD_MAX_FILE_COUNT}. "
                "Refusing extraction."
            )

        # Hard ceiling on declared size
        declared_total = sum(i.file_size for i in infolist if not i.is_dir())
        if declared_total > _HARD_MAX_TOTAL_SIZE:
            raise ExtractionError(
                f"Total declared size {declared_total / 1024 / 1024:.1f} MB exceeds "
                f"hard ceiling of {_HARD_MAX_TOTAL_SIZE // 1024 // 1024} MB. "
                "Refusing extraction."
            )

        # Safety checks on all members
        for info in infolist:
            _check_zip_info(info)

        pkg_prefix = _find_package_prefix(infolist)

        # Filter file members belonging to the package root
        package_members: list[zipfile.ZipInfo] = []
        for info in infolist:
            if info.is_dir():
                continue
            fn = info.filename.replace("\\", "/")
            if pkg_prefix:
                if fn.startswith(pkg_prefix):
                    package_members.append(info)
            else:
                package_members.append(info)

        capped = False
        cap_reason: str | None = None

        if len(package_members) > config.max_files:
            if config.soft_cap:
                capped = True
                cap_reason = (
                    f"Archive has {len(package_members)} files (soft cap: {config.max_files}); "
                    "only priority files (package.json, JS/TS) were extracted."
                )
                filtered = [
                    m
                    for m in package_members
                    if _PRIORITY_PATTERNS.search(
                        PurePosixPath(m.filename.replace("\\", "/")).name
                    )
                ]
                package_members = filtered or [
                    m for m in package_members if m.filename.endswith("package.json")
                ]
                logger.warning("Soft file-count cap triggered in zip: %s", cap_reason)
            else:
                raise ExtractionError(
                    f"Archive has {len(package_members)} files; cap is {config.max_files}. "
                    "Refusing extraction."
                )

        pkg_declared_total = sum(i.file_size for i in package_members)
        if not capped and pkg_declared_total > config.max_total_size:
            if config.soft_cap:
                capped = True
                cap_reason = (
                    f"Declared size {pkg_declared_total / 1024 / 1024:.1f} MB exceeds "
                    f"soft cap of {config.max_total_size // 1024 // 1024} MB; "
                    "only priority files were extracted."
                )
                filtered = [
                    m
                    for m in package_members
                    if _PRIORITY_PATTERNS.search(
                        PurePosixPath(m.filename.replace("\\", "/")).name
                    )
                ]
                package_members = filtered or [
                    m for m in package_members if m.filename.endswith("package.json")
                ]
                logger.warning("Soft size cap triggered in zip: %s", cap_reason)
            else:
                raise ExtractionError(
                    f"Total declared size {pkg_declared_total / 1024 / 1024:.1f} MB exceeds "
                    f"cap of {config.max_total_size // 1024 // 1024} MB. "
                    "Refusing extraction."
                )

        files_map: dict[str, bytes] = {}
        actual_total = 0

        for info in package_members:
            fn = info.filename.replace("\\", "/")
            rel = fn[len(pkg_prefix) :] if pkg_prefix and fn.startswith(pkg_prefix) else fn

            try:
                data = zf.read(info)
            except RuntimeError as exc:
                # Typically wrong password or corrupted archive
                raise ExtractionError(f"Failed to decrypt zip member {fn!r}: {exc}") from exc
            except Exception as exc:
                raise ExtractionError(f"Failed to read zip member {fn!r}: {exc}") from exc

            # Guard against decompressed size exceeding hard ceiling
            actual_total += len(data)
            if actual_total > _HARD_MAX_TOTAL_SIZE:
                ceiling_mb = _HARD_MAX_TOTAL_SIZE // 1024 // 1024
                raise ExtractionError(
                    f"Decompressed data exceeded hard ceiling of {ceiling_mb} MB"
                )

            files_map[rel] = data

    return ReleaseContents(
        files=files_map,
        total_size=actual_total,
        capped=capped,
        cap_reason=cap_reason,
        root=None,
    )
