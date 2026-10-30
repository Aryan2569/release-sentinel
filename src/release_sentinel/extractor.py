"""Safe tarball extraction for Release Sentinel.

Security constraints enforced here:
-------------------------------------------------------
* Reject absolute paths (starting with ``/`` or a Windows drive letter).
* Reject path traversal (any component that is ``..``).
* Reject symlinks (``TarInfo.issym()``).
* Reject hardlinks (``TarInfo.islnk()``).
* Reject device files (``TarInfo.isdev()``, ``TarInfo.isfifo()``).
* Apply ``tarfile.data_filter`` as the baseline before our own checks.
* **Soft-cap mode** (default): when file-count or size caps are exceeded,
  extract only priority files and record a limitation — do not abort.
* Hard ceiling: always abort at 10 000 members or 500 MB.
* Write nothing outside the designated temp directory.
"""

from __future__ import annotations

import io
import json
import logging
import re
import tarfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

logger = logging.getLogger(__name__)

# Hard ceilings — never exceeded even in soft-cap mode
_HARD_MAX_FILE_COUNT = 10_000
_HARD_MAX_TOTAL_SIZE = 500 * 1024 * 1024  # 500 MB

# Matches Windows-style drive absolute paths (e.g. D:\ or D:/)
_WINDOWS_ABS_RE = re.compile(r"^[A-Za-z]:[/\\]")

# Priority file patterns for soft-cap partial extraction
_PRIORITY_PATTERNS = re.compile(
    r"""(?x)
    ^package\.json$           # manifest
    | \.js$                   # JavaScript
    | \.mjs$                  # ES module
    | \.cjs$                  # CommonJS
    | \.ts$                   # TypeScript
    """,
    re.IGNORECASE,
)


@dataclass
class ExtractionConfig:
    """Configurable extraction limits."""

    max_files: int = 5_000
    max_total_size: int = 200 * 1024 * 1024  # 200 MB
    soft_cap: bool = True  # True = partial extraction; False = abort


@dataclass
class FileEntry:
    """Metadata for a single file inside an extracted release."""

    rel_path: str  # Package-relative path (after stripping the top-level dir)
    abs_path: Path | None = None  # Absolute path on disk, or None if in-memory
    size: int = 0  # Uncompressed size in bytes


@dataclass
class ReleaseContents:
    """In-memory representation of an npm release (path -> bytes)."""

    files: dict[str, bytes] = field(default_factory=dict)
    total_size: int = 0
    capped: bool = False
    cap_reason: str | None = None
    root: Path | None = None  # Optional root if backed by disk directory

    @property
    def file_paths(self) -> list[str]:
        return sorted(self.files.keys())

    @property
    def file_entries(self) -> list[FileEntry]:
        return [
            FileEntry(
                rel_path=p,
                abs_path=(self.root / p).resolve() if self.root else None,
                size=len(data),
            )
            for p, data in sorted(self.files.items())
        ]

    def read_bytes(self, rel_path: str) -> bytes:
        return self.files[rel_path]

    def read_text(self, rel_path: str, errors: str = "replace") -> str:
        return self.files[rel_path].decode("utf-8", errors=errors)

    def package_json(self) -> dict[str, Any] | None:
        if "package.json" not in self.files:
            return None
        try:
            return json.loads(self.read_text("package.json"))
        except Exception:
            return None

    @classmethod
    def from_extraction_result(cls, res: ExtractionResult) -> ReleaseContents:
        contents: dict[str, bytes] = {}
        for entry in res.files:
            if entry.abs_path is not None:
                try:
                    contents[entry.rel_path] = entry.abs_path.read_bytes()
                except OSError:
                    pass
        return cls(
            files=contents,
            total_size=res.total_size,
            capped=res.capped,
            cap_reason=res.cap_reason,
            root=res.root,
        )


@dataclass
class ExtractionResult:
    """The result of extracting a tarball."""

    root: Path  # Root directory of the extracted tree
    files: list[FileEntry] = field(default_factory=list)
    total_size: int = 0
    capped: bool = False  # True when soft-cap was triggered
    cap_reason: str | None = None  # Human-readable cap reason

    def to_release_contents(self) -> ReleaseContents:
        """Convert this extraction result to in-memory ReleaseContents."""
        return ReleaseContents.from_extraction_result(self)


class ExtractionError(Exception):
    """Raised when extraction is refused or fails."""


def extract_release(
    tarball_path: Path,
    dest_dir: Path,
    config: ExtractionConfig | None = None,
) -> ExtractionResult:
    """Safely extract *tarball_path* into *dest_dir*.

    Parameters
    ----------
    tarball_path:
        Path to a ``.tgz`` / ``.tar.gz`` file.
    dest_dir:
        Directory under which the contents will be extracted.
    config:
        Extraction limits.  Uses safe defaults if ``None``.

    Returns
    -------
    ExtractionResult
        Inventory of extracted files with package-relative paths.
        ``ExtractionResult.capped`` is True when a soft-cap was triggered
        and only priority files were extracted.

    Raises
    ------
    ExtractionError
        On hard-ceiling violations, safety-check failures, or tarfile errors.
    """
    if config is None:
        config = ExtractionConfig()

    dest_dir = Path(dest_dir).resolve()

    try:
        tf = tarfile.open(tarball_path, mode="r:gz")
    except tarfile.TarError as exc:
        raise ExtractionError(f"Cannot open tarball {tarball_path}: {exc}") from exc

    with tf:
        members = tf.getmembers()

        # --- Hard ceiling on count ---
        if len(members) > _HARD_MAX_FILE_COUNT:
            raise ExtractionError(
                f"Tarball has {len(members)} members; hard ceiling is {_HARD_MAX_FILE_COUNT}. "
                "Refusing extraction."
            )

        # --- Hard ceiling on declared size ---
        declared_total = sum(m.size for m in members if m.isfile())
        if declared_total > _HARD_MAX_TOTAL_SIZE:
            raise ExtractionError(
                f"Total declared size {declared_total / 1024 / 1024:.1f} MB exceeds "
                f"hard ceiling of {_HARD_MAX_TOTAL_SIZE // 1024 // 1024} MB. "
                "Refusing extraction."
            )

        # --- Per-member safety checks (all members, always) ---
        for member in members:
            _check_member(member)

        # --- Determine top-level directory ---
        top_level = _find_top_level(members)

        # --- Soft-cap check ---
        capped = False
        cap_reason: str | None = None
        file_members = [m for m in members if m.isfile()]

        if len(file_members) > config.max_files:
            if config.soft_cap:
                capped = True
                cap_reason = (
                    f"Archive has {len(file_members)} files (soft cap: {config.max_files}); "
                    "only priority files (package.json, JS/TS) were extracted."
                )
                file_members = _priority_filter(file_members)
                logger.warning("Soft file-count cap triggered: %s", cap_reason)
            else:
                raise ExtractionError(
                    f"Archive has {len(file_members)} files; cap is {config.max_files}. "
                    "Refusing extraction."
                )

        if not capped and declared_total > config.max_total_size:
            if config.soft_cap:
                capped = True
                cap_reason = (
                    f"Declared size {declared_total / 1024 / 1024:.1f} MB exceeds "
                    f"soft cap of {config.max_total_size // 1024 // 1024} MB; "
                    "only priority files were extracted."
                )
                file_members = _priority_filter(file_members)
                logger.warning("Soft size cap triggered: %s", cap_reason)
            else:
                raise ExtractionError(
                    f"Total declared size {declared_total / 1024 / 1024:.1f} MB exceeds "
                    f"cap of {config.max_total_size // 1024 // 1024} MB. "
                    "Refusing extraction."
                )

        # --- Extract selected members ---
        for member in file_members:
            try:
                member.mode = member.mode & 0o755  # normalise permissions
                tf.extract(
                    member,
                    path=dest_dir,
                    set_attrs=False,
                    filter="data",
                )
            except tarfile.TarError as exc:
                raise ExtractionError(
                    f"Extraction failed for member {member.name!r}: {exc}"
                ) from exc

            # Defence in depth: confirm the file landed inside dest_dir
            extracted_abs = (dest_dir / member.name).resolve()
            if not str(extracted_abs).startswith(str(dest_dir)):
                raise ExtractionError(
                    f"Member {member.name!r} escaped dest_dir after extraction — aborting."
                )

    # --- Build inventory ---
    result_root = dest_dir / top_level if top_level else dest_dir
    entries: list[FileEntry] = []
    actual_total_size = 0

    for member in file_members:
        abs_path = (dest_dir / member.name).resolve()
        if not abs_path.exists():
            continue
        rel = member.name
        if top_level and rel.startswith(top_level + "/"):
            rel = rel[len(top_level) + 1 :]
        entries.append(FileEntry(rel_path=rel, abs_path=abs_path, size=member.size))
        actual_total_size += member.size

    return ExtractionResult(
        root=result_root,
        files=entries,
        total_size=actual_total_size,
        capped=capped,
        cap_reason=cap_reason,
    )


def extract_release_in_memory(
    tarball_source: Path | str | bytes | BinaryIO,
    config: ExtractionConfig | None = None,
) -> ReleaseContents:
    """Safely extract a tarball entirely in memory into a ReleaseContents object.

    No files are written to disk. All extraction safety limits (path traversal,
    absolute paths, symlinks, caps, and hard ceilings) are enforced.
    """
    if config is None:
        config = ExtractionConfig()

    if isinstance(tarball_source, (bytes, bytearray)):
        tf = tarfile.open(fileobj=io.BytesIO(tarball_source), mode="r:*")
    elif isinstance(tarball_source, (str, Path)):
        tf = tarfile.open(name=str(tarball_source), mode="r:*")
    else:
        tf = tarfile.open(fileobj=tarball_source, mode="r:*")

    with tf:
        members = tf.getmembers()

        # Hard ceiling on member count
        if len(members) > _HARD_MAX_FILE_COUNT:
            raise ExtractionError(
                f"Tarball has {len(members)} members; hard ceiling is {_HARD_MAX_FILE_COUNT}. "
                "Refusing extraction."
            )

        # Hard ceiling on declared size
        declared_total = sum(m.size for m in members if m.isfile())
        if declared_total > _HARD_MAX_TOTAL_SIZE:
            raise ExtractionError(
                f"Total declared size {declared_total / 1024 / 1024:.1f} MB exceeds "
                f"hard ceiling of {_HARD_MAX_TOTAL_SIZE // 1024 // 1024} MB. "
                "Refusing extraction."
            )

        # Per-member safety checks
        for member in members:
            _check_member(member)

        top_level = _find_top_level(members)
        file_members = [m for m in members if m.isfile()]

        capped = False
        cap_reason: str | None = None

        if len(file_members) > config.max_files:
            if config.soft_cap:
                capped = True
                cap_reason = (
                    f"Archive has {len(file_members)} files (soft cap: {config.max_files}); "
                    "only priority files (package.json, JS/TS) were extracted."
                )
                file_members = _priority_filter(file_members)
                logger.warning("Soft file-count cap triggered: %s", cap_reason)
            else:
                raise ExtractionError(
                    f"Archive has {len(file_members)} files; cap is {config.max_files}. "
                    "Refusing extraction."
                )

        if not capped and declared_total > config.max_total_size:
            if config.soft_cap:
                capped = True
                cap_reason = (
                    f"Declared size {declared_total / 1024 / 1024:.1f} MB exceeds "
                    f"soft cap of {config.max_total_size // 1024 // 1024} MB; "
                    "only priority files were extracted."
                )
                file_members = _priority_filter(file_members)
                logger.warning("Soft size cap triggered: %s", cap_reason)
            else:
                raise ExtractionError(
                    f"Total declared size {declared_total / 1024 / 1024:.1f} MB exceeds "
                    f"cap of {config.max_total_size // 1024 // 1024} MB. "
                    "Refusing extraction."
                )

        files_map: dict[str, bytes] = {}
        actual_total = 0

        for member in file_members:
            extracted_file = tf.extractfile(member)
            if extracted_file is None:
                continue
            data = extracted_file.read()
            rel = member.name
            if top_level and rel.startswith(top_level + "/"):
                rel = rel[len(top_level) + 1 :]
            files_map[rel] = data
            actual_total += len(data)

    return ReleaseContents(
        files=files_map,
        total_size=actual_total,
        capped=capped,
        cap_reason=cap_reason,
        root=None,
    )


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------


def _check_member(member: tarfile.TarInfo) -> None:
    """Apply all per-member safety checks.

    Raises
    ------
    ExtractionError
        On any violation.
    """
    name = member.name

    # Symlinks and hardlinks
    if member.issym():
        raise ExtractionError(f"Refusing symlink in tarball: {name!r}")
    if member.islnk():
        raise ExtractionError(f"Refusing hardlink in tarball: {name!r}")

    # Device files and FIFOs
    if member.isdev():
        raise ExtractionError(f"Refusing device file in tarball: {name!r}")
    if member.isfifo():
        raise ExtractionError(f"Refusing FIFO in tarball: {name!r}")

    # Absolute paths
    posix_name = PurePosixPath(name)
    if posix_name.is_absolute():
        raise ExtractionError(f"Refusing absolute path in tarball: {name!r}")
    if _WINDOWS_ABS_RE.match(name):
        raise ExtractionError(f"Refusing Windows absolute path in tarball: {name!r}")

    # Path traversal via ".." components
    for part in PurePosixPath(name).parts:
        if part == "..":
            raise ExtractionError(f"Path traversal detected in tarball member: {name!r}")

    # Overly deep paths (defence against decompression of nested archives)
    if len(PurePosixPath(name).parts) > 50:
        raise ExtractionError(f"Refusing excessively deep path in tarball: {name!r}")

    # Overly long filename component
    for part in PurePosixPath(name).parts:
        if len(part) > 255:
            raise ExtractionError(
                f"Refusing member with filename component > 255 chars: {name!r}"
            )


def _priority_filter(members: list[tarfile.TarInfo]) -> list[tarfile.TarInfo]:
    """Return only priority members when operating under a soft cap."""
    priority = [
        m for m in members if _PRIORITY_PATTERNS.search(PurePosixPath(m.name).name)
    ]
    if not priority:
        # At minimum extract package.json if present
        priority = [m for m in members if m.name.endswith("package.json")]
    return priority


def _find_top_level(members: list[tarfile.TarInfo]) -> str:
    """Return the common top-level directory name, or empty string if none."""
    dirs: set[str] = set()
    for m in members:
        parts = PurePosixPath(m.name).parts
        if parts:
            dirs.add(parts[0])
    if len(dirs) == 1:
        return next(iter(dirs))
    return ""
