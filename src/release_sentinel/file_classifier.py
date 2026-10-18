"""File type classifier for Release Sentinel.

Classifies files by extension and, for binaries, by magic bytes.
Used by the differ to decide which files need individual evidence items
versus aggregated summaries, and which files can be silently ignored.

Rule 6: no real malware patterns here — this module classifies, not detects.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

# ---------------------------------------------------------------------------
# File category enum
# ---------------------------------------------------------------------------


class FileCategory(StrEnum):
    """Broad category of a file in an npm package."""

    SCRIPT = "script"  # JS / TS / CoffeeScript / etc.
    NATIVE_BINARY = "native_binary"  # .node, .so, .dll, .dylib — ELF/Mach-O/PE
    EXECUTABLE = "executable"  # Other executables / shell scripts / .exe
    DOTFILE = "dotfile"  # Hidden config file (name starts with .)
    MINIFIED = "minified"  # Minified JS/CSS (very long lines)
    ASSET = "asset"  # Images, fonts, audio/video
    DOCUMENT = "document"  # README, LICENSE, markdown, txt
    SOURCE_MAP = "source_map"  # .map files
    OTHER = "other"  # Anything not matched above


# ---------------------------------------------------------------------------
# Extension look-up tables
# ---------------------------------------------------------------------------

# Extensions → FileCategory (lowercase, no dot)
_EXT_MAP: dict[str, FileCategory] = {
    # Scripts
    "js": FileCategory.SCRIPT,
    "mjs": FileCategory.SCRIPT,
    "cjs": FileCategory.SCRIPT,
    "ts": FileCategory.SCRIPT,
    "tsx": FileCategory.SCRIPT,
    "jsx": FileCategory.SCRIPT,
    "coffee": FileCategory.SCRIPT,
    "py": FileCategory.SCRIPT,
    "rb": FileCategory.SCRIPT,
    "sh": FileCategory.EXECUTABLE,
    "bash": FileCategory.EXECUTABLE,
    "zsh": FileCategory.EXECUTABLE,
    "fish": FileCategory.EXECUTABLE,
    "ps1": FileCategory.EXECUTABLE,
    "cmd": FileCategory.EXECUTABLE,
    "bat": FileCategory.EXECUTABLE,
    # Native binaries
    "node": FileCategory.NATIVE_BINARY,
    "so": FileCategory.NATIVE_BINARY,
    "dll": FileCategory.NATIVE_BINARY,
    "dylib": FileCategory.NATIVE_BINARY,
    "exe": FileCategory.EXECUTABLE,
    "wasm": FileCategory.NATIVE_BINARY,
    # Assets — images
    "png": FileCategory.ASSET,
    "jpg": FileCategory.ASSET,
    "jpeg": FileCategory.ASSET,
    "gif": FileCategory.ASSET,
    "svg": FileCategory.ASSET,
    "ico": FileCategory.ASSET,
    "webp": FileCategory.ASSET,
    "avif": FileCategory.ASSET,
    "bmp": FileCategory.ASSET,
    "tiff": FileCategory.ASSET,
    # Assets — fonts
    "woff": FileCategory.ASSET,
    "woff2": FileCategory.ASSET,
    "ttf": FileCategory.ASSET,
    "otf": FileCategory.ASSET,
    "eot": FileCategory.ASSET,
    # Assets — audio/video
    "mp3": FileCategory.ASSET,
    "mp4": FileCategory.ASSET,
    "ogg": FileCategory.ASSET,
    "wav": FileCategory.ASSET,
    "webm": FileCategory.ASSET,
    # Assets — misc
    "zip": FileCategory.ASSET,
    "gz": FileCategory.ASSET,
    "tar": FileCategory.ASSET,
    # Documents
    "md": FileCategory.DOCUMENT,
    "markdown": FileCategory.DOCUMENT,
    "txt": FileCategory.DOCUMENT,
    "rst": FileCategory.DOCUMENT,
    "html": FileCategory.DOCUMENT,
    "htm": FileCategory.DOCUMENT,
    "pdf": FileCategory.DOCUMENT,
    "csv": FileCategory.DOCUMENT,
    # Source maps
    "map": FileCategory.SOURCE_MAP,
    # Config / data (other)
    "json": FileCategory.OTHER,
    "yaml": FileCategory.OTHER,
    "yml": FileCategory.OTHER,
    "toml": FileCategory.OTHER,
    "ini": FileCategory.OTHER,
    "lock": FileCategory.OTHER,
    "css": FileCategory.OTHER,
    "scss": FileCategory.OTHER,
    "less": FileCategory.OTHER,
}

# Magic bytes → FileCategory
_MAGIC_BYTES: list[tuple[bytes, FileCategory]] = [
    (b"\x7fELF", FileCategory.NATIVE_BINARY),  # ELF (Linux .so / executables)
    (b"\xfe\xed\xfa\xce", FileCategory.NATIVE_BINARY),  # Mach-O 32-bit
    (b"\xfe\xed\xfa\xcf", FileCategory.NATIVE_BINARY),  # Mach-O 64-bit
    (b"\xce\xfa\xed\xfe", FileCategory.NATIVE_BINARY),  # Mach-O reverse endian
    (b"\xcf\xfa\xed\xfe", FileCategory.NATIVE_BINARY),  # Mach-O 64 reverse
    (b"MZ", FileCategory.NATIVE_BINARY),  # PE (Windows .dll / .exe)
    (b"\x00asm", FileCategory.NATIVE_BINARY),  # WASM
]

# Line length threshold for minified-file detection (chars)
_MINIFIED_LINE_THRESHOLD = 500

# Number of header bytes to read for magic detection
_MAGIC_READ_BYTES = 8

# Dotfile: basename starts with "." and has no extension making it a config file
# (e.g. .npmrc, .eslintrc — NOT .gitignore which is a well-known safe file)
_SAFE_DOTFILES = {
    ".gitignore",
    ".gitattributes",
    ".gitkeep",
    ".npmignore",
    ".editorconfig",
    ".prettierignore",
    ".eslintignore",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def classify(target: Path | bytes | str | None, rel_path: str) -> FileCategory:
    """Classify a single file.

    Parameters
    ----------
    target:
        Absolute path on disk, in-memory bytes/str, or None. Used for magic byte reads
        and minification sampling. If None, classification uses path heuristics only.
    rel_path:
        Package-relative path (used for extension and dotfile checks).

    Returns
    -------
    FileCategory
        The best-match category.
    """
    basename = Path(rel_path).name
    suffix = Path(rel_path).suffix.lstrip(".").lower()

    # Dotfile check first — name starts with "." and is not a known safe dotfile
    if basename.startswith(".") and basename not in _SAFE_DOTFILES:
        return FileCategory.DOTFILE

    # Extension lookup
    if suffix and suffix in _EXT_MAP:
        cat = _EXT_MAP[suffix]
        # For text-like files, also check if minified / very long lines
        if cat in {FileCategory.SCRIPT, FileCategory.OTHER} and _is_minified(target):
            return FileCategory.MINIFIED
        return cat

    # Magic bytes for files without a recognised extension
    magic_cat = _check_magic_bytes(target)
    if magic_cat is not None:
        return magic_cat

    if _is_minified(target):
        return FileCategory.MINIFIED

    return FileCategory.OTHER


def is_ignorable(cat: FileCategory) -> bool:
    """Return True if files of this category should produce no evidence at all.

    Ignorable files are things like images, fonts, source maps, and documentation
    that are very common, very unlikely to be malicious, and cannot be statically
    inspected in a useful way.
    """
    return cat in {FileCategory.ASSET, FileCategory.DOCUMENT, FileCategory.SOURCE_MAP}


def is_notable(cat: FileCategory) -> bool:
    """Return True if a *new* file of this category deserves individual evidence.

    Notable files get their own Evidence item rather than being rolled into
    the aggregated ``new_files_summary``.
    """
    return cat in {
        FileCategory.NATIVE_BINARY,
        FileCategory.EXECUTABLE,
        FileCategory.DOTFILE,
        FileCategory.MINIFIED,
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _check_magic_bytes(target: Path | bytes | str | None) -> FileCategory | None:
    """Read the first few bytes and compare against known magic numbers."""
    if target is None:
        return None

    header: bytes
    if isinstance(target, (bytes, bytearray)):
        header = bytes(target[:_MAGIC_READ_BYTES])
    elif isinstance(target, str):
        header = target[:_MAGIC_READ_BYTES].encode("utf-8", errors="replace")
    elif isinstance(target, Path):
        try:
            with target.open("rb") as fh:
                header = fh.read(_MAGIC_READ_BYTES)
        except OSError:
            return None
    else:
        return None

    for magic, cat in _MAGIC_BYTES:
        if header.startswith(magic):
            return cat

    return None


def _is_minified(target: Path | bytes | str | None) -> bool:
    """Return True if the file appears to be minified (has very long lines)."""
    if target is None:
        return False

    if isinstance(target, (bytes, bytearray)):
        text = target.decode("utf-8", errors="replace")
        for line in text.splitlines():
            if len(line) > _MINIFIED_LINE_THRESHOLD:
                return True
        return False

    if isinstance(target, str):
        for line in target.splitlines():
            if len(line) > _MINIFIED_LINE_THRESHOLD:
                return True
        return False

    if isinstance(target, Path):
        try:
            with target.open(encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if len(line) > _MINIFIED_LINE_THRESHOLD:
                        return True
        except OSError:
            pass
        return False

    return False
