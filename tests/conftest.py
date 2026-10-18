"""Shared test fixtures for Release Sentinel.

All network-free: tarballs are built programmatically in memory.
No real npm packages, no real malware, no external calls.
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Tarball builder helper
# ---------------------------------------------------------------------------


def make_tarball(dest: Path, files: dict[str, str | bytes], top_dir: str = "package") -> Path:
    """Create a .tgz tarball at *dest* with the given *files*.

    Parameters
    ----------
    dest:
        Destination path for the tarball (must end in .tgz).
    files:
        Mapping of ``<top_dir>/<relative_path>`` → file content.
        Provide a leading component yourself to match npm conventions.
    top_dir:
        Top-level directory name inside the archive.

    Returns
    -------
    Path
        The path to the written tarball.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(dest, "w:gz") as tf:
        for rel_path, content in files.items():
            member_path = f"{top_dir}/{rel_path}"
            if isinstance(content, str):
                data = content.encode()
            else:
                data = content
            info = tarfile.TarInfo(name=member_path)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return dest


def make_package_json(**kwargs: object) -> str:
    """Return a minimal package.json string with the given extra fields."""
    base: dict[str, object] = {
        "name": "test-package",
        "version": "1.0.0",
    }
    base.update(kwargs)
    return json.dumps(base)


# ---------------------------------------------------------------------------
# Basic release fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_tarballs(tmp_path: Path) -> Path:
    """Return a temporary directory for tarball storage."""
    d = tmp_path / "tarballs"
    d.mkdir()
    return d


@pytest.fixture
def old_tarball(tmp_tarballs: Path) -> Path:
    """A minimal 'old' release tarball with a basic package.json."""
    return make_tarball(
        tmp_tarballs / "old.tgz",
        {
            "package.json": make_package_json(
                version="1.0.0",
                scripts={"test": "echo ok"},
                dependencies={"lodash": "^4.17.20"},
            ),
            "index.js": "module.exports = {};",
        },
    )


@pytest.fixture
def new_tarball_clean(tmp_tarballs: Path) -> Path:
    """A 'new' release with no suspicious changes."""
    return make_tarball(
        tmp_tarballs / "new_clean.tgz",
        {
            "package.json": make_package_json(
                version="1.0.1",
                scripts={"test": "echo ok"},
                dependencies={"lodash": "^4.17.21"},  # minor bump only
            ),
            "index.js": "module.exports = {};",
        },
    )


@pytest.fixture
def new_tarball_with_postinstall(tmp_tarballs: Path) -> Path:
    """A 'new' release that added a postinstall script."""
    return make_tarball(
        tmp_tarballs / "new_postinstall.tgz",
        {
            "package.json": make_package_json(
                version="1.0.1",
                scripts={
                    "test": "echo ok",
                    "postinstall": "node setup.js",
                },
                dependencies={"lodash": "^4.17.20"},
            ),
            "index.js": "module.exports = {};",
            "setup.js": "// setup",
        },
    )


@pytest.fixture
def new_tarball_changed_install_script(tmp_tarballs: Path) -> Path:
    """A 'new' release where an existing install script was changed."""
    return make_tarball(
        tmp_tarballs / "new_changed_script.tgz",
        {
            "package.json": make_package_json(
                version="1.0.1",
                scripts={
                    "test": "echo ok",
                    "postinstall": "node new-setup.js",  # changed
                },
                dependencies={"lodash": "^4.17.20"},
            ),
            "index.js": "module.exports = {};",
        },
    )


@pytest.fixture
def old_tarball_with_postinstall(tmp_tarballs: Path) -> Path:
    """An 'old' release that already has a postinstall script."""
    return make_tarball(
        tmp_tarballs / "old_postinstall.tgz",
        {
            "package.json": make_package_json(
                version="1.0.0",
                scripts={
                    "test": "echo ok",
                    "postinstall": "node old-setup.js",
                },
                dependencies={"lodash": "^4.17.20"},
            ),
            "index.js": "module.exports = {};",
        },
    )


@pytest.fixture
def new_tarball_new_bin(tmp_tarballs: Path) -> Path:
    """A 'new' release that added a bin entry."""
    return make_tarball(
        tmp_tarballs / "new_bin.tgz",
        {
            "package.json": make_package_json(
                version="1.0.1",
                bin={"my-cli": "./cli.js"},
                dependencies={"lodash": "^4.17.20"},
            ),
            "index.js": "module.exports = {};",
            "cli.js": "#!/usr/bin/env node\nconsole.log('hello');",
        },
    )


@pytest.fixture
def new_tarball_new_dep(tmp_tarballs: Path) -> Path:
    """A 'new' release that added a new dependency."""
    return make_tarball(
        tmp_tarballs / "new_dep.tgz",
        {
            "package.json": make_package_json(
                version="1.0.1",
                dependencies={"lodash": "^4.17.20", "axios": "^1.0.0"},
            ),
            "index.js": "module.exports = {};",
        },
    )
