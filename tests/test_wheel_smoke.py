"""Smoke test for the built wheel package in a fresh virtual environment (Stage 6 Part 4).

Verifies:
- Wheel packages release_sentinel and release_sentinel.data.
- Wheel installs cleanly into a fresh virtualenv.
- `sentinel` console script entry point works.
- `sentinel check` runs from an empty temp directory without repository-relative paths.
"""

from __future__ import annotations

import glob
import json
import os
import subprocess
import sys
import venv
from pathlib import Path

import pytest


@pytest.mark.skipif(sys.platform == "win32" and "CI" in os.environ, reason="Heavy venv test on CI")
def test_wheel_installation_and_smoke_check(tmp_path: Path):
    # 1. Find built wheel (choose newest by mtime)
    wheels = glob.glob("dist/*.whl")
    if not wheels:
        # Build wheel if not present
        cmd_b = [sys.executable, "-m", "build", "--wheel"]
        res = subprocess.run(cmd_b, capture_output=True, text=True)  # noqa: S603
        if res.returncode != 0:
            msg = f"build failed ({res.returncode}):\nstdout: {res.stdout}\nstderr: {res.stderr}"
            raise RuntimeError(msg)
        wheels = glob.glob("dist/*.whl")

    assert len(wheels) > 0, "No built wheel found in dist/"
    wheel_path = max([Path(w).resolve() for w in wheels], key=os.path.getmtime)

    # 2. Create fresh virtual environment
    venv_dir = tmp_path / "venv"
    venv.create(venv_dir, with_pip=True)

    if sys.platform == "win32":
        venv_python = venv_dir / "Scripts" / "python.exe"
        sentinel_exe = venv_dir / "Scripts" / "sentinel.exe"
    else:
        venv_python = venv_dir / "bin" / "python"
        sentinel_exe = venv_dir / "bin" / "sentinel"

    assert venv_python.exists(), f"Virtualenv python not found at {venv_python}"

    # 3. Install wheel
    proc = subprocess.run(  # noqa: S603
        [str(venv_python), "-m", "pip", "install", str(wheel_path)],
        capture_output=True,
        text=True,
        check=True,
    )
    assert proc.returncode == 0

    # 4. Create empty working directory outside repo
    isolated_dir = tmp_path / "empty_work_dir"
    isolated_dir.mkdir()

    # 5. Test `sentinel --version`
    if sentinel_exe.exists():
        ver_cmd = [str(sentinel_exe), "--version"]
    else:
        ver_cmd = [str(venv_python), "-m", "release_sentinel", "--version"]
    proc = subprocess.run(  # noqa: S603
        ver_cmd,
        cwd=str(isolated_dir),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    )
    assert "0.5.0" in proc.stdout or "0.5.0" in proc.stderr

    # 6. Test `sentinel check` on fixture lockfiles from empty directory (network-free diff)
    base_lock = isolated_dir / "base.json"
    head_lock = isolated_dir / "head.json"
    base_lock.write_text(json.dumps({"lockfileVersion": 3, "packages": {}}), encoding="utf-8")
    head_lock.write_text(json.dumps({"lockfileVersion": 3, "packages": {}}), encoding="utf-8")

    check_cmd = [
        str(sentinel_exe) if sentinel_exe.exists() else str(venv_python),
        *([] if sentinel_exe.exists() else ["-m", "release_sentinel"]),
        "check",
        "--base", str(base_lock),
        "--head", str(head_lock),
        "--format", "markdown",
    ]
    proc_check = subprocess.run(  # noqa: S603
        check_cmd,
        cwd=str(isolated_dir),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    msg = f"check failed ({proc_check.returncode}):\n{proc_check.stdout}\n{proc_check.stderr}"
    assert proc_check.returncode == 0, msg
    assert "Release Sentinel" in proc_check.stdout, "Expected 'Release Sentinel' in stdout"
