"""The lockfile fits `pyproject.toml` (TST-24) - found here, not by CI."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.skipif(shutil.which("uv") is None, reason="uv is not on PATH")
def test_the_lockfile_is_current():
    done = subprocess.run(["uv", "lock", "--check", "--offline"], cwd=ROOT,
                          capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
