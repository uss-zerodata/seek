from __future__ import annotations

import os
from pathlib import Path

import pytest


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    """A small representative project tree."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").write_text(
        "def main():\n    print('hello world')\n    return 0\n"
    )
    (tmp_path / "src" / "helper.py").write_text("X = 1\ndef helper():\n    return X\n")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "README.md").write_text("# Title\n\nsome docs about main\n")
    (tmp_path / ".hidden").write_text("secret main config\n")
    (tmp_path / "notes.txt").write_text("todo: fix main\nline two\n")
    (tmp_path / "data.bin").write_bytes(b"\x00\x01\x02 main \x00")

    # gitignore + an ignored file
    (tmp_path / ".gitignore").write_text("build/\n*.log\n")
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "artifact.js").write_text("// generated main\n")
    (tmp_path / "run.log").write_text("log line with main\n")

    # noise dir
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "pkg.js").write_text("module main\n")

    # a real .git dir
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    return tmp_path


@pytest.fixture
def symlink_loop(tmp_path: Path) -> Path:
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "file.txt").write_text("hi\n")
    try:
        os.symlink(tmp_path, tmp_path / "a" / "loop", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported here")
    return tmp_path


@pytest.fixture(autouse=True)
def _private_state_dir(tmp_path_factory, monkeypatch):
    """Every test gets an empty state directory: nothing reads or writes the
    user's own - above all not a real vulnerability database, whose contents
    would make lookups depend on the machine the tests ran on."""
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path_factory.mktemp("state")))


@pytest.fixture(autouse=True)
def _no_internet(monkeypatch):
    """No test reaches past loopback. A source added to the update without a
    fixture would otherwise download the real feed - which is how this guard
    came to exist."""
    import socket

    real = socket.create_connection

    def loopback_only(address, *args, **kwargs):
        host = address[0]
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise AssertionError(f"a test tried to connect to {host}")
        return real(address, *args, **kwargs)

    monkeypatch.setattr(socket, "create_connection", loopback_only)
