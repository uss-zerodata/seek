import subprocess
from pathlib import Path

import pytest

from seek.shell import cd_channel_path, render_init, write_cd_target


def test_render_init_bash_zsh():
    for shell in ("bash", "zsh"):
        code = render_init(shell)
        assert "seek()" in code
        assert "SEEK_CD_FILE" in code
        assert f"seek init {shell}" in code
    assert "${=SEEK_BIN}" in render_init("zsh")
    assert "$SEEK_BIN" in render_init("bash")


def test_write_cd_target_uses_channel(tmp_path, monkeypatch):
    channel = tmp_path / "cd"
    monkeypatch.setenv("SEEK_CD_FILE", str(channel))
    assert cd_channel_path() == channel
    target = tmp_path / "some dir"
    target.mkdir()
    assert write_cd_target(target) is True
    assert channel.read_text() == str(target)


def test_write_cd_target_no_channel(monkeypatch):
    monkeypatch.delenv("SEEK_CD_FILE", raising=False)
    assert write_cd_target(Path("/tmp")) is False


@pytest.mark.skipif(not Path("/bin/bash").exists(), reason="bash required")
def test_bash_wrapper_cds_and_preserves_status(tmp_path):
    script = tmp_path / "t.sh"
    dest = tmp_path / "target dir"
    dest.mkdir()
    fake_bin = tmp_path / "fakeseek"
    fake_bin.write_text(
        "#!/bin/bash\n"
        f'printf "%s" "{dest}" > "$SEEK_CD_FILE"\n'
        "exit 7\n"
    )
    fake_bin.chmod(0o755)
    script.write_text(
        render_init("bash")
        + f'\nexport SEEK_BIN="{fake_bin}"\n'
        + "seek\n"
        + 'echo "status=$?"\n'
        + 'echo "pwd=$PWD"\n'
    )
    out = subprocess.run(
        ["/bin/bash", str(script)], capture_output=True, text=True, cwd=tmp_path
    )
    assert "status=7" in out.stdout
    assert f"pwd={dest}" in out.stdout


@pytest.mark.skipif(not Path("/bin/bash").exists(), reason="bash required")
def test_wrapper_eval_safe_without_binary(tmp_path):
    script = tmp_path / "t.sh"
    script.write_text(
        'eval "$(cat <<\'EOF\'\n'
        + render_init("bash")
        + "\nEOF\n)"
        + '"\necho defined-ok\n'
    )
    out = subprocess.run(
        ["/bin/bash", str(script)], capture_output=True, text=True,
        env={"PATH": "/nonexistent"},
    )
    assert "defined-ok" in out.stdout
