from pathlib import Path

import pytest

from seek import actions
from seek.actions import ActionError, editor_argv, format_lines, resolve_targets
from seek.config import Config
from seek.models import MatchKind, Result


def _r(kind, rel, line=None):
    return Result(kind=kind, path=Path("/root") / rel, rel=rel, score=1,
                  line_no=line, line_text="x" if line else None)


def test_resolve_targets_prefers_selection():
    hi = _r(MatchKind.FILENAME, "a.py")
    sel = [_r(MatchKind.FILENAME, "b.py")]
    assert resolve_targets(sel, hi) == sel
    assert resolve_targets([], hi) == [hi]
    assert resolve_targets([], None) == []


def test_format_lines_relative_and_line():
    cfg = Config()
    targets = [_r(MatchKind.FILENAME, "src/a.py"), _r(MatchKind.CONTENT, "src/b.py", 88)]
    assert format_lines(targets, cfg) == "src/a.py\nsrc/b.py:88"


def test_format_lines_absolute():
    cfg = Config(absolute_output=True)
    t = _r(MatchKind.CONTENT, "src/b.py", 88)
    assert format_lines([t], cfg) == "/root/src/b.py:88"


def test_editor_argv_content_jumps_to_line():
    cfg = Config()
    argv = editor_argv(cfg, [_r(MatchKind.CONTENT, "a.py", 42)])
    assert argv == ["nvim", "+42", "/root/a.py"]


def test_editor_argv_filename_no_line():
    cfg = Config()
    argv = editor_argv(cfg, [_r(MatchKind.FILENAME, "a.py")])
    assert argv == ["nvim", "/root/a.py"]


def test_editor_argv_multiple_targets_single_invocation():
    cfg = Config()
    argv = editor_argv(cfg, [_r(MatchKind.FILENAME, "a.py"), _r(MatchKind.FILENAME, "b.py")])
    assert argv == ["nvim", "/root/a.py", "/root/b.py"]


def test_code_argv():
    assert actions.code_argv([_r(MatchKind.CONTENT, "a.py", 10)]) == [
        "code", "--goto", "/root/a.py:10",
    ]
    assert actions.code_argv([_r(MatchKind.FILENAME, "a.py")]) == ["code", "/root/a.py"]


def test_opener_argv(monkeypatch):
    monkeypatch.setattr("sys.platform", "linux")
    assert actions.opener_argv(Path("/x/y")) == ["xdg-open", "/x/y"]
    monkeypatch.setattr("sys.platform", "darwin")
    assert actions.opener_argv(Path("/x/y")) == ["open", "/x/y"]


def _fake_run(calls):
    def run(argv, **kw):
        calls.append((argv, kw["input"]))

        class Done:
            returncode = 0
        return Done()
    return run


def test_clipboard_uses_the_first_program_present(monkeypatch):
    calls = []
    monkeypatch.setattr(actions.shutil, "which", lambda name: name == "xclip")
    monkeypatch.setattr(actions.subprocess, "run", _fake_run(calls))
    actions.copy_to_clipboard("héllo")
    assert calls == [(["xclip", "-selection", "clipboard"], "héllo".encode())]


def test_windows_clip_gets_utf16_so_non_ascii_survives(monkeypatch):
    calls = []
    monkeypatch.setattr(actions.shutil, "which", lambda name: name == "clip.exe")
    monkeypatch.setattr(actions.subprocess, "run", _fake_run(calls))
    actions.copy_to_clipboard("héllo")
    assert calls[0][1].decode("utf-16") == "héllo"


def test_clipboard_unavailable(monkeypatch):
    monkeypatch.setattr(actions.shutil, "which", lambda name: None)
    with pytest.raises(ActionError):
        actions.copy_to_clipboard("hello")
