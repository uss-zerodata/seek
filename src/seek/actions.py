"""Result actions: target resolution, output formatting, and external commands.

The interactive parts (confirm dialog, destination prompt) live in the TUI;
this module holds the testable logic it calls into.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from seek.config import Config
from seek.models import MatchKind, Result


class ActionError(Exception):
    pass


def resolve_targets(selection: list[Result], highlighted: Result | None) -> list[Result]:
    """Selection wins when non-empty, else the highlighted row, else nothing."""
    if selection:
        return list(selection)
    if highlighted is not None:
        return [highlighted]
    return []


def format_lines(targets: list[Result], config: Config) -> str:
    return "\n".join(t.format_output(config.absolute_output) for t in targets)


def write_new(path: str, text: str) -> Path:
    """Write an export to a file that does not exist yet.

    An existing file is refused, never replaced: the prompt offers the same
    name every time, so the second export of a session would otherwise
    silently overwrite the first.
    """
    target = Path(path).expanduser()
    if target.exists():
        raise ActionError(f"{target} exists - choose another name")
    target.write_text(text + "\n", encoding="utf-8")
    return target


# --- external program argv construction ------------------------------------------


def opener_argv(path: Path) -> list[str]:
    if sys.platform == "darwin":
        return ["open", str(path)]
    if sys.platform == "win32":
        return ["cmd", "/c", "start", "", str(path)]
    return ["xdg-open", str(path)]


def _fill_template(template: str, file: str, line: int | None) -> list[str]:
    parts = shlex.split(template)
    out: list[str] = []
    for part in parts:
        filled = part.replace("{file}", file).replace("{line}", str(line or 1))
        # Drop a bare "+{line}" style arg when there is no line to jump to.
        if line is None and part in {"+{line}", "--line={line}", "{line}"}:
            continue
        out.append(filled)
    return out


def editor_argv(
    config: Config, targets: list[Result], *, editor: str | None = None
) -> list[str]:
    name = editor or config.default_editor
    template = config.editors.get(name)
    if template is None:
        raise ActionError(f"unknown editor {name!r}")
    if "{file}" not in template:
        raise ActionError(f"editor template for {name!r} has no {{file}} placeholder")
    if len(targets) == 1:
        t = targets[0]
        line = t.line_no if t.kind is MatchKind.CONTENT else None
        return _fill_template(template, str(t.path), line)
    # Multiple targets: one invocation, the template minus its file slot (the
    # program and its flags - `emacsclient -n` needs the `-n`), every file after.
    argv = _fill_template(template, "\x00", None)
    prog = [a for a in argv if "\x00" not in a]
    return prog + [str(t.path) for t in targets]


def code_argv(targets: list[Result]) -> list[str]:
    if len(targets) == 1 and targets[0].kind is MatchKind.CONTENT:
        t = targets[0]
        return ["code", "--goto", f"{t.path}:{t.line_no}"]
    return ["code", *(str(t.path) for t in targets)]



# --- clipboard ------------------------------------------------------------------

_CLIPBOARD_FALLBACKS = (
    ["wl-copy"],
    ["xclip", "-selection", "clipboard"],
    ["xsel", "--clipboard", "--input"],
    ["pbcopy"],
    ["clip.exe"],
    ["clip"],
)


def copy_to_clipboard(text: str) -> None:
    """Through the platform's own clipboard program - Wayland, X11, macOS,
    Windows, WSL - the same set a clipboard library would try, without one."""
    for argv in _CLIPBOARD_FALLBACKS:
        if shutil.which(argv[0]):
            # Windows' clip reads UTF-16 with a byte-order mark; UTF-8 bytes
            # turn every non-ASCII character into two wrong ones.
            data = (("\ufeff" + text).encode("utf-16-le") if argv[0].startswith("clip")
                    else text.encode("utf-8"))
            try:
                subprocess.run(argv, input=data, check=True)  # noqa: S603 - fixed argv
                return
            except (OSError, subprocess.CalledProcessError):
                continue
    raise ActionError("no clipboard mechanism available")


# --- process replacement -------------------------------------------------------


@dataclass(slots=True)
class ExitRequest:
    """What run_session returns so the CLI can hand off cleanly after teardown."""

    kind: str  # "exec" | "print" | "cd" | "quit"
    argv: list[str] | None = None
    text: str | None = None
    path: Path | None = None
    status: int = 0


def resolve_program(argv: list[str]) -> list[str]:
    """``argv`` with its program resolved on ``PATH``, or an ActionError."""
    prog = shutil.which(argv[0])
    if prog is None:
        raise ActionError(f"{argv[0]}: not found")
    return [prog, *argv[1:]]


def run_foreground(argv: list[str]) -> int:
    """Run ``argv`` on this terminal and wait for it; the session carries on after.

    The caller must have given the terminal back first (``App.suspend``).
    """
    try:
        return subprocess.run(resolve_program(argv)).returncode  # noqa: S603
    except OSError as exc:
        raise ActionError(f"{argv[0]}: {exc}") from exc


def spawn_detached(argv: list[str]) -> None:
    prog = shutil.which(argv[0])
    if prog is None:
        raise ActionError(f"{argv[0]}: not found")
    kwargs = {}
    if os.name == "posix":
        kwargs["start_new_session"] = True
    subprocess.Popen(  # noqa: S603
        [prog, *argv[1:]],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        **kwargs,
    )


def perform_exec(argv: list[str]) -> None:
    """Replace this process with ``argv`` (POSIX) or run and exit (Windows)."""
    prog = shutil.which(argv[0])
    if prog is None:
        raise ActionError(f"{argv[0]}: not found")
    if os.name == "posix":
        os.execvp(prog, argv)
    else:  # pragma: no cover - platform specific
        raise SystemExit(subprocess.run([prog, *argv[1:]]).returncode)
