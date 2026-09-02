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
    # Multiple targets: one invocation, program name + every file, no line jump.
    argv = _fill_template(template, "\x00", None)
    prog = [a for a in argv if a != "\x00"][:1]
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
    try:
        import pyperclip

        pyperclip.copy(text)
        return
    except Exception:  # noqa: BLE001 - pyperclip raises many things
        pass
    for argv in _CLIPBOARD_FALLBACKS:
        if shutil.which(argv[0]):
            try:
                subprocess.run(argv, input=text.encode("utf-8"), check=True)
                return
            except (OSError, subprocess.CalledProcessError):
                continue
    raise ActionError("no clipboard mechanism available")


# --- process replacement -------------------------------------------------------


@dataclass(slots=True)
class ExitRequest:
    """What run_session returns so the CLI can hand off cleanly after teardown."""

    kind: str  # "exec" | "spawn" | "print" | "cd" | "quit"
    argv: list[str] | None = None
    argvs: list[list[str]] | None = None  # for kind == "spawn": one process each
    text: str | None = None
    path: Path | None = None
    status: int = 0


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
