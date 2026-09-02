"""``seek init`` shell-integration code and the directory hand-off channel.

The wrapper function passes a scratch file path to the program in
``SEEK_CD_FILE``. On a "go to directory" action the program writes the chosen
directory there (see :func:`write_cd_target`); the wrapper reads it and ``cd``s.
The interactive UI renders to ``/dev/tty``, so stdout and the scratch file stay
clean.
"""

from __future__ import annotations

import os
from pathlib import Path

SUPPORTED_SHELLS = {"bash", "zsh"}

_CD_ENV = "SEEK_CD_FILE"

_COMMON_BODY = r"""
seek() {{
    local _seek_cd _seek_status
    _seek_cd="$(command mktemp "${{TMPDIR:-/tmp}}/seek-cd.XXXXXX")" || return 1
    {invoke}
    _seek_status=$?
    if [ -s "$_seek_cd" ]; then
        local _seek_dir
        _seek_dir="$(command cat "$_seek_cd")"
        [ -d "$_seek_dir" ] && cd -- "$_seek_dir"
    fi
    command rm -f "$_seek_cd"
    return $_seek_status
}}
""".strip()

_INVOKE_BASH = (
    'if [ -n "${SEEK_BIN:-}" ]; then\n'
    f'        {_CD_ENV}="$_seek_cd" $SEEK_BIN "$@"\n'
    "    else\n"
    f'        {_CD_ENV}="$_seek_cd" command seek "$@"\n'
    "    fi"
)

_INVOKE_ZSH = (
    'if [ -n "${SEEK_BIN:-}" ]; then\n'
    f'        {_CD_ENV}="$_seek_cd" ${{=SEEK_BIN}} "$@"\n'
    "    else\n"
    f'        {_CD_ENV}="$_seek_cd" command seek "$@"\n'
    "    fi"
)


def render_init(shell: str) -> str:
    if shell == "bash":
        body = _COMMON_BODY.format(invoke=_INVOKE_BASH)
    elif shell == "zsh":
        body = _COMMON_BODY.format(invoke=_INVOKE_ZSH)
    else:  # pragma: no cover - guarded by the CLI
        raise ValueError(shell)
    header = (
        "# seek shell integration - add to your rc file:\n"
        f'#   eval "$(seek init {shell})"\n'
        "# Set SEEK_BIN to override how the program is invoked "
        '(e.g. SEEK_BIN="uv run seek").\n'
    )
    return header + body + "\n"


def cd_channel_path() -> Path | None:
    """The scratch file the wrapper is listening on, if any."""
    value = os.environ.get(_CD_ENV)
    return Path(value) if value else None


def write_cd_target(directory: Path) -> bool:
    """Report a chosen directory back to the shell wrapper.

    Returns True if the wrapper channel was used, False if the caller should
    fall back to printing the path on stdout.
    """
    channel = cd_channel_path()
    if channel is None:
        return False
    try:
        channel.write_text(str(directory), encoding="utf-8")
        return True
    except OSError:
        return False
