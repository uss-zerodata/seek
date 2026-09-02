"""Shared key-name prettifier for the hint bar and the help overlay.

Textual key specs (``ctrl+e``, ``alt+up``, ``question_mark``) are turned into
compact display forms (``^E``, ``⌥↑``, ``?``) so the hint bar and the help
overlay always show a rebound key the same way.
"""

from __future__ import annotations

_MODS: dict[str, str] = {
    "ctrl": "^",
    "control": "^",
    "alt": "⌥",
    "option": "⌥",
    "meta": "⌥",
    "shift": "⇧",
    "cmd": "⌘",
    "super": "◆",
}

_NAMES: dict[str, str] = {
    "question_mark": "?",
    "underscore": "_",
    "up": "↑",
    "down": "↓",
    "left": "←",
    "right": "→",
    "pageup": "PgUp",
    "pagedown": "PgDn",
    "enter": "↵",
    "return": "↵",
    "escape": "Esc",
    "tab": "⇥",
    "space": "Space",
    "backspace": "⌫",
    "delete": "Del",
    "home": "Home",
    "end": "End",
}


def pretty_key(spec: str) -> str:
    """Compact display form of one Textual key spec.

    Comma-separated alternatives are allowed; the first is used.
    """
    spec = spec.split(",")[0].strip()
    if not spec:
        return ""
    *mods, base = spec.split("+")
    prefix = "".join(_MODS.get(m.lower(), f"{m}+") for m in mods)
    low = base.lower()
    if low in _NAMES:
        shown = _NAMES[low]
    elif len(base) == 1:
        shown = base.upper()
    elif low.startswith("f") and low[1:].isdigit():
        shown = low.upper()
    else:
        shown = base.capitalize()
    return prefix + shown

