"""Help overlay: the complete reference for operating the interface.

Groups every keybinding by purpose and documents the query grammar, so a user
who opens it once never needs external docs.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Static

from seek.tui.keyhints import pretty_key

# (section title, [(action-id-or-literal, description)]). An entry whose first
# element is a known action id is resolved through the user's keys; anything
# else is shown literally.
_GROUPS: list[tuple[str, list[tuple[str, str]]]] = [
    (
        "Navigate",
        [
            ("left / right", "move the query cursor"),
            ("up / down", "move the highlighted row"),
            ("pageup / pagedown", "page the list"),
            ("enter", "open the detail view"),
            ("history_prev", "recall the previous query"),
            ("history_next", "recall the next query"),
        ],
    ),
    (
        "Act on a result",
        [
            ("open_default", "open in the OS default app"),
            ("open_editor", "open in the editor"),
            ("open_code", "open in code"),
            ("copy", "copy path(s)"),
            ("export", "export (stdout / clipboard / file)"),
            ("goto_dir", "go to directory (cd)"),
            ("ctrl+p", "command palette — every action, searchable by name"),
            ("mark", "mark / unmark the row"),
            ("clear_marks", "clear all marks"),
            ("action_menu", "action menu (everything)"),
        ],
    ),
    (
        "Search scope",
        [
            ("toggle_file", "toggle filename matching"),
            ("toggle_dir", "toggle directory matching"),
            ("toggle_content", "toggle content matching"),
            ("toggle_format", "toggle re-indenting of minified files"),
            ("reroot", "re-root at the highlighted directory"),
            ("breadcrumb_pop", "pop one breadcrumb level"),
            ("refresh", "refresh (re-walk)"),
        ],
    ),
    (
        "Other",
        [
            ("escape", "clear query, then pop breadcrumb, then quit"),
            ("help", "this help"),
        ],
    ),
]

_SYNTAX: list[tuple[str, str]] = [
    ("foo bar", "fuzzy-match foo AND fuzzy-match bar"),
    ("'foo", "exact substring match"),
    ("^foo", "prefix-anchored match"),
    ("foo$", "suffix-anchored match"),
    ("^foo$", "whole-string match"),
    ("!foo", "negate a term (also !^foo, !foo$, !'foo)"),
    ("Foo", "an uppercase letter makes the term case-sensitive"),
]


def _key_for(keys: dict[str, str], token: str) -> str:
    parts = [p.strip() for p in token.split("/")]
    return " / ".join(
        pretty_key(keys[p]) if p in keys else pretty_key(p) for p in parts
    )


def help_text(keys: dict[str, str]) -> str:
    """The full reference body, resolved against the user's keybindings."""
    rows: list[str] = ["seek — reference", ""]
    for title, entries in _GROUPS:
        rows.append(title)
        for token, desc in entries:
            rows.append(f"  {_key_for(keys, token):<16} {desc}")
        rows.append("")
    rows.append("Query syntax  (fuzzy — not a regular expression)")
    for pat, desc in _SYNTAX:
        rows.append(f"  {pat:<10} {desc}")
    return "\n".join(rows)


class HelpScreen(ModalScreen[None]):
    BINDINGS = [("escape,question_mark,q,f1", "close", "Close")]
    DEFAULT_CSS = """
    HelpScreen { align: center middle; }
    HelpScreen > VerticalScroll {
        width: 72; height: auto; max-height: 90%;
        background: $panel; border: round $primary; padding: 1 2;
    }
    """

    def __init__(self, keys: dict[str, str]) -> None:
        super().__init__()
        self._keys = keys

    def compose(self) -> ComposeResult:
        with VerticalScroll():
            yield Static(help_text(self._keys))

    def action_close(self) -> None:
        self.dismiss(None)
