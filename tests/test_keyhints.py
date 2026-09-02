from __future__ import annotations

from seek.config import DEFAULT_KEYS
from seek.tui.keyhints import pretty_key


def test_pretty_key_known_forms():
    assert pretty_key("ctrl+e") == "^E"
    assert pretty_key("alt+up") == "⌥↑"
    assert pretty_key("shift+tab") == "⇧⇥"
    assert pretty_key("ctrl+underscore") == "^_"
    assert pretty_key("question_mark") == "?"
    assert pretty_key("tab") == "⇥"
    assert pretty_key("escape") == "Esc"
    assert pretty_key("f1") == "F1"


def test_pretty_key_takes_first_alternative():
    assert pretty_key("escape,q") == "Esc"


def test_pretty_key_covers_every_default_binding():
    for spec in DEFAULT_KEYS.values():
        assert pretty_key(spec)  # non-empty, no crash
