from __future__ import annotations

from seek.config import DEFAULT_KEYS
from seek.models import MatchKind
from seek.tui.help import help_text


def test_mode_words_share_their_initial_with_the_row_marker():
    # the status-bar mode indicator spells out these words; each starts with the
    # same letter used as that kind's row marker, so the two are learnable together
    assert MatchKind.FILENAME.marker == "files"[0]
    assert MatchKind.DIRNAME.marker == "dirs"[0]
    assert MatchKind.CONTENT.marker == "content"[0]


def test_help_documents_query_syntax():
    text = help_text(DEFAULT_KEYS)
    assert "Query syntax" in text
    assert "not a regular expression" in text
    for token in ("'foo", "^foo", "foo$", "!foo"):
        assert token in text
    assert "case-sensitive" in text


def test_help_is_grouped():
    text = help_text(DEFAULT_KEYS)
    for section in ("Navigate", "Act on a result", "Search scope"):
        assert section in text


def test_help_reflects_a_rebound_key():
    text = help_text(dict(DEFAULT_KEYS, copy="ctrl+w"))
    assert "^W" in text
    assert "copy path" in text
