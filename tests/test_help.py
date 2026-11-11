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


def test_the_viewer_help_names_the_tag_keys_and_their_limits():
    from seek.tui.nmap.help import _GROUPS

    tags = dict(_GROUPS)["Tags"]
    text = " ".join(f"{k} {v}" for k, v in tags)
    for key in ("t", "T", "R"):
        assert key in dict(tags), key
    for limit in ("?", "not scanned", "1 MiB", "not: without a port", "(a+)+"):
        assert limit in text, limit
    query = " ".join(v for _k, v in dict(_GROUPS)["Query the scan"])
    assert "tagged printer" in query
