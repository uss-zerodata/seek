"""The full-screen detail reader: scrolling, search, and a live scan's log.

Driven directly (not through `NmapApp`) with a minimal host `App`, since the
reader is a self-contained modal - `tests/test_nmap_scanning.py` covers the
`d` / `D` wiring into the viewer itself.
"""

from __future__ import annotations

import pytest
from rich.console import Group
from rich.text import Text

from seek.tui.nmap.reader import DetailReader, render_to_lines

pytestmark = pytest.mark.asyncio


class _Host:
    """The smallest possible App: one screen, pushed on mount."""

    def __init__(self, reader: DetailReader):
        self._reader = reader

    def app_class(self):
        from textual.app import App

        reader = self._reader

        class Host(App):
            def on_mount(self) -> None:
                self.push_screen(reader)

        return Host


def _content(n: int = 200, marker_at: tuple[int, ...] = ()) -> Group:
    lines = [Text(f"line {i} filler text") for i in range(n)]
    for i in marker_at:
        lines[i] = Text(f"line {i} carries the MARKER word")
    return Group(*lines)


def _app(reader: DetailReader):
    return _Host(reader).app_class()()


# --- rendering ---------------------------------------------------------


# These two are pure and use no Textual App, but the module carries a
# blanket asyncio mark - `async def` keeps pytest-asyncio from warning.
async def test_render_to_lines_wraps_at_the_given_width_and_keeps_style():
    group = Group(Text("hello", style="bold"), Text("a rather long line of text", style="dim"))
    lines = render_to_lines(group, width=12)
    assert len(lines) > 2, "the long line wrapped onto more than one row"
    assert lines[0].spans and lines[0].spans[0].style.bold is True


async def test_render_to_lines_never_returns_nothing():
    assert render_to_lines(Text(""), width=40) == [Text("")]


# --- opening and scrolling ----------------------------------------------


async def test_opening_shows_the_title_and_the_content():
    reader = DetailReader("My Title", _content(5))
    app = _app(reader)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause(0.2)
        assert reader._lines[0].plain == "line 0 filler text"
        assert len(reader._lines) == 5


async def test_scrolling_moves_the_window():
    reader = DetailReader("T", _content(100))
    app = _app(reader)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause(0.2)
        start = reader.top_line
        await pilot.press("down")
        await pilot.pause(0.1)
        assert reader.top_line == start + 1
        await pilot.press("G")
        await pilot.pause(0.1)
        assert reader.top_line > start + 1, "G jumps to the end"
        await pilot.press("g")
        await pilot.pause(0.1)
        assert reader.top_line == 0


async def test_escape_dismisses_when_nothing_is_focused():
    reader = DetailReader("T", _content(5))
    app = _app(reader)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause(0.2)
        assert isinstance(app.screen, DetailReader)
        await pilot.press("escape")
        await pilot.pause(0.2)
        assert not isinstance(app.screen, DetailReader)


async def test_a_heading_free_of_content_shows_the_same_note_the_pane_would():
    """`d` on a row with nothing to say must not open an empty modal."""
    note = Text("Ports\n\nSelect a line under this heading to open what it counts.",
                style="dim")
    reader = DetailReader("Ports", note)
    app = _app(reader)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause(0.2)
        assert "Select a line under this heading" in "\n".join(
            line.plain for line in reader._lines)


# --- search --------------------------------------------------------------


async def test_the_first_keystroke_does_not_leak_into_the_search_box():
    """Textual auto-focuses the first focusable widget on mount - without a
    focusable body, the very "/" that opens search would be typed into the
    (still-hidden) Input instead of triggering the binding."""
    reader = DetailReader("T", _content(20))
    app = _app(reader)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("slash")
        await pilot.pause(0.1)
        assert reader.query_one("#search-input").value == ""


async def test_searching_highlights_every_occurrence_and_counts_them():
    reader = DetailReader("T", _content(200, marker_at=(10, 50, 190)))
    app = _app(reader)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("slash")
        for ch in "marker":
            await pilot.press(ch)
        await pilot.pause(0.2)
        assert len(reader._matches) == 3
        assert reader._match_index == 0
        assert "3 matches" in reader._controls_text()


async def test_search_is_case_insensitive():
    reader = DetailReader("T", _content(50, marker_at=(5,)))
    app = _app(reader)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("slash")
        for ch in "marker":
            await pilot.press(ch)
        await pilot.pause(0.2)
        assert len(reader._matches) == 1, "MARKER in the content, 'marker' typed"


async def test_a_search_matching_nothing_says_so():
    reader = DetailReader("T", _content(20))
    app = _app(reader)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("slash")
        for ch in "zzzznope":
            await pilot.press(ch)
        await pilot.pause(0.2)
        assert reader._matches == []
        assert "no matches" in reader._controls_text()


async def test_next_and_previous_move_between_matches_in_order():
    reader = DetailReader("T", _content(200, marker_at=(10, 50, 190)))
    app = _app(reader)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("slash")
        for ch in "marker":
            await pilot.press(ch)
        await pilot.pause(0.2)
        await pilot.press("enter")            # commit, give up the box
        await pilot.pause(0.1)
        assert reader._match_index == 0
        await pilot.press("n")
        await pilot.pause(0.1)
        assert reader._match_index == 1
        await pilot.press("n")
        await pilot.pause(0.1)
        assert reader._match_index == 2
        await pilot.press("n")                # wraps
        await pilot.pause(0.1)
        assert reader._match_index == 0
        await pilot.press("N")                # wraps the other way
        await pilot.pause(0.1)
        assert reader._match_index == 2
        # the matched line is actually visible, not just "current"
        line, _s, _e = reader._matches[reader._match_index]
        assert reader.top_line <= line < reader.top_line + reader._height()


async def test_clearing_the_search_keeps_the_reader_open():
    reader = DetailReader("T", _content(50, marker_at=(5,)))
    app = _app(reader)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("slash")
        for ch in "marker":
            await pilot.press(ch)
        await pilot.pause(0.2)
        assert reader._matches
        await pilot.press("escape")            # while the box is focused: clear
        await pilot.pause(0.2)
        assert isinstance(app.screen, DetailReader), "still open"
        assert reader._term == "" and reader._matches == []


async def test_escape_a_second_time_dismisses():
    reader = DetailReader("T", _content(20))
    app = _app(reader)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("slash")
        await pilot.press("x")
        await pilot.pause(0.1)
        await pilot.press("escape")            # clears
        await pilot.pause(0.1)
        assert isinstance(app.screen, DetailReader)
        await pilot.press("escape")            # now dismisses
        await pilot.pause(0.2)
        assert not isinstance(app.screen, DetailReader)


# --- live updates ----------------------------------------------------------


async def test_update_replaces_the_content():
    reader = DetailReader("T", _content(3))
    app = _app(reader)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause(0.2)
        reader.update(_content(3, marker_at=(1,)))
        await pilot.pause(0.1)
        assert "MARKER" in reader._lines[1].plain


async def test_following_the_tail_tracks_new_lines_until_scrolled_away():
    reader = DetailReader("T", _content(30), follow=True)
    app = _app(reader)
    async with app.run_test(size=(80, 10)) as pilot:
        await pilot.pause(0.2)
        assert reader._follow is True
        reader.update(_content(60))
        await pilot.pause(0.1)
        assert reader.top_line == max(0, 60 - reader._height())

        await pilot.press("up")               # scroll away: stop following
        await pilot.pause(0.1)
        assert reader._follow is False
        top_after_scroll = reader.top_line
        reader.update(_content(90))
        await pilot.pause(0.1)
        assert reader.top_line == top_after_scroll, "content grew, view held still"

        await pilot.press("G")                # explicitly back to the tail
        await pilot.pause(0.1)
        assert reader._follow is True


async def test_a_search_re_applies_to_lines_that_arrive_after_it_was_typed():
    reader = DetailReader("T", _content(5))
    app = _app(reader)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("slash")
        for ch in "marker":
            await pilot.press(ch)
        await pilot.pause(0.2)
        assert reader._matches == []
        reader.update(_content(6, marker_at=(5,)))
        await pilot.pause(0.1)
        assert len(reader._matches) == 1, "the new line was searched too"


async def test_freezing_calls_back_without_touching_the_process():
    """The reader owns no scan; freezing is entirely the callback's business -
    this only proves the reader invokes it and reflects the resulting content."""
    calls = []

    def toggle():
        calls.append(1)
        reader.update(Group(Text("frozen — the scan is still running"),
                            Text("line 1"), Text("line 2")))

    reader = DetailReader("T", _content(3), on_freeze=toggle)
    app = _app(reader)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("p")
        await pilot.pause(0.1)
        assert calls == [1]
        assert "frozen" in reader._lines[0].plain


async def test_freeze_is_a_no_op_when_no_callback_is_given():
    reader = DetailReader("T", _content(3))     # on_freeze omitted
    app = _app(reader)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("p")                  # must not raise
        await pilot.pause(0.1)
        assert isinstance(app.screen, DetailReader)


# --- stepping between entries ------------------------------------------


def _stepping_reader(entries: list[tuple[str, Group]]) -> tuple[DetailReader, dict]:
    """A reader wired to a fake list of `entries`, with the cursor in `state`."""
    state = {"at": 0}

    def on_step(delta: int):
        target = state["at"] + delta
        if not (0 <= target < len(entries)):
            return None            # the ends clamp, they do not wrap
        state["at"] = target
        title, content = entries[target]
        return title, content, False

    return DetailReader(entries[0][0], entries[0][1], on_step=on_step), state


async def test_right_and_left_move_to_the_neighbouring_entry():
    entries = [(f"Entry {i}", _content(30)) for i in range(3)]
    reader, state = _stepping_reader(entries)
    async with _app(reader).run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        assert reader._title == "Entry 0"
        await pilot.press("right")
        await pilot.pause()
        assert (reader._title, state["at"]) == ("Entry 1", 1)
        await pilot.press("right")
        await pilot.pause()
        assert (reader._title, state["at"]) == ("Entry 2", 2)
        await pilot.press("left")
        await pilot.pause()
        assert (reader._title, state["at"]) == ("Entry 1", 1)


async def test_h_and_l_step_entries_like_the_arrows():
    entries = [(f"Entry {i}", _content(30)) for i in range(3)]
    reader, state = _stepping_reader(entries)
    async with _app(reader).run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.press("l")
        await pilot.pause()
        assert state["at"] == 1
        await pilot.press("h")
        await pilot.pause()
        assert state["at"] == 0


async def test_stepping_stops_at_either_end_rather_than_wrapping():
    entries = [(f"Entry {i}", _content(30)) for i in range(2)]
    reader, state = _stepping_reader(entries)
    async with _app(reader).run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.press("left")          # already at the first
        await pilot.pause()
        assert (reader._title, state["at"]) == ("Entry 0", 0)
        await pilot.press("right")
        await pilot.press("right")         # already at the last
        await pilot.pause()
        assert (reader._title, state["at"]) == ("Entry 1", 1)


async def test_a_stepped_to_entry_is_read_from_its_top():
    entries = [(f"Entry {i}", _content(200)) for i in range(2)]
    reader, _state = _stepping_reader(entries)
    async with _app(reader).run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.press("G")
        await pilot.pause()
        assert reader.top_line > 0, "scrolled away from the top"
        await pilot.press("right")
        await pilot.pause()
        assert reader.top_line == 0


async def test_a_search_carries_across_entries_and_is_recounted():
    entries = [
        ("Entry 0", _content(60, marker_at=(3,))),
        ("Entry 1", _content(60, marker_at=(5, 9, 40))),
    ]
    reader, _state = _stepping_reader(entries)
    async with _app(reader).run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.press("slash")
        for char in "marker":
            await pilot.press(char)
        await pilot.pause()
        assert len(reader._matches) == 1
        await pilot.press("enter")         # give up the box, keep the term
        await pilot.press("right")
        await pilot.pause()
        assert reader._term == "marker", "the term survived the move"
        assert len(reader._matches) == 3, "recounted against the new entry"
        assert "3 matches" in reader._controls_text()
        await pilot.press("n")             # n goes to the first, not the second
        await pilot.pause()
        assert reader._match_index == 0
        assert "1/3 matches" in reader._controls_text()


async def test_the_step_hint_is_only_shown_when_stepping_is_wired():
    entries = [("Entry 0", _content(10))]
    stepping, _state = _stepping_reader(entries)
    assert "←/→ entry" in stepping._controls_text()
    assert "←/→ entry" not in DetailReader("Alone", _content(10))._controls_text()


async def test_stepping_is_a_no_op_when_the_reader_has_no_list_behind_it():
    reader = DetailReader("Alone", _content(30))
    async with _app(reader).run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.press("right")
        await pilot.pause()
        assert reader._title == "Alone"
