from __future__ import annotations

import pytest
from textual.containers import VerticalScroll
from textual.geometry import Region
from textual.widgets import Input, OptionList

from seek.config import DEFAULT_KEYS, Config
from seek.engine.engine import Modes
from seek.models import MatchKind, ResultSet, ResultSetState
from seek.scope import build_scope
from seek.session import SessionConfig
from seek.tui.app import _SPINNER, SeekApp
from seek.tui.results import ResultsList

pytestmark = pytest.mark.asyncio


def _session(tree, **kw) -> SessionConfig:
    return SessionConfig(
        root=tree,
        modes=kw.get("modes", Modes()),
        scope=kw.get("scope", build_scope([], regex=False)),
        config=kw.get("config", Config(debounce_ms=10)),
        patterns=kw.get("patterns", []),
    )


async def _settle(pilot, tries: int = 40):
    for _ in range(tries):
        await pilot.pause(0.05)
        if not pilot.app.store.scanning:
            return
    await pilot.pause(0.1)


async def test_streaming_then_query(tree):
    app = SeekApp(_session(tree))
    async with app.run_test() as pilot:
        await _settle(pilot)
        assert len(app.store) > 0
        await pilot.press(*"main")
        await pilot.pause(0.2)
        rl = app.query_one(ResultsList)
        assert rl.results
        assert any(r.rel == "src/main.py" for r in rl.results)


async def test_empty_query_shows_tree(tree):
    app = SeekApp(_session(tree))
    async with app.run_test() as pilot:
        await _settle(pilot)
        assert app.query_one("#tree", VerticalScroll).display is True
        assert app.query_one(ResultsList).display is False
        await pilot.press(*"main")
        await pilot.pause(0.2)
        assert app.query_one(ResultsList).display is True
        for _ in range(4):
            await pilot.press("backspace")
        await pilot.pause(0.2)
        assert app.query_one("#tree", VerticalScroll).display is True


async def test_query_box_keeps_focus_and_letters_edit(tree):
    app = SeekApp(_session(tree))
    async with app.run_test() as pilot:
        await _settle(pilot)
        await pilot.press(*"abc")
        assert app.query_one("#query", Input).value == "abc"
        assert app.focused is app.query_one("#query", Input)


async def test_mode_toggle_recompute(tree):
    app = SeekApp(_session(tree))
    async with app.run_test() as pilot:
        await _settle(pilot)
        await pilot.press(*"hello")
        await pilot.pause(0.2)
        rl = app.query_one(ResultsList)
        assert any(r.kind is MatchKind.CONTENT for r in rl.results)
        await pilot.press("ctrl+c")  # toggle content off
        await pilot.pause(0.2)
        assert app.modes.content is False
        assert all(r.kind is not MatchKind.CONTENT for r in rl.results)


async def test_multiselect_persists_across_requery(tree):
    app = SeekApp(_session(tree))
    async with app.run_test() as pilot:
        await _settle(pilot)
        await pilot.press(*"main")
        await pilot.pause(0.2)
        rl = app.query_one(ResultsList)
        first = rl.current()
        await pilot.press("tab")
        assert first.identity() in rl.marked
        await pilot.press("p")  # "main" -> "mainp", still fuzzy-matches src/main.py
        await pilot.pause(0.2)
        await pilot.press("backspace")
        await pilot.pause(0.2)
        assert first.identity() in rl.marked
        await pilot.press("shift+tab")
        assert not rl.marked


async def test_navigation_updates_preview(tree):
    app = SeekApp(_session(tree))
    async with app.run_test() as pilot:
        await _settle(pilot)
        await pilot.press(*"py")
        await pilot.pause(0.2)
        rl = app.query_one(ResultsList)
        if len(rl.results) > 1:
            # cursor starts on the best match at the bottom
            assert rl.highlighted == len(rl.results) - 1
            start = rl.highlighted
            await pilot.press("up")
            assert rl.highlighted == start - 1


async def test_detail_view_roundtrip_preserves_state(tree):
    app = SeekApp(_session(tree))
    async with app.run_test() as pilot:
        await _settle(pilot)
        await pilot.press(*"main")
        await pilot.pause(0.2)
        rl = app.query_one(ResultsList)
        await pilot.press("tab")
        marked = set(rl.marked)
        query = app.query_one("#query", Input).value
        await pilot.press("enter")
        await pilot.pause(0.1)
        await pilot.press("escape")
        await pilot.pause(0.1)
        assert app.query_one("#query", Input).value == query
        assert set(app.query_one(ResultsList).marked) == marked


async def test_reroot_and_breadcrumb_pop(tree):
    app = SeekApp(_session(tree))
    async with app.run_test() as pilot:
        await _settle(pilot)
        await pilot.press(*"src")
        await pilot.pause(0.2)
        rl = app.query_one(ResultsList)
        idx = next(
            i for i, r in enumerate(rl.results)
            if r.kind is MatchKind.DIRNAME and r.rel == "src"
        )
        rl.highlighted = idx
        await pilot.press("ctrl+r")
        await _settle(pilot)
        assert app.root == tree / "src"
        assert len(app._breadcrumb) == 2
        await pilot.press("alt+left")
        await _settle(pilot)
        assert app.root == tree
        assert len(app._breadcrumb) == 1
        # cannot pop past launch root
        await pilot.press("alt+left")
        assert app.root == tree


async def test_layout_query_at_bottom_preview_above_list(tree):
    app = SeekApp(_session(tree))
    async with app.run_test(size=(120, 40)) as pilot:
        await _settle(pilot)
        kids = [w.id or type(w).__name__ for w in app.screen.children]
        assert kids[0] == "preview"
        assert kids[-1] == "prompt-row"  # holds the query input
        assert kids.index("preview") < kids.index("ResultsList")
        # the query input is inside the bottom row
        assert app.query_one("#prompt-row").query("#query")


async def test_best_match_at_bottom_cursor_on_best(tree):
    app = SeekApp(_session(tree))
    async with app.run_test(size=(120, 40)) as pilot:
        await _settle(pilot)
        await pilot.press(*"main")
        await pilot.pause(0.2)
        rl = app.query_one(ResultsList)
        assert len(rl.results) > 1
        # display order is worst -> best; scores non-decreasing down the list
        scores = [r.score for r in rl.results]
        assert scores == sorted(scores)
        # cursor sits on the best match, at the bottom
        assert rl.highlighted == len(rl.results) - 1
        assert rl.current().score == max(scores)


async def test_preview_hidden_on_short_terminal(tree):
    app = SeekApp(_session(tree))
    async with app.run_test(size=(120, 40)) as pilot:
        await _settle(pilot)
        await pilot.press(*"main")
        await pilot.pause(0.2)
        assert app.query_one("#preview").display is True
        await pilot.resize_terminal(120, 10)
        await pilot.pause(0.5)
        assert app.query_one("#preview").display is False
        assert app.query_one(ResultsList).display is True
        await pilot.resize_terminal(120, 40)
        await pilot.pause(0.5)
        assert app.query_one("#preview").display is True


async def test_export_order_is_best_first(tree):
    app = SeekApp(_session(tree))
    async with app.run_test(size=(120, 40)) as pilot:
        await _settle(pilot)
        await pilot.press(*"main")
        await pilot.pause(0.2)
        rl = app.query_one(ResultsList)
        ranked = rl.ranked()
        assert [r.score for r in ranked] == sorted(
            (r.score for r in ranked), reverse=True
        )


async def test_rows_do_not_wrap_by_default(tmp_path):
    (tmp_path / "big.py").write_text("x\n" + "q " * 400 + "needle" + " z" * 400 + "\n")
    app = SeekApp(_session(tmp_path, config=Config(debounce_ms=10)))
    async with app.run_test(size=(60, 20)) as pilot:
        await _settle(pilot)
        await pilot.press(*"needle")
        await pilot.pause(0.3)
        rl = app.query_one(ResultsList)
        # one screen line per option -> no wrapping
        assert len(rl._line_cache.lines) == rl.option_count
        row = rl.render_line(rl.option_count - 1).text
        assert "needle" in row  # match kept visible
        assert len(row) <= rl._budget() + 1


async def test_wrap_results_config_wraps(tmp_path):
    (tmp_path / "big.py").write_text("x\n" + "q " * 300 + "needle\n")
    app = SeekApp(_session(tmp_path, config=Config(debounce_ms=10, wrap_results=True)))
    async with app.run_test(size=(60, 20)) as pilot:
        await _settle(pilot)
        await pilot.press(*"needle")
        await pilot.pause(0.3)
        rl = app.query_one(ResultsList)
        assert len(rl._line_cache.lines) > rl.option_count  # wrapped


async def test_row_path_and_content_differ_in_colour(tmp_path):
    (tmp_path / "code.py").write_text("alpha needle beta\n")
    app = SeekApp(_session(tmp_path, config=Config(debounce_ms=10)))
    async with app.run_test(size=(80, 20)) as pilot:
        await _settle(pilot)
        await pilot.press(*"needle")
        await pilot.pause(0.3)
        rl = app.query_one(ResultsList)
        row = next(i for i, r in enumerate(rl.results) if r.kind is MatchKind.CONTENT)
        segs = [s for s in rl.render_line(row) if s.text.strip()]
        path_seg = next(s for s in segs if "code.py" in s.text)
        content_seg = next(s for s in segs if s.text.strip() == "alpha")
        assert path_seg.style.color != content_seg.style.color


async def test_scroll_up_at_top_does_not_error(tree):
    app = SeekApp(_session(tree))
    async with app.run_test() as pilot:
        await _settle(pilot)
        await pilot.press(*"main")
        await pilot.pause(0.2)
        for _ in range(30):  # walk past the top of the list
            await pilot.press("up")
        await pilot.pause(0.2)
        assert app.query_one(ResultsList).highlighted == 0


async def test_preview_centres_on_matched_line(tmp_path):
    lines = [f"line {i}" for i in range(400)]
    lines[250] = "the needle is here"
    (tmp_path / "f.txt").write_text("\n".join(lines) + "\n")
    app = SeekApp(_session(tmp_path, config=Config(debounce_ms=10)))
    async with app.run_test(size=(100, 40)) as pilot:
        await _settle(pilot)
        await pilot.press(*"needle")
        await pilot.pause(0.4)
        preview = app.query_one("#preview")
        region = Region(0, 0, preview.size.width, preview.size.height)
        shown = "\n".join(
            "".join(seg.text for seg in strip) for strip in preview.render_lines(region)
        )
        assert "251" in shown  # 1-based line number of the match is visible
        assert "line 249" in shown and "line 253" in shown  # context around it


async def test_detail_view_scrolls_with_keys(tmp_path):
    """The pager moves a line offset; only the visible slice is ever rendered."""
    (tmp_path / "f.txt").write_text("\n".join(f"row {i}" for i in range(300)) + "\n")
    app = SeekApp(_session(tmp_path, config=Config(debounce_ms=10)))
    async with app.run_test(size=(100, 30)) as pilot:
        await _settle(pilot)
        await pilot.press(*"row")
        await pilot.pause(0.3)
        await pilot.press("enter")
        await pilot.pause(0.4)

        screen = app.screen
        start = screen.top_line
        await pilot.press("down", "down", "down")
        await pilot.pause(0.1)
        assert screen.top_line == start + 3
        await pilot.press("G")
        await pilot.pause(0.1)
        assert screen.top_line > start + 100
        assert "row 299" in _render(screen.query_one("#detail-body"))
        await pilot.press("g")
        await pilot.pause(0.1)
        assert screen.top_line == 1
        assert "row 0" in _render(screen.query_one("#detail-body"))
        await pilot.press("pagedown")
        await pilot.pause(0.1)
        assert screen.top_line > 1


async def test_result_cap_reflected_in_list_and_status(tmp_path):
    for i in range(40):
        (tmp_path / f"needlefile_{i}.py").write_text("x\n")
    app = SeekApp(_session(tmp_path, config=Config(debounce_ms=10, max_results=10)))
    async with app.run_test(size=(100, 30)) as pilot:
        await _settle(pilot)
        await pilot.press(*"needlefile")
        await pilot.pause(0.3)
        rl = app.query_one(ResultsList)
        assert len(rl.results) == 10
        status = app.query_one("#status")
        region = Region(0, 0, status.size.width, 1)
        text = "".join(s.text for s in status.render_lines(region)[0])
        assert "10/" in text


async def test_cursor_preserved_on_progressive_update(tmp_path):
    for i in range(20):
        (tmp_path / f"a{i}.txt").write_text("needle\n")
    app = SeekApp(_session(tmp_path, config=Config(debounce_ms=10)))
    async with app.run_test(size=(100, 30)) as pilot:
        await _settle(pilot)
        await pilot.press(*"needle")
        await pilot.pause(0.3)
        rl = app.query_one(ResultsList)
        rl.highlighted = 3
        keep = rl.current().identity()
        # a progressive update for the SAME query must not move the cursor
        app._apply_results(
            ResultSet(ResultSetState.RESULTS, rl.ranked(), app._generation,
                      False, total=99, partial=True),
            app._applied_query,
        )
        await pilot.pause(0.1)
        assert rl.current().identity() == keep


async def test_goto_dir_on_file_uses_parent(tree):
    app = SeekApp(_session(tree))
    async with app.run_test() as pilot:
        await _settle(pilot)
        await pilot.press(*"mainpy")
        await pilot.pause(0.2)
        rl = app.query_one(ResultsList)
        idx = next(
            i for i, r in enumerate(rl.results)
            if r.kind is MatchKind.FILENAME and r.rel == "src/main.py"
        )
        rl.highlighted = idx
        await pilot.press("alt+c")
        await pilot.pause(0.1)
    assert app.exit_request.kind == "cd"
    assert app.exit_request.path == tree / "src"


async def test_preview_has_header(tmp_path):
    (tmp_path / "code.py").write_text("import os\nneedle = 1\nprint(needle)\n")
    app = SeekApp(_session(tmp_path, config=Config(debounce_ms=10)))
    async with app.run_test(size=(100, 40)) as pilot:
        await _settle(pilot)
        await pilot.press(*"needle")
        await pilot.pause(0.4)
        preview = app.query_one("#preview")
        region = Region(0, 0, preview.size.width, preview.size.height)
        shown = "\n".join(
            "".join(s.text for s in strip) for strip in preview.render_lines(region)
        )
        assert "code.py:2" in shown
        assert "lines" in shown  # "· python · N lines"


async def test_mouse_click_highlights_row(tree):
    app = SeekApp(_session(tree))
    async with app.run_test(size=(120, 40)) as pilot:
        await _settle(pilot)
        await pilot.press(*"py")
        await pilot.pause(0.2)
        rl = app.query_one(ResultsList)
        if len(rl.results) < 2:
            return
        rl.highlighted = 0
        await pilot.click(ResultsList, offset=(2, 1))
        await pilot.pause(0.1)
        assert rl.highlighted == 1


async def test_no_match_state(tree):
    app = SeekApp(_session(tree))
    async with app.run_test() as pilot:
        await _settle(pilot)
        await pilot.press(*"zzqqnotthere")
        await pilot.pause(0.2)
        assert app._no_match is True
        assert app.query_one(ResultsList).results == []
        # the nomatch element is shown in place of the list
        hint = app.query_one("#nomatch")
        assert hint.display is True
        assert app.query_one(ResultsList).display is False
        region = Region(0, 0, hint.size.width, hint.size.height)
        shown = "\n".join(
            "".join(s.text for s in strip) for strip in hint.render_lines(region)
        )
        assert "no matches" in shown
        # settled message steers the user away from regex and points at help
        assert "fuzzy" in shown and "regex" in shown
        # preview is dropped when there's nothing to show
        assert app.query_one("#preview").display is False


def _render(widget) -> str:
    region = Region(0, 0, widget.size.width, max(1, widget.size.height))
    return "\n".join(
        "".join(s.text for s in strip) for strip in widget.render_lines(region)
    )


async def test_no_match_note_mentions_disabled_content_mode(tree):
    app = SeekApp(_session(tree, modes=Modes(file=True, dir=True, content=False)))
    async with app.run_test() as pilot:
        await _settle(pilot)
        await pilot.press(*"zzqqnotthere")
        await pilot.pause(0.2)
        shown = _render(app.query_one("#nomatch"))
        assert "content" in shown.lower()


async def test_hint_bar_always_visible_and_context_aware(tree):
    app = SeekApp(_session(tree))
    async with app.run_test(size=(120, 40)) as pilot:
        await _settle(pilot)
        bar = app.query_one("#hint-bar")
        assert bar.display is True
        assert "type to search" in _render(bar)  # tree context
        await pilot.press(*"main")
        await pilot.pause(0.2)
        results_hints = _render(bar)
        assert "view" in results_hints and "edit" in results_hints  # results context


async def test_result_area_fenced_by_rule_not_filled_band(tree):
    app = SeekApp(_session(tree))
    async with app.run_test(size=(120, 40)) as pilot:
        await _settle(pilot)
        await pilot.press(*"main")
        await pilot.pause(0.2)
        # the divider is a border rule under the result list...
        assert app.query_one(ResultsList).styles.border_bottom[0] == "solid"
        # ...not a filled background on the status / hint lines
        assert app.query_one("#status").styles.background.a == 0
        assert app.query_one("#hint-bar").styles.background.a == 0


async def test_search_waits_for_the_query_to_go_idle(tree):
    app = SeekApp(_session(tree, config=Config(debounce_ms=150)))
    async with app.run_test() as pilot:
        await _settle(pilot)
        assert app._applied_query is None
        for ch in "main":
            await pilot.press(ch)
            await pilot.pause(0.04)  # keystrokes 40ms apart, under the 150ms debounce
        assert app._searching is False       # nothing started yet
        assert app._applied_query is None    # no results applied yet
        await pilot.pause(0.35)               # now idle past 150ms
        assert app._applied_query == "main"
        assert any(r.rel == "src/main.py" for r in app.query_one(ResultsList).results)


async def test_query_change_cancels_the_in_flight_search(tree):
    app = SeekApp(_session(tree, config=Config(debounce_ms=10)))
    async with app.run_test() as pilot:
        await _settle(pilot)
        await pilot.press(*"main")
        await pilot.pause(0.05)
        app._searching = True          # pretend a slow search is still running
        gen = app._generation
        await pilot.press("x")         # any edit
        await pilot.pause(0.01)
        assert app._generation != gen  # in-flight generation invalidated at once
        assert app._searching is False


async def test_streaming_indicator_during_search(tree):
    app = SeekApp(_session(tree))
    async with app.run_test(size=(120, 40)) as pilot:
        await _settle(pilot)  # initial walk finished
        assert app._searching is False
        app._searching = True
        app._refresh_status()
        await pilot.pause(0.15)  # let a tick animate the prompt
        assert "searching" in _render(app.query_one("#status"))
        assert _render(app.query_one("#prompt")).strip() in _SPINNER
        app._searching = False
        app._refresh_status()
        assert _render(app.query_one("#prompt")).strip() == "❯"


async def test_streaming_indicator_clears_when_results_settle(tree):
    app = SeekApp(_session(tree))
    async with app.run_test(size=(120, 40)) as pilot:
        await _settle(pilot)
        await pilot.press(*"main")
        await pilot.pause(0.3)
        assert app._searching is False
        assert "searching" not in _render(app.query_one("#status"))


async def test_hint_bar_survives_short_terminal(tree):
    app = SeekApp(_session(tree))
    async with app.run_test(size=(120, 40)) as pilot:
        await _settle(pilot)
        await pilot.press(*"main")
        await pilot.pause(0.2)
        await pilot.resize_terminal(120, 8)
        await pilot.pause(0.4)
        assert app.query_one("#preview").display is False
        assert app.query_one("#hint-bar").display is True


async def test_hint_bar_reflects_rebound_key_and_esc_state(tree):
    cfg = Config(debounce_ms=10, keys=dict(DEFAULT_KEYS, copy="ctrl+w"))
    app = SeekApp(_session(tree, config=cfg))
    async with app.run_test(size=(120, 40)) as pilot:
        await _settle(pilot)
        assert "quit" in _render(app.query_one("#hint-bar"))  # empty query
        await pilot.press(*"main")
        await pilot.pause(0.2)
        shown = _render(app.query_one("#hint-bar"))
        assert "^W copy" in shown
        assert "clear query" in shown  # esc now clears


async def test_mode_indicator_is_self_describing(tree):
    app = SeekApp(_session(tree))
    async with app.run_test(size=(120, 40)) as pilot:
        await _settle(pilot)
        await pilot.press(*"main")
        await pilot.pause(0.2)
        status = _render(app.query_one("#status"))
        assert "files" in status and "dirs" in status and "content" in status
        assert "toggle" in status and "^F" in status


async def test_esc_clears_query_before_quitting(tree):
    app = SeekApp(_session(tree))
    async with app.run_test() as pilot:
        await _settle(pilot)
        await pilot.press(*"main")
        await pilot.pause(0.2)
        await pilot.press("escape")
        await pilot.pause(0.1)
        assert app.query_one("#query", Input).value == ""
        assert app.is_running  # did not quit
        assert app.query_one("#tree", VerticalScroll).display is True


async def test_open_from_detail_view_runs_the_action(tree):
    app = SeekApp(_session(tree))
    async with app.run_test(size=(120, 40)) as pilot:
        await _settle(pilot)
        await pilot.press(*"mainpy")
        await pilot.pause(0.2)
        await pilot.press("enter")
        await pilot.pause(0.2)
        assert "edit" in _render(app.screen.query_one(".controls"))
        await pilot.press("ctrl+e")  # open in editor from the detail view
        await pilot.pause(0.2)
    assert app.exit_request is not None
    assert app.exit_request.kind == "exec"


async def test_empty_state_heading(tree):
    app = SeekApp(_session(tree))
    async with app.run_test(size=(120, 40)) as pilot:
        await _settle(pilot)
        shown = _render(app.query_one("#tree-body"))
        assert f"root: {tree.name}" in shown
        assert ".gitignore off" in shown


async def test_refresh_picks_up_new_file(tree):
    app = SeekApp(_session(tree))
    async with app.run_test() as pilot:
        await _settle(pilot)
        await pilot.press(*"freshzz")
        await pilot.pause(0.2)
        (tree / "freshzz.txt").write_text("hi\n")
        await pilot.press("ctrl+g")
        await _settle(pilot)
        await pilot.pause(0.2)
        rl = app.query_one(ResultsList)
        assert any(r.rel == "freshzz.txt" for r in rl.results)


async def test_help_overlay(tree):
    app = SeekApp(_session(tree))
    async with app.run_test() as pilot:
        await _settle(pilot)
        await pilot.press("question_mark")
        await pilot.pause(0.1)
        assert app.screen is not app.screen_stack[0]
        await pilot.press("escape")
        await pilot.pause(0.1)
        assert app.screen is app.screen_stack[0]


async def test_quit_from_top_level(tree):
    app = SeekApp(_session(tree))
    async with app.run_test() as pilot:
        await _settle(pilot)
        await pilot.press("escape")
        await pilot.pause(0.1)
    assert app.return_code == 0


async def test_esc_pops_breadcrumb_before_quitting(tree):
    app = SeekApp(_session(tree))
    async with app.run_test() as pilot:
        await _settle(pilot)
        await pilot.press(*"src")
        await pilot.pause(0.2)
        rl = app.query_one(ResultsList)
        idx = next(
            i for i, r in enumerate(rl.results)
            if r.kind is MatchKind.DIRNAME and r.rel == "src"
        )
        rl.highlighted = idx
        await pilot.press("ctrl+r")
        await _settle(pilot)
        assert app.root == tree / "src"
        await pilot.press("escape")  # clears the "src" query
        await pilot.pause(0.1)
        await pilot.press("escape")  # pops the breadcrumb
        await _settle(pilot)
        assert app.root == tree
        assert app.is_running


async def test_copy_stays_in_session(tree, monkeypatch):
    captured = {}
    monkeypatch.setattr("seek.actions.copy_to_clipboard", lambda text: captured.update(text=text))
    app = SeekApp(_session(tree))
    async with app.run_test() as pilot:
        await _settle(pilot)
        await pilot.press(*"main")
        await pilot.pause(0.2)
        await pilot.press("ctrl+y")
        await pilot.pause(0.2)
        assert "text" in captured
        assert app.is_running


async def test_export_to_file_stays_in_session(tree, tmp_path):
    out = tmp_path / "out.txt"
    app = SeekApp(_session(tree))
    async with app.run_test() as pilot:
        await _settle(pilot)
        await pilot.press(*"main")
        await pilot.pause(0.2)
        await pilot.press("ctrl+x")
        await pilot.pause(0.2)
        # the choices are an option list, so pick the way the keyboard does
        options = app.screen.query_one(OptionList)
        options.highlighted = options.get_option_index("file")
        await pilot.press("enter")
        await pilot.pause(0.2)
        for ch in str(out):
            await pilot.press(ch if ch != "/" else "slash")
        await pilot.press("enter")
        await pilot.pause(0.2)
        assert app.is_running
    assert out.exists()
    assert "main" in out.read_text()


async def test_goto_dir_sets_exit_request(tree):
    app = SeekApp(_session(tree))
    async with app.run_test() as pilot:
        await _settle(pilot)
        await pilot.press(*"docs")
        await pilot.pause(0.2)
        rl = app.query_one(ResultsList)
        idx = next(
            i for i, r in enumerate(rl.results)
            if r.kind is MatchKind.DIRNAME and r.rel == "docs"
        )
        rl.highlighted = idx
        await pilot.press("alt+c")
        await pilot.pause(0.1)
    assert app.exit_request is not None
    assert app.exit_request.kind == "cd"
    assert app.exit_request.path == tree / "docs"


async def test_refresh_picks_up_an_edit_made_on_disk(tree):
    """`Ctrl+G` is the escape hatch from "files are stable for this session".

    It used to drop only the cached *walk*. The content cache is keyed on path
    with no mtime check, so a content search after the refresh still answered
    from text read before the edit - the search reported a line that was no
    longer in the file, and missed the one that was.
    """
    app = SeekApp(_session(tree))
    async with app.run_test() as pilot:
        await _settle(pilot)
        q = app.query_one("#query", Input)
        q.value = "hello"
        await pilot.pause(0.3)
        rl = app.query_one(ResultsList)
        assert any(r.kind is MatchKind.CONTENT for r in rl.results)

        (tree / "src" / "main.py").write_text("def main():\n    print('goodbye moon')\n")

        app.action_seek_refresh()
        await _settle(pilot)
        await pilot.pause(0.3)
        assert not any(r.kind is MatchKind.CONTENT for r in rl.results), (
            "the removed line must not still be reported"
        )

        q.value = "goodbye"
        await pilot.pause(0.3)
        assert any(r.kind is MatchKind.CONTENT for r in rl.results), (
            "the new line must be found"
        )


async def test_rebinding_a_key_withdraws_the_default_it_replaced(tree):
    """`[keys]` moves an action; it does not give it a second home.

    `on_mount` used to add the user's key without removing the built-in one, so
    `copy = "ctrl+w"` left `ctrl+y` running copy as well - the key the user had
    freed for something else was not actually free.
    """
    cfg = Config(debounce_ms=10, keys=dict(DEFAULT_KEYS, copy="ctrl+w"))
    app = SeekApp(_session(tree, config=cfg))
    async with app.run_test(size=(120, 40)) as pilot:
        await _settle(pilot)
        bound = app.screen.active_bindings
        assert bound["ctrl+w"].binding.action == "seek_copy"
        assert "ctrl+y" not in bound, "the default must be withdrawn, not kept alongside"


async def test_two_actions_can_swap_their_keys(tree):
    """Withdrawing by action rather than by key makes a swap resolve."""
    cfg = Config(
        debounce_ms=10,
        keys=dict(DEFAULT_KEYS, copy="ctrl+e", open_editor="ctrl+y"),
    )
    app = SeekApp(_session(tree, config=cfg))
    async with app.run_test(size=(120, 40)) as pilot:
        await _settle(pilot)
        bound = app.screen.active_bindings
        assert bound["ctrl+e"].binding.action == "seek_copy"
        assert bound["ctrl+y"].binding.action == "seek_open_editor"


async def test_untouched_keys_keep_their_defaults(tree):
    app = SeekApp(_session(tree))
    async with app.run_test(size=(120, 40)) as pilot:
        await _settle(pilot)
        bound = app.screen.active_bindings
        assert bound["ctrl+y"].binding.action == "seek_copy"
        assert bound["ctrl+e"].binding.action == "seek_open_editor"


async def test_detail_view_opens_at_once_on_a_large_file(tmp_path):
    """The pager renders the visible slice, not the whole file.

    Building the file into one `Static` made Textual lay out every line before
    the screen appeared - 0.8 s for 2,000 lines and 29 s for 120,000, with the
    event loop blocked throughout. Cost is now set by the viewport.
    """
    import time

    (tmp_path / "big.py").write_text(
        "\n".join(f"def fn_{i}(): return {i}  # a source line" for i in range(40_000))
    )
    app = SeekApp(_session(tmp_path, config=Config(debounce_ms=10)))
    async with app.run_test(size=(100, 30)) as pilot:
        await _settle(pilot)
        await pilot.press(*"fn_399")
        await pilot.pause(0.5)

        started = time.perf_counter()
        app.action_seek_detail()
        await pilot.pause(0.05)
        assert time.perf_counter() - started < 0.5, "the event loop must stay free"

        for _ in range(60):
            await pilot.pause(0.05)
            if getattr(app.screen, "_view", None) is not None:
                break
        screen = app.screen
        assert len(screen._view.lines) == 40_000
        assert screen.top_line > 1, "opens centred on the match, not at the top"

        moved = time.perf_counter()
        screen.action_page(1)
        assert time.perf_counter() - moved < 0.3, "paging is O(viewport), not O(file)"


async def test_detail_view_centres_on_the_matched_line(tmp_path):
    (tmp_path / "f.txt").write_text("\n".join(f"row {i}" for i in range(500)) + "\n")
    app = SeekApp(_session(tmp_path, config=Config(debounce_ms=10)))
    async with app.run_test(size=(100, 30)) as pilot:
        await _settle(pilot)
        await pilot.press(*"row 421")
        await pilot.pause(0.5)
        await pilot.press("enter")
        await pilot.pause(0.4)
        assert "row 421" in _render(app.screen.query_one("#detail-body"))


# --- consistency with the scan viewer ---------------------------------------


async def test_ctrl_p_opens_the_command_palette(tree):
    """The same key does the same thing in both halves of the app.

    `Ctrl+P` was "go to directory" here and the command palette in the scan
    viewer. Going to a directory moved to `Alt+C`, which is what `fzf` binds it
    to, and `Ctrl+P` now lists every action by name in both modes.
    """
    from textual.command import CommandPalette

    from seek.tui.commands import SeekCommands

    assert SeekCommands in SeekApp.COMMANDS
    app = SeekApp(_session(tree))
    async with app.run_test(size=(120, 40)) as pilot:
        await _settle(pilot)
        await pilot.press("ctrl+p")
        await pilot.pause(0.4)
        assert isinstance(app.screen, CommandPalette)


async def test_the_palette_lists_every_keybound_action(tree):
    """Nothing should be reachable only by knowing a modifier combination."""
    from seek.tui.app import _ACTION_KEYS
    from seek.tui.commands import _STATIC, SeekCommands

    app = SeekApp(_session(tree))
    async with app.run_test(size=(120, 40)) as pilot:
        await _settle(pilot)
        provider = SeekCommands(app.screen)
        hits = [hit async for hit in provider.discover()]
        assert hits, "the palette must list entries before anything is typed"
        assert all(hit.help for hit in hits), "every entry names what it does"

        offered = {method for _t, _s, method, _a in _STATIC}
        for action in _ACTION_KEYS.values():
            assert f"action_{action}" in offered, f"{action} is not in the palette"
            assert callable(getattr(app, f"action_{action}"))


async def test_palette_entries_name_their_key(tree):
    from seek.tui.commands import SeekCommands

    app = SeekApp(_session(tree))
    async with app.run_test(size=(120, 40)) as pilot:
        await _settle(pilot)
        provider = SeekCommands(app.screen)
        helps = {hit.display: hit.help async for hit in provider.discover()}
        assert "(^Y)" in helps["Copy paths"]
        assert "(⌥C)" in helps["Go to directory"]


async def test_the_action_menu_shows_keys_the_way_the_hint_bar_does(tree):
    """The menu printed the raw Textual spec (`ctrl+o`) beside a `^O` hint."""
    from seek.tui.menu import ActionMenuScreen

    app = SeekApp(_session(tree))
    async with app.run_test(size=(120, 40)) as pilot:
        await _settle(pilot)
        app.action_seek_action_menu()
        await pilot.pause(0.4)
        assert isinstance(app.screen, ActionMenuScreen)
        shown = _render(app.screen.query_one(OptionList))
        assert "^O" in shown or "^E" in shown
        assert "ctrl+" not in shown


async def test_history_records_the_query_not_the_prefixes_typed_towards_it(tree):
    """`Alt+↑` should recall queries, not the keystrokes on the way to one.

    History was committed on every debounced search, so typing `main` recorded
    `ma`, `mai` and `main`. It is committed instead when the query is used.
    """
    from seek.history import History

    app = SeekApp(_session(tree))
    app.history = History([], None)  # in-memory, no state file
    async with app.run_test(size=(120, 40)) as pilot:
        await _settle(pilot)
        for ch in "main":
            await pilot.press(ch)
            await pilot.pause(0.08)
        await pilot.pause(0.3)
        assert app.history.entries == [], "typing alone commits nothing"

        await pilot.press("enter")  # opening a result means the query was meant
        await pilot.pause(0.4)
        assert app.history.entries == ["main"]


async def test_ctrl_d_and_ctrl_c_toggle_directory_and_content_modes(tree):
    """`Ctrl+F` / `Ctrl+D` / `Ctrl+C`: file, directory, content."""
    app = SeekApp(_session(tree))
    async with app.run_test() as pilot:
        await _settle(pilot)
        modes = app.modes
        await pilot.press("ctrl+d")
        await pilot.pause(0.1)
        assert app.modes.dir is not modes.dir
        await pilot.press("ctrl+c")
        await pilot.pause(0.1)
        assert app.modes.content is not modes.content
        assert app.is_running, "Ctrl+C toggles content search; it does not quit"
        await pilot.press("ctrl+f")
        await pilot.pause(0.1)
        assert app.modes.file is not modes.file


async def test_ctrl_d_pages_the_detail_view_rather_than_toggling(tmp_path):
    """The toggles are priority bindings; in a modal they step aside."""
    (tmp_path / "f.txt").write_text("\n".join(f"row {i}" for i in range(300)) + "\n")
    app = SeekApp(_session(tmp_path, config=Config(debounce_ms=10)))
    async with app.run_test(size=(100, 30)) as pilot:
        await _settle(pilot)
        await pilot.press(*"row")
        await pilot.pause(0.3)
        await pilot.press("enter")
        await pilot.pause(0.4)
        screen = app.screen
        modes = app.modes
        start = screen.top_line
        await pilot.press("ctrl+d")
        await pilot.pause(0.1)
        assert screen.top_line > start, "half a page down"
        assert app.modes == modes, "and no mode changed"
        await pilot.press("ctrl+c")
        await pilot.pause(0.1)
        assert app.modes == modes and app.is_running
