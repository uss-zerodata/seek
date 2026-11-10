"""The in-session formatting toggle, and the formatted preview."""

from __future__ import annotations

import json

import pytest
from textual.geometry import Region

from seek.config import Config
from seek.engine.engine import Modes
from seek.scope import build_scope
from seek.session import SessionConfig
from seek.tui.app import SeekApp
from seek.tui.results import ResultsList

pytestmark = [pytest.mark.asyncio, pytest.mark.slow]

BLOB = json.dumps({"users": [{"id": i, "name": f"user{i}", "role": "admin"}
                             for i in range(80)]})


@pytest.fixture
def jtree(tmp_path):
    (tmp_path / "data.json").write_text(BLOB + "\n")
    (tmp_path / "notes.txt").write_text("admin notes\n")
    return tmp_path


def _session(root, **cfg) -> SessionConfig:
    return SessionConfig(
        root=root, modes=Modes(), scope=build_scope([], regex=False),
        config=Config(debounce_ms=10, **cfg), patterns=[],
    )


async def _settle(pilot, tries: int = 40):
    for _ in range(tries):
        await pilot.pause(0.05)
        if not pilot.app.store.scanning:
            return


def _render(widget) -> str:
    region = Region(0, 0, widget.size.width, max(1, widget.size.height))
    return "\n".join(
        "".join(s.text for s in strip) for strip in widget.render_lines(region)
    )


def _json_rows(app):
    return [r for r in app.query_one(ResultsList).results if r.rel == "data.json"]


async def test_toggle_off_reindexes_as_stored_and_back_on(jtree):
    app = SeekApp(_session(jtree))
    async with app.run_test(size=(120, 40)) as pilot:
        await _settle(pilot)
        await pilot.press(*"admin")
        await pilot.pause(0.3)
        formatted = len(_json_rows(app))
        assert formatted > 10

        await pilot.press("ctrl+n")  # formatting off
        await pilot.pause(0.4)
        assert app.config.format_content is False
        assert len(_json_rows(app)) == 1, "unformatted, the file is one long line"

        await pilot.press("ctrl+n")  # back on
        await pilot.pause(0.4)
        assert app.config.format_content is True
        assert len(_json_rows(app)) == formatted


async def test_toggle_state_is_visible_in_the_status_line(jtree):
    app = SeekApp(_session(jtree))
    async with app.run_test(size=(120, 40)) as pilot:
        await _settle(pilot)
        await pilot.press(*"admin")
        await pilot.pause(0.3)
        assert "fmt" in _render(app.query_one("#status"))
        assert "^N" in _render(app.query_one("#status"))


async def test_toggle_clears_the_content_cache_and_pool(jtree):
    app = SeekApp(_session(jtree))
    async with app.run_test(size=(120, 40)) as pilot:
        await _settle(pilot)
        await pilot.press(*"admin")
        await pilot.pause(0.3)
        assert app.engine.cache.cached_bytes > 0
        app.action_seek_toggle_format()
        assert app.engine._pool is None
        assert app.engine.cache.format_content is False


async def test_preview_shows_the_formatted_text(jtree):
    app = SeekApp(_session(jtree))
    async with app.run_test(size=(100, 40)) as pilot:
        await _settle(pilot)
        await pilot.press(*"admin")
        await pilot.pause(0.3)
        rl = app.query_one(ResultsList)
        idx = next(i for i, r in enumerate(rl.results) if r.rel == "data.json")
        rl.highlighted = idx
        await pilot.pause(0.4)
        shown = _render(app.query_one("#preview"))
        # the raw file is one 3,000+ char line; the preview must not show that
        assert max((len(x) for x in shown.splitlines()), default=0) < 120
        assert "admin" in shown
        assert "data.json:1" in shown, "header still names the real file location"


async def test_disabled_in_config_indexes_everything_as_stored(jtree):
    app = SeekApp(_session(jtree, format_content=False))
    async with app.run_test(size=(120, 40)) as pilot:
        await _settle(pilot)
        await pilot.press(*"admin")
        await pilot.pause(0.3)
        assert len(_json_rows(app)) == 1


async def test_marks_on_matches_sharing_a_line_are_independent(jtree):
    app = SeekApp(_session(jtree))
    async with app.run_test(size=(120, 40)) as pilot:
        await _settle(pilot)
        await pilot.press(*"admin")
        await pilot.pause(0.3)
        rl = app.query_one(ResultsList)
        rows = [i for i, r in enumerate(rl.results) if r.rel == "data.json"]
        assert len(rows) > 1
        rl.highlighted = rows[0]
        await pilot.press("tab")
        assert len(rl.marked) == 1, "marking one must not mark its neighbours"
        rl.highlighted = rows[1]
        await pilot.press("tab")
        assert len(rl.marked) == 2
