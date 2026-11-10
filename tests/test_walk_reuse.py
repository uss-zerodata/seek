"""Changing root reuses the launch scan instead of walking the tree again."""

from __future__ import annotations

import pytest
from textual.widgets import Input

from seek.config import Config
from seek.engine.engine import Modes
from seek.models import MatchKind
from seek.scope import build_scope
from seek.session import SessionConfig
from seek.tui.app import SeekApp
from seek.tui.results import ResultsList
from seek.walk import walk

pytestmark = [pytest.mark.asyncio, pytest.mark.slow]


# --- the TUI path ----------------------------------------------------------


def _session(tree) -> SessionConfig:
    return SessionConfig(
        root=tree, modes=Modes(), scope=build_scope([], regex=False),
        config=Config(debounce_ms=10), patterns=[],
    )


async def _settle(pilot, tries: int = 40):
    for _ in range(tries):
        await pilot.pause(0.05)
        if not pilot.app.store.scanning:
            return


async def test_reroot_and_pop_do_not_rewalk(tree, monkeypatch):
    import seek.tui.app as app_mod

    calls = {"n": 0}
    real = app_mod.walk

    def counting(*args, **kwargs):
        calls["n"] += 1
        return real(*args, **kwargs)

    monkeypatch.setattr(app_mod, "walk", counting)
    app = SeekApp(_session(tree))
    async with app.run_test() as pilot:
        await _settle(pilot)
        assert calls["n"] == 1  # the launch walk
        assert app._base_candidates is not None

        await pilot.press(*"src")
        await pilot.pause(0.2)
        rl = app.query_one(ResultsList)
        idx = next(
            i for i, r in enumerate(rl.results)
            if r.kind is MatchKind.DIRNAME and r.rel == "src"
        )
        rl.highlighted = idx
        await pilot.press("ctrl+r")  # re-root
        await _settle(pilot)
        assert app.root == tree / "src"
        assert calls["n"] == 1, "re-root walked the filesystem again"

        await pilot.press("alt+left")  # pop back to the launch root
        await _settle(pilot)
        assert app.root == tree
        assert calls["n"] == 1, "breadcrumb pop walked the filesystem again"


async def test_reused_candidates_match_a_real_walk(tree):
    app = SeekApp(_session(tree))
    async with app.run_test() as pilot:
        await _settle(pilot)
        app.root = tree / "src"
        app._breadcrumb.append(tree / "src")
        assert app._reuse_walk() is True
        got = sorted(c.rel for c in app.store.snapshot())
    want = sorted(
        c.rel for c in walk(tree / "src", Config(), build_scope([], regex=False))
    )
    assert got == want


async def test_refresh_still_walks_the_filesystem(tree, monkeypatch):
    import seek.tui.app as app_mod

    calls = {"n": 0}
    real = app_mod.walk

    def counting(*args, **kwargs):
        calls["n"] += 1
        return real(*args, **kwargs)

    monkeypatch.setattr(app_mod, "walk", counting)
    app = SeekApp(_session(tree))
    async with app.run_test() as pilot:
        await _settle(pilot)
        assert calls["n"] == 1
        (tree / "brandnew.txt").write_text("hi\n")
        await pilot.press("ctrl+g")
        await _settle(pilot)
        assert calls["n"] == 2, "refresh must bypass the cached scan"
        assert any(c.rel == "brandnew.txt" for c in app.store.snapshot())


async def test_positional_scope_falls_back_to_a_real_walk(tree):
    session = SessionConfig(
        root=tree, modes=Modes(), scope=build_scope(["*.py"], regex=False),
        config=Config(debounce_ms=10), patterns=["*.py"],
    )
    app = SeekApp(session)
    async with app.run_test() as pilot:
        await _settle(pilot)
        app.root = tree / "src"
        app._breadcrumb.append(tree / "src")
        # a scope was resolved against the launch root, so it cannot be rebased
        assert app._reuse_walk() is False


async def test_query_input_still_focused_after_reroot(tree):
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
        assert app.focused is app.query_one("#query", Input)
