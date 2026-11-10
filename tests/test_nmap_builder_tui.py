"""The chooser and the builder in the terminal: order, reuse, the guided path,
fine-tune, the measurement offer, leaving, and fitting the screen."""

from __future__ import annotations

import pytest
from test_nmap_scanning import _app, _choose, _stub
from textual.widgets import Input, OptionList, TextArea

from seek.config import Config
from seek.tui.menu import ChoiceScreen
from seek.tui.nmap.builder import BuilderScreen, ChooserScreen
from seek.tui.nmap.scope import CommandScreen

pytestmark = [pytest.mark.asyncio, pytest.mark.slow]


def _ids(screen) -> list[str | None]:
    options = screen.query_one(OptionList)
    return [options.get_option_at_index(i).id for i in range(options.option_count)]


async def _open_chooser(pilot, app, targets="192.0.2.10\n192.0.2.11\n"):
    await pilot.pause(0.3)
    await pilot.press("n")
    await pilot.pause(0.4)
    app.screen.query_one(TextArea).text = targets
    await pilot.pause(0.2)
    await pilot.press("ctrl+s")
    await pilot.pause(0.4)


def _config(tmp_path) -> Config:
    return Config(nmap_path=_stub(tmp_path), nmap_presets={"Quick": "-sV"},
                  scan_output_dir=str(tmp_path))


async def test_the_chooser_offers_build_then_earlier_then_presets(tmp_path):
    app = _app(tmp_path, "timing", config=_config(tmp_path))
    async with app.run_test(size=(120, 40)) as pilot:
        await _open_chooser(pilot, app)
        assert isinstance(app.screen, ChooserScreen)
        ids = _ids(app.screen)
        assert ids[0] == "@build"
        assert ids.index("@recent:0") < ids.index("@frequent:0") < ids.index("Quick")


async def test_typing_filters_every_section(tmp_path):
    app = _app(tmp_path, "timing", config=_config(tmp_path))
    async with app.run_test(size=(120, 40)) as pilot:
        await _open_chooser(pilot, app)
        for key in "quick":
            await pilot.press(key)
        await pilot.pause(0.2)
        assert [i for i in _ids(app.screen) if i] == ["Quick"]
        await pilot.press("escape")                     # clears the filter first
        await pilot.pause(0.2)
        assert isinstance(app.screen, ChooserScreen) and "@build" in _ids(app.screen)


async def test_a_recent_command_is_reused_with_the_current_targets(tmp_path):
    app = _app(tmp_path, "timing", config=_config(tmp_path))
    async with app.run_test(size=(120, 40)) as pilot:
        await _open_chooser(pilot, app)
        await _choose(pilot, app, "@recent:0")
        await pilot.pause(0.4)
        assert isinstance(app.screen, CommandScreen)
        command = app.screen.query_one(TextArea).text
        assert "-sS -T4 -p22,80" in command, "the known ports filled in again"
        assert command.endswith("192.0.2.10 192.0.2.11")


async def _open_builder(pilot, app):
    await _open_chooser(pilot, app)
    await _choose(pilot, app, "@build")
    await pilot.pause(0.5)
    assert isinstance(app.screen, BuilderScreen)
    return app.screen


async def test_the_guided_path_ends_in_the_usual_command_step(tmp_path):
    app = _app(tmp_path, "timing", config=_config(tmp_path))
    async with app.run_test(size=(120, 40)) as pilot:
        builder = await _open_builder(pilot, app)
        for _ in range(6):                              # every recommendation
            await pilot.press("enter")
            await pilot.pause(0.2)
        assert builder.state.step == "tune"
        await pilot.press("ctrl+s")
        await pilot.pause(0.2)
        assert builder.state.step == "choose"
        assert _ids(builder) == ["fast", "reliable"]
        await _choose(pilot, app, "reliable")
        await pilot.pause(0.4)
        assert isinstance(app.screen, CommandScreen)
        assert "-sV" in app.screen.query_one(TextArea).text


async def test_back_and_jump_keep_the_answers(tmp_path):
    app = _app(tmp_path, "timing", config=_config(tmp_path))
    async with app.run_test(size=(120, 40)) as pilot:
        builder = await _open_builder(pilot, app)
        for _ in range(3):
            await pilot.press("enter")
            await pilot.pause(0.2)
        assert builder.state.step == "reach"
        await pilot.press("left")
        await pilot.pause(0.2)
        assert builder.state.step == "ports" and builder.state.answer("ports")
        await pilot.press("1")
        await pilot.pause(0.2)
        assert builder.state.step == "goal" and builder.state.answer("protocol")
        await pilot.press("8")                          # not reached yet: refused
        await pilot.pause(0.2)
        assert builder.state.step == "goal"


async def test_fine_tune_checks_a_value_where_it_is_typed(tmp_path):
    app = _app(tmp_path, "timing", config=_config(tmp_path))
    async with app.run_test(size=(120, 40)) as pilot:
        builder = await _open_builder(pilot, app)
        await pilot.press("ctrl+s")                     # needs a goal first
        await pilot.pause(0.2)
        assert builder.state.step == "goal"
        for _ in range(6):
            await pilot.press("enter")
            await pilot.pause(0.2)
        builder._edit("--host-timeout")
        await pilot.pause(0.2)
        edit = builder.query_one("#edit", Input)
        edit.value = "fast"
        await pilot.pause(0.2)
        assert "expected a time" in str(builder.query_one("#error").render())
        await pilot.press("enter")
        await pilot.pause(0.2)
        assert builder._editing == "--host-timeout", "an invalid value is not taken"
        edit.value = "45m"
        await pilot.press("enter")
        await pilot.pause(0.2)
        assert ("--host-timeout", "45m") in builder.state.overrides
        assert "--host-timeout 45m" in str(builder.query_one("#command").render())


async def test_declining_the_measurement_sends_nothing(tmp_path, monkeypatch):
    sent = []
    monkeypatch.setattr("seek.nmap.timing.measure_connect", lambda *a, **k: sent.append(a))
    monkeypatch.setattr("seek.nmap.timing.measure_ping", lambda *a, **k: sent.append(a))
    app = _app(tmp_path, "timing", config=_config(tmp_path))
    async with app.run_test(size=(120, 40)) as pilot:
        builder = await _open_builder(pilot, app)
        for _ in range(5):
            await pilot.press("enter")
            await pilot.pause(0.2)
        assert builder.state.step == "network"
        await _choose(pilot, app, "measure")
        await pilot.pause(0.3)
        assert isinstance(app.screen, ChoiceScreen)
        assert "TCP connections" in app.screen._prompt
        app.screen.choose("no")
        await pilot.pause(0.3)
        assert sent == [] and builder.state.step == "network"
        assert "nothing was sent" in str(builder.query_one("#notes").render())


async def test_leaving_with_answers_asks_first(tmp_path):
    app = _app(tmp_path, "timing", config=_config(tmp_path))
    async with app.run_test(size=(120, 40)) as pilot:
        builder = await _open_builder(pilot, app)
        await pilot.press("enter")
        await pilot.pause(0.2)
        await pilot.press("escape")
        await pilot.pause(0.3)
        assert isinstance(app.screen, ChoiceScreen)
        app.screen.choose("continue")
        await pilot.pause(0.3)
        assert app.screen is builder and builder.state.answer("goal")


def _fits(app) -> None:
    frame = app.screen.query_one("#frame").region
    width, height = app.size
    assert frame.right <= width and frame.bottom <= height
    for widget in app.screen.query("#frame > *"):
        if not widget.display:
            continue
        assert widget.region.height > 0, widget
        assert widget.region.bottom <= frame.bottom - 1, (
            widget, app.screen.state.step,
            [(w.id, w.region.height, str(w.styles.max_height))
             for w in app.screen.query("#frame *") if w.display and w.id])


@pytest.mark.parametrize("size", [(60, 18), (80, 24), (160, 48)])
async def test_the_builder_fits_every_size(tmp_path, size):
    app = _app(tmp_path, "timing", config=_config(tmp_path))
    async with app.run_test(size=size) as pilot:
        builder = await _open_builder(pilot, app)
        assert builder.has_class("wide") == (size[0] >= 120)
        for _ in range(6):
            _fits(app)
            await pilot.press("enter")
            await pilot.pause(0.3)
        _fits(app)                                      # fine-tune, every option listed
        await pilot.press("ctrl+s")
        await pilot.pause(0.3)
        _fits(app)
