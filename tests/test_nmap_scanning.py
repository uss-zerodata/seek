"""The scan flow in the viewer: the tab, the review, and folding a run back in.

**No test here runs nmap.** `Config.nmap_path` points at a stub script that
prints canned output, which is exactly why the runner takes its program from
configuration.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from textual.geometry import Region
from textual.widgets import Button, DataTable, Label, OptionList, Tabs, TextArea

from seek.config import Config
from seek.nmap.merge import load
from seek.nmap.runner import State
from seek.nmap.views import prepare
from seek.tui.nmap.app import NmapApp
from seek.tui.nmap.scope import CommandScreen, ReviewScreen, ScopeScreen

pytestmark = pytest.mark.asyncio
FIX = Path(__file__).parent / "fixtures" / "nmap"

_DONE = """#!/bin/sh
echo "Starting Nmap 7.94 ( https://nmap.org )"
echo "Nmap done: 1 IP address (1 host up) scanned in 0.10 seconds"
"""


_VERSION = ('case "$1" in --version) '
            'echo "Nmap version 7.94 ( https://nmap.org )"; exit 0;; esac\n')


def _stub(tmp_path: Path, body: str = _DONE, name: str = "fake-nmap") -> str:
    """A stand-in for nmap. It answers `--version` because the app probes with it."""
    path = tmp_path / name
    head, _, rest = body.partition("\n")
    path.write_text(f"{head}\n{_VERSION}{rest}")
    path.chmod(0o755)
    return str(path)


def _config(tmp_path: Path, **kwargs) -> Config:
    return Config(nmap_path=_stub(tmp_path), nmap_presets={"Quick": "-sV"},
                  scan_output_dir=str(tmp_path), **kwargs)


def _app(tmp_path, *names, config: Config | None = None) -> NmapApp:
    paths = [FIX / f"{n}.xml" for n in names]
    return NmapApp(prepare(load(paths)), config or _config(tmp_path),
                   sources=paths, scan_dir=tmp_path)


def _render(w) -> str:
    region = Region(0, 0, w.size.width, max(1, w.size.height))
    return "\n".join("".join(s.text for s in strip) for strip in w.render_lines(region))


def _labels(app) -> list[str]:
    return [str(w.render()) for w in app.screen.query(Label)]


def _modal_text(app) -> str:
    """A modal covers the app, so render its own widgets rather than the screen."""
    from textual.widgets import Static
    return "\n".join(str(w.render()) for w in app.screen.query(Static))


async def _choose(pilot, app, choice_id):
    options = app.screen.query_one(OptionList)
    options.highlighted = options.get_option_index(choice_id)
    await pilot.press("enter")
    await pilot.pause(0.3)


# --- availability -----------------------------------------------------------


async def test_the_status_line_says_whether_a_scan_can_be_run(tmp_path):
    app = _app(tmp_path, "basic")
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause(0.3)
        assert "⌁ nmap" in _render(app.query_one("#status"))
        assert app.nmap.available


async def test_without_nmap_the_viewer_is_otherwise_unchanged(tmp_path):
    config = Config(nmap_path=str(tmp_path / "nope"), scan_output_dir=str(tmp_path))
    app = _app(tmp_path, "basic", config=config)
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause(0.3)
        assert not app.nmap.available
        assert "⌁ nmap not found" in _render(app.query_one("#status"))
        assert [r.cells[0] for r in app._rows] == ["192.0.2.1", "192.0.2.2", "192.0.2.3"]


async def test_a_scan_action_without_nmap_explains_rather_than_failing(tmp_path):
    config = Config(nmap_path=str(tmp_path / "nope"), scan_output_dir=str(tmp_path))
    app = _app(tmp_path, "basic", config=config)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        await pilot.press("n")
        await pilot.pause(0.4)
        assert app.runner.runs == [], "nothing was started"
        assert not isinstance(app.screen, ScopeScreen)


# --- the Scans tab ----------------------------------------------------------


async def test_the_scans_tab_lists_the_loaded_scans_as_history(tmp_path):
    app = _app(tmp_path, "basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        app.query_one(Tabs).active = "scans"
        await pilot.pause(0.4)
        assert app.view.kind == "scans"
        assert [r.cells[0] for r in app._rows] == ["✓ basic"], "the file, as history"
        assert app._rows[0].cells[4] == "baseline · 3 host(s)"


async def test_the_scans_tab_is_empty_only_with_no_scans(tmp_path):
    config = _config(tmp_path)
    app = NmapApp(prepare(load([])), config, sources=[], scan_dir=tmp_path)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        app.query_one(Tabs).active = "scans"
        await pilot.pause(0.4)
        assert app._rows == []
        shown = str(app.query_one("#empty").render())
        assert "No scans yet" in shown and "n runs one" in shown


async def test_without_nmap_the_scans_tab_says_what_is_missing(tmp_path):
    config = Config(nmap_path=str(tmp_path / "nope"), scan_output_dir=str(tmp_path))
    app = NmapApp(prepare(load([])), config, sources=[], scan_dir=tmp_path)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        app.query_one(Tabs).active = "scans"
        await pilot.pause(0.4)
        shown = str(app.query_one("#empty").render())
        assert "Scanning is unavailable" in shown
        assert "still works" in shown


# --- the flow ---------------------------------------------------------------


async def _run_a_scan(pilot, app, targets="10.0.0.1\n"):
    """scope → preset → command → review → run, the way a user does it."""
    await pilot.press("n")
    await pilot.pause(0.4)
    app.screen.query_one(TextArea).text = targets
    await pilot.pause(0.3)
    await pilot.press("ctrl+s")
    await pilot.pause(0.4)
    await _choose(pilot, app, "Quick")
    await pilot.pause(0.3)
    await pilot.press("ctrl+s")             # the command, unedited
    await pilot.pause(0.4)
    app.screen.query_one(Button).press()
    await pilot.pause(0.6)


async def test_a_scan_runs_from_the_editor_and_lands_in_the_run_list(tmp_path):
    app = _app(tmp_path, "basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        await _run_a_scan(pilot, app)
        for _ in range(60):
            await pilot.pause(0.1)
            if app.runner.runs and not app.runner.runs[0].running:
                break
        run = app.runner.runs[0]
        assert run.state is State.DONE, run.result
        assert app._active_tab == "scans"
        # the stub writes no .xml, so the finished run has no file and stays a
        # live row named by its preset (a run that DID write one would fold into
        # the history as its filename instead)
        assert any("Quick" in r.cells[0] for r in app._rows)


async def test_the_review_shows_the_argv_the_scope_and_the_warning(tmp_path):
    app = _app(tmp_path, "basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        await pilot.press("n")
        await pilot.pause(0.4)
        app.screen.query_one(TextArea).text = "10.0.0.1\n10.0.0.2\n"
        await pilot.pause(0.3)
        await pilot.press("ctrl+s")
        await pilot.pause(0.4)
        await _choose(pilot, app, "Quick")
        await pilot.press("ctrl+s")
        await pilot.pause(0.5)
        assert isinstance(app.screen, ReviewScreen)
        shown = _modal_text(app)
        assert "-sV" in shown and "-oA" in shown
        assert "2 target(s)" in shown
        assert "authorised" in shown, "the reminder is part of the review"
        await pilot.press("escape")
        await pilot.pause(0.3)
        assert app.runner.runs == [], "backing out of the review runs nothing"


async def test_a_command_that_would_need_a_shell_is_refused_at_the_command_step(tmp_path):
    app = _app(tmp_path, "basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        await pilot.press("n")
        await pilot.pause(0.4)
        app.screen.query_one(TextArea).text = "10.0.0.1\n"
        await pilot.pause(0.3)
        await pilot.press("ctrl+s")
        await pilot.pause(0.4)
        await _choose(pilot, app, "Quick")
        app.screen.query_one(TextArea).text = f"{app.config.nmap_path} -sV | tee x"
        await pilot.press("ctrl+s")
        await pilot.pause(0.5)
        assert isinstance(app.screen, CommandScreen), "back on the command, not running"
        assert app.runner.runs == []


async def test_cancelling_the_scope_runs_nothing(tmp_path):
    app = _app(tmp_path, "basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        await pilot.press("n")
        await pilot.pause(0.4)
        assert isinstance(app.screen, ScopeScreen)
        await pilot.press("escape")
        await pilot.pause(0.3)
        assert app.runner.runs == []


async def test_a_scope_with_no_valid_target_is_refused(tmp_path):
    app = _app(tmp_path, "basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        await pilot.press("n")
        await pilot.pause(0.4)
        screen = app.screen
        screen.query_one(TextArea).text = "not a target!\n"
        await pilot.pause(0.3)
        await pilot.press("ctrl+s")
        await pilot.pause(0.3)
        assert app.screen is screen, "still in the editor"
        assert "not an address" in _render(screen.query_one("#summary"))


async def test_an_unwritable_scan_directory_stops_before_the_review(tmp_path):
    import os
    if os.geteuid() == 0:
        pytest.skip("root can write anywhere")
    locked = tmp_path / "locked"
    locked.mkdir(mode=0o500)
    config = Config(nmap_path=_stub(tmp_path), nmap_presets={"Quick": "-sV"},
                    scan_output_dir=str(locked))
    app = _app(tmp_path, "basic", config=config)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        await pilot.press("n")
        await pilot.pause(0.4)
        app.screen.query_one(TextArea).text = "10.0.0.1\n"
        await pilot.pause(0.3)
        await pilot.press("ctrl+s")
        await pilot.pause(0.4)
        await _choose(pilot, app, "Quick")
        await pilot.pause(0.4)
        assert not isinstance(app.screen, (CommandScreen, ReviewScreen))
        assert app.runner.runs == []


# --- while it runs ----------------------------------------------------------


async def test_freezing_the_log_never_touches_the_scan(tmp_path):
    slow = _stub(tmp_path, "#!/bin/sh\necho going\nsleep 5\n", name="slow-nmap")
    config = Config(nmap_path=slow, nmap_presets={"Quick": "-sV"},
                    scan_output_dir=str(tmp_path))
    app = _app(tmp_path, "basic", config=config)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        await _run_a_scan(pilot, app)
        for _ in range(60):
            await pilot.pause(0.1)
            if app.runner.runs:
                break
        run = app.runner.runs[0]
        assert run.running
        app._select_target(run)         # the live run, not the imported scan on row 0
        await pilot.pause(0.2)
        app._report_mode = "raw"
        await pilot.press("p")
        await pilot.pause(0.3)
        assert app._log_frozen
        assert run.running, "freezing is a view state; the process is untouched"
        assert "still running" in _render(app.query_one("#detail-body"))
        await pilot.press("c")
        await pilot.pause(1.0)
        for _ in range(80):
            await pilot.pause(0.1)
            if not run.running:
                break
        assert run.state is State.CANCELLED


async def test_a_second_scan_is_refused_while_one_runs(tmp_path):
    slow = _stub(tmp_path, "#!/bin/sh\necho going\nsleep 5\n", name="slow-nmap")
    config = Config(nmap_path=slow, nmap_presets={"Quick": "-sV"},
                    scan_output_dir=str(tmp_path))
    app = _app(tmp_path, "basic", config=config)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        await _run_a_scan(pilot, app)
        for _ in range(60):
            await pilot.pause(0.1)
            if app.runner.runs:
                break
        await pilot.press("n")
        await pilot.pause(0.4)
        assert not isinstance(app.screen, ScopeScreen), "refused, naming the running one"
        app.runner.cancel()
        await pilot.pause(1.0)


# --- the report -------------------------------------------------------------


async def test_the_report_cycles_through_its_three_modes(tmp_path):
    app = _app(tmp_path, "basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        await _run_a_scan(pilot, app)
        for _ in range(60):
            await pilot.pause(0.1)
            if app.runner.runs and not app.runner.runs[0].running:
                break
        app._report_mode = "condensed"
        app._refresh_detail()
        await pilot.pause(0.2)
        seen = []
        for _ in range(3):
            seen.append(_render(app.query_one("#detail-body")).strip().splitlines()[0])
            await pilot.press("o")
            await pilot.pause(0.3)
        assert any("overview" in line for line in seen)
        assert any("added" in line for line in seen)
        assert any("raw output" in line for line in seen)


# --- folding it back in -----------------------------------------------------


async def test_a_finished_scan_is_merged_and_diffed(tmp_path):
    """The stub writes an XML file exactly as nmap's -oA would."""
    xml = (FIX / "scripts.xml").read_text()
    writer = tmp_path / "writing-nmap"
    writer.write_text(
        "#!/bin/sh\n"
        + _VERSION +
        "echo 'Nmap done: 1 IP address (1 host up) scanned'\n"
        'while [ $# -gt 0 ]; do\n'
        '  if [ "$1" = "-oA" ]; then base="$2"; fi\n'
        '  shift\n'
        'done\n'
        f'cat > "$base.xml" <<\'XML\'\n{xml}\nXML\n'
    )
    writer.chmod(0o755)
    config = Config(nmap_path=str(writer), nmap_presets={"Quick": "-sV"},
                    scan_output_dir=str(tmp_path))
    app = _app(tmp_path, "basic", config=config)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        before = {h.address for h in app.scans.hosts}
        await _run_a_scan(pilot, app)
        for _ in range(80):
            await pilot.pause(0.1)
            if app.runner.runs and not app.runner.runs[0].running:
                break
        run = app.runner.runs[0]
        assert run.state is State.DONE, run.result
        after = {h.address for h in app.scans.hosts}
        assert after > before, "the new host is in the model"
        changes = app._diffs[id(run)]
        assert changes.new_hosts and "new host" in changes.summary()


# --- export → scan ----------------------------------------------------------


async def test_the_export_dialog_offers_scanning_when_nmap_is_there(tmp_path):
    app = _app(tmp_path, "basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        await pilot.press("x")
        await pilot.pause(0.4)
        options = app.screen.query_one(OptionList)
        assert options.get_option_index("scan") is not None
        await pilot.press("escape")
        await pilot.pause(0.2)


async def test_the_export_dialog_hides_scanning_without_nmap(tmp_path):
    config = Config(nmap_path=str(tmp_path / "nope"), scan_output_dir=str(tmp_path))
    app = _app(tmp_path, "basic", config=config)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        await pilot.press("x")
        await pilot.pause(0.4)
        options = app.screen.query_one(OptionList)
        ids = [options.get_option_at_index(i).id for i in range(options.option_count)]
        assert "scan" not in ids
        await pilot.press("escape")
        await pilot.pause(0.2)


async def test_scanning_the_selection_carries_its_addresses(tmp_path):
    app = _app(tmp_path, "basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        app.query_one(DataTable).move_cursor(row=1)
        await pilot.press("m")                       # 192.0.2.2
        await pilot.pause(0.3)
        await pilot.press("x")
        await pilot.pause(0.4)
        await _choose(pilot, app, "scan")
        await pilot.pause(0.5)
        options = app.screen.query_one(OptionList)   # straight to the presets
        assert options.get_option_index("Quick") is not None
        assert "1 target(s)" in " ".join(_labels(app))
        await pilot.press("escape")
        await pilot.pause(0.2)


# --- the entry point --------------------------------------------------------
# (async only because this module carries a module-wide asyncio mark; these
# three drive the CLI, not the app.)


async def test_an_empty_directory_is_an_invitation_when_nmap_is_there(tmp_path, monkeypatch):
    """A directory with nothing in it is the case for starting a scan."""
    from typer.testing import CliRunner

    from seek.cli import app as cli

    _stub(tmp_path, name="nmap")
    monkeypatch.setenv("PATH", str(tmp_path))
    empty = tmp_path / "engagement"
    empty.mkdir()
    monkeypatch.setattr("seek.cli._stdout_is_usable", lambda: False)
    result = CliRunner().invoke(cli, ["nmap", str(empty)])
    assert "no readable nmap output" not in result.output
    assert "requires an interactive terminal" in result.output, \
        "it got as far as wanting a terminal, rather than refusing the directory"


async def test_an_empty_directory_without_nmap_still_reports_nothing_to_read(
    tmp_path, monkeypatch
):
    from typer.testing import CliRunner

    from seek.cli import app as cli

    monkeypatch.setenv("PATH", str(tmp_path / "empty-path"))
    empty = tmp_path / "engagement"
    empty.mkdir()
    opened = []
    monkeypatch.setattr("seek.tui.nmap.app.run_viewer",
                        lambda *a, **k: opened.append(a) or 0)
    result = CliRunner().invoke(cli, ["nmap", str(empty)])
    assert result.exit_code == 1
    assert "no readable nmap output" in result.output
    assert "no scan can be started" in result.output
    assert not opened, "and it says so without opening the viewer"


async def test_unreadable_candidates_are_the_viewers_problem(tmp_path, monkeypatch):
    """The command decides from discovery alone, so it cannot pre-empt this.

    A file that looks like a scan and turns out not to parse used to be found
    out before the viewer started. Reading now happens with the viewer open,
    so the command hands the candidate over and the viewer reports it - which
    is the one externally visible change this makes.
    """
    from typer.testing import CliRunner

    from seek.cli import app as cli

    broken = tmp_path / "broken.xml"
    broken.write_text('<?xml version="1.0"?>\n<!DOCTYPE nmaprun>\n<nmaprun><host')
    monkeypatch.setenv("PATH", str(tmp_path / "empty-path"))
    monkeypatch.setattr("seek.cli._stdout_is_usable", lambda: True)
    handed = {}
    monkeypatch.setattr(
        "seek.tui.nmap.app.run_viewer",
        lambda scans, *a, **k: handed.update(paths=list(scans.paths)) or 1)
    result = CliRunner().invoke(cli, ["nmap", str(tmp_path)])
    assert handed["paths"] == [broken], "handed over unread"
    assert result.exit_code == 1, "and the viewer's verdict is the exit status"


async def test_no_argument_reads_the_working_directory(tmp_path, monkeypatch):
    """`cd engagement && seek nmap` is the whole invocation - naming `.` adds nothing."""
    from typer.testing import CliRunner

    from seek.cli import app as cli

    deep = tmp_path / "01-discovery"
    deep.mkdir()
    shutil.copy(FIX / "basic.xml", deep / "basic.xml")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("seek.cli._stdout_is_usable", lambda: True)
    seen = {}

    def fake_viewer(scans, config, sources, scan_dir):
        # The command hands over candidates, not a model: reading them is the
        # viewer's job now, and what is asserted here is that discovery found
        # them and passed them on.
        seen.update(found=[p.name for p in scans.paths], sources=list(sources),
                    scan_dir=scan_dir)
        return 0

    monkeypatch.setattr("seek.tui.nmap.app.run_viewer", fake_viewer)
    result = CliRunner().invoke(cli, ["nmap"])
    assert result.exit_code == 0
    assert seen["found"] == ["basic.xml"], "the scan in the subdirectory was found"
    assert seen["sources"] == [Path.cwd()] and seen["scan_dir"] == Path.cwd(), \
        "the working directory is the source, so a scan started here is covered"


async def test_the_search_says_nothing_when_stderr_is_not_a_terminal(tmp_path, monkeypatch):
    """The progress line is drawn with `\\r`; piped, it would be a thousand half-lines."""
    from typer.testing import CliRunner

    from seek.cli import app as cli

    shutil.copy(FIX / "basic.xml", tmp_path / "basic.xml")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("seek.cli._stdout_is_usable", lambda: False)
    result = CliRunner().invoke(cli, ["nmap"])
    assert "searching for scans" not in result.output
    assert "\r" not in result.output


async def test_a_directory_with_scans_opens_on_them_as_before(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from seek.cli import app as cli

    _stub(tmp_path, name="nmap")
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setattr("seek.cli._stdout_is_usable", lambda: False)
    result = CliRunner().invoke(cli, ["nmap", str(FIX / "basic.xml")])
    assert "requires an interactive terminal" in result.output


async def test_quitting_does_not_leave_a_scan_running(tmp_path):
    """The child is in its own session, so nothing else would reap it."""
    slow = _stub(tmp_path, "#!/bin/sh\necho going\nsleep 30\n", name="slow-nmap")
    config = Config(nmap_path=slow, nmap_presets={"Quick": "-sV"},
                    scan_output_dir=str(tmp_path))
    app = _app(tmp_path, "basic", config=config)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        await _run_a_scan(pilot, app)
        for _ in range(60):
            await pilot.pause(0.1)
            if app.runner.runs:
                break
        assert app.runner.busy() is not None
        app.exit(0)
        await pilot.pause(0.5)
    # The process is signalled on the way out. Its *state* cannot settle - the
    # worker that would have awaited it went with the app - and a terminated
    # child stays a zombie until something reaps it, so asserting liveness here
    # would be asserting the reaper, not the app.
    assert "[seek] cancelling" in "\n".join(app.runner.runs[0].log)


# --- the ports the model already knows --------------------------------------


async def test_a_preset_can_reuse_the_ports_already_found(tmp_path):
    """The reference workflow greps these out of the last .gnmap; we know them."""
    config = Config(nmap_path=_stub(tmp_path),
                    nmap_presets={"Versions": "-sV -p{ports}"},
                    scan_output_dir=str(tmp_path))
    app = _app(tmp_path, "basic", config=config)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        await pilot.press("n")
        await pilot.pause(0.4)
        app.screen.query_one(TextArea).text = "10.0.0.1\n"
        await pilot.pause(0.3)
        await pilot.press("ctrl+s")
        await pilot.pause(0.4)
        await _choose(pilot, app, "Versions")
        await pilot.pause(0.4)
        shown = app.screen.query_one(TextArea).text
        assert "-p22,80" in shown, "the open ports of the current model"
        assert "{ports}" not in shown
        await pilot.press("escape")
        await pilot.pause(0.2)


async def test_a_ports_preset_is_refused_when_nothing_is_known_yet(tmp_path):
    config = Config(nmap_path=_stub(tmp_path),
                    nmap_presets={"Versions": "-sV -p{ports}"},
                    scan_output_dir=str(tmp_path))
    app = NmapApp(prepare(load([])), config, sources=[], scan_dir=tmp_path)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.4)
        # the empty model opens the editor by itself
        app.screen.query_one(TextArea).text = "10.0.0.1\n"
        await pilot.pause(0.3)
        await pilot.press("ctrl+s")
        await pilot.pause(0.4)
        await _choose(pilot, app, "Versions")
        await pilot.pause(0.4)
        assert not isinstance(app.screen, CommandScreen), "refused, not a broken -p"
        assert app.runner.runs == []


async def test_the_shipped_presets_are_the_documented_workflow():
    from seek.nmap.presets import DEFAULT_PRESETS, needs_root, parse_args

    names = list(DEFAULT_PRESETS)
    assert [n[:2] for n in names] == sorted(n[:2] for n in names), \
        "the phases read in the order the work is done"
    for name, args in DEFAULT_PRESETS.items():
        parsed = parse_args(args)
        assert "sudo" not in parsed, f"{name}: elevation is added at launch"
        assert not any(a.startswith("-iL") for a in parsed), f"{name}: scope is the app's"
        assert not any(a.startswith("-o") for a in parsed), f"{name}: output is the app's"
    # Named by property rather than by exact title, so a rename of the shipped
    # presets does not break the contract this test is really about.
    a_ping_sweep = next(
        (a for a in DEFAULT_PRESETS.values() if "-PE" in a or "-PU" in parse_args(a)),
        None)
    assert a_ping_sweep and needs_root(parse_args(a_ping_sweep)), \
        "a preset using raw ICMP/UDP pings is treated as needing root"
    a_reverse_lookup = next(
        (a for a in DEFAULT_PRESETS.values()
         if "-sL" in parse_args(a) and "-R" in parse_args(a)), None)
    assert a_reverse_lookup, "a reverse-lookup preset ships"
    assert "-n" not in parse_args(a_reverse_lookup), "resolving names is its point"
    assert not needs_root(parse_args(a_reverse_lookup))


# --- not by accident --------------------------------------------------------


async def _start_a_slow_scan(pilot, app):
    await _run_a_scan(pilot, app)
    for _ in range(60):
        await pilot.pause(0.1)
        if app.runner.runs:
            break
    assert app.runner.busy() is not None


def _slow(tmp_path) -> Config:
    slow = _stub(tmp_path, "#!/bin/sh\necho going\nsleep 30\n", name="slow-nmap")
    return Config(nmap_path=slow, nmap_presets={"Quick": "-sV"},
                  scan_output_dir=str(tmp_path))


async def test_quitting_while_a_scan_runs_asks_first(tmp_path):
    app = _app(tmp_path, "basic", config=_slow(tmp_path))
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        await _start_a_slow_scan(pilot, app)
        await pilot.press("q")
        await pilot.pause(0.5)
        assert app.is_running, "not gone yet"
        assert any("Quitting ends it" in t for t in _labels(app))
        await pilot.press("escape")             # the safe answer
        await pilot.pause(0.4)
        assert app.is_running and app.runner.busy() is not None
        app.runner.cancel()
        await pilot.pause(1.0)


async def test_choosing_to_keep_scanning_stays(tmp_path):
    app = _app(tmp_path, "basic", config=_slow(tmp_path))
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        await _start_a_slow_scan(pilot, app)
        await pilot.press("q")
        await pilot.pause(0.5)
        await _choose(pilot, app, "stay")
        await pilot.pause(0.4)
        assert app.is_running and app.runner.busy() is not None
        app.runner.cancel()
        await pilot.pause(1.0)


async def test_choosing_to_quit_ends_the_scan_and_leaves(tmp_path):
    app = _app(tmp_path, "basic", config=_slow(tmp_path))
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        await _start_a_slow_scan(pilot, app)
        await pilot.press("q")
        await pilot.pause(0.5)
        await _choose(pilot, app, "quit")
        await pilot.pause(0.6)
        assert not app.is_running
    assert "[seek] cancelling" in "\n".join(app.runner.runs[0].log)


async def test_escape_at_the_top_is_guarded_too(tmp_path):
    app = _app(tmp_path, "basic", config=_slow(tmp_path))
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        await _start_a_slow_scan(pilot, app)
        app.query_one(Tabs).active = "hosts"     # the first tab, where Esc quits
        await pilot.pause(0.4)
        await pilot.press("escape")
        await pilot.pause(0.5)
        assert app.is_running
        assert any("Quitting ends it" in t for t in _labels(app))
        await pilot.press("escape")
        await pilot.pause(0.3)
        app.runner.cancel()
        await pilot.pause(1.0)


async def test_the_hint_bar_says_that_quitting_will_ask(tmp_path):
    app = _app(tmp_path, "basic", config=_slow(tmp_path))
    async with app.run_test(size=(200, 40)) as pilot:
        await pilot.pause(0.3)
        assert "Esc quit" in _render(app.query_one("#hint-bar"))
        await _start_a_slow_scan(pilot, app)
        app.query_one(Tabs).active = "hosts"
        await pilot.pause(0.4)
        assert "asks while a scan runs" in _render(app.query_one("#hint-bar"))
        app.runner.cancel()
        await pilot.pause(1.0)


async def test_quitting_with_nothing_running_is_immediate(tmp_path):
    app = _app(tmp_path, "basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        await pilot.press("q")
        await pilot.pause(0.4)
        assert not app.is_running, "no scan, no question"


# --- the preset chooser reads cleanly ---------------------------------------


async def test_the_preset_chooser_shows_each_preset_and_its_privilege(tmp_path):
    from textual.widgets import OptionList

    from seek.tui.nmap.scope import PresetScreen
    presets = {
        "02 · Services, top 1000 TCP": "-vv -T4 -n -Pn -sS --host-timeout 30m",
        "03 · SMB vulnerabilities (139, 445)": "-vv -Pn -p139,445 --script smb-vuln*",
    }
    screen = PresetScreen("New scan · 1 target(s)", "10.0.0.1", presets)
    app = _app(tmp_path, "basic")
    async with app.run_test(size=(96, 30)) as pilot:
        await pilot.pause(0.2)
        await app.push_screen(screen)
        await pilot.pause(0.3)
        options = app.screen.query_one(OptionList)
        assert options.option_count == 2, "one entry per preset, not one per line"
        ids = [options.get_option_at_index(i).id for i in range(options.option_count)]
        assert ids == list(presets), "the id is the preset name"
        rendered = _render(options)
        assert "needs root" in rendered, "the SYN preset's privilege shows"
        assert "-sS --host-timeout 30m" in rendered, "and a preview of its flags"
        await pilot.press("escape")
        await pilot.pause(0.2)


async def test_a_long_preset_name_does_not_wrap_into_the_next(tmp_path):
    from textual.geometry import Region
    from textual.widgets import OptionList

    from seek.tui.nmap.scope import PresetScreen
    presets = {"02 · Services, versions on the ports already found":
               "-vv -T4 -n -Pn -sS -A --host-timeout 30m -p1-65535"}
    app = _app(tmp_path, "basic")
    async with app.run_test(size=(96, 30)) as pilot:
        await pilot.pause(0.2)
        await app.push_screen(PresetScreen("New scan", "10.0.0.1", presets))
        await pilot.pause(0.3)
        options = app.screen.query_one(OptionList)
        strips = options.render_lines(Region(0, 0, options.size.width, 6))
        lines = ["".join(sg.text for sg in s) for s in strips]
        # the whole name and its badge sit on one line, uncut; the flags on one
        # more - the wrapping that used to tear them apart is gone
        name_line = next(ln for ln in lines if "already found" in ln)
        assert "needs root" in name_line, "name and badge share one intact line"
        assert any("-p1-65535" in ln for ln in lines), "the preview is one line too"
        assert not any(ln.strip().startswith("needs root") for ln in lines), \
            "the badge never falls onto a line of its own"
        await pilot.press("escape")
        await pilot.pause(0.2)


async def test_the_help_body_is_a_grid_of_every_section():
    # async only because this module carries a module-wide asyncio mark.
    from rich.console import Console

    from seek.tui.nmap.help import _GROUPS, help_body

    console = Console(width=78)
    with console.capture() as cap:
        console.print(help_body())
    text = cap.get()
    for title, _ in _GROUPS:
        assert title in text
    # a long description stays on its own indented column, not the left margin
    assert "\nhost →" not in text, "a wrapped description must not fall to column 0"


# --- opening the detail full-screen (`d`), collapsing the pane (`D`) --------


async def test_d_opens_the_reader_on_a_host_record(tmp_path):
    from seek.tui.nmap.reader import DetailReader

    app = _app(tmp_path, "basic")
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.3)
        await pilot.press("d")
        await pilot.pause(0.3)
        assert isinstance(app.screen, DetailReader)
        assert any("192.0.2.1" in line.plain for line in app.screen._lines)
        await pilot.press("escape")
        await pilot.pause(0.2)
        assert not isinstance(app.screen, DetailReader)


async def test_d_shows_the_same_content_the_pane_shows(tmp_path):

    app = _app(tmp_path, "scripts")
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.3)
        pane_text = _render(app.query_one("#detail-body"))
        await pilot.press("d")
        await pilot.pause(0.3)
        reader_text = "\n".join(line.plain for line in app.screen._lines)
        # The pane wraps differently at a different width, but every word in
        # its narrow rendering must appear in the reader's - same content.
        for word in pane_text.split():
            assert word in reader_text
        await pilot.press("escape")
        await pilot.pause(0.2)


async def test_capital_d_still_collapses_the_inline_pane(tmp_path):
    app = _app(tmp_path, "basic")
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.3)
        assert app._show_detail is True
        await pilot.press("D")
        await pilot.pause(0.2)
        assert app._show_detail is False
        await pilot.press("D")
        await pilot.pause(0.2)
        assert app._show_detail is True


async def test_lowercase_d_no_longer_collapses_the_pane(tmp_path):
    """The breaking change the proposal called out: `d` opens, it does not
    toggle - collapsing moved to `D`."""
    from seek.tui.nmap.reader import DetailReader

    app = _app(tmp_path, "basic")
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.3)
        await pilot.press("d")
        await pilot.pause(0.3)
        assert isinstance(app.screen, DetailReader)
        assert app._show_detail is True, "d did not touch the pane's visibility"
        await pilot.press("escape")
        await pilot.pause(0.2)


async def test_d_works_while_the_pane_is_collapsed(tmp_path):
    from seek.tui.nmap.reader import DetailReader

    app = _app(tmp_path, "basic")
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.3)
        await pilot.press("D")
        await pilot.pause(0.2)
        assert app._show_detail is False
        await pilot.press("d")
        await pilot.pause(0.3)
        assert isinstance(app.screen, DetailReader)
        await pilot.press("escape")
        await pilot.pause(0.2)


async def test_d_on_a_heading_shows_the_same_note_the_pane_would(tmp_path):
    from seek.tui.nmap.reader import DetailReader

    app = _app(tmp_path, "basic")
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.3)
        await pilot.press("s")                # statistics tab
        await pilot.pause(0.3)
        row = next(i for i, r in enumerate(app._rows) if r.heading)
        app.query_one(DataTable).move_cursor(row=row)
        await pilot.pause(0.2)
        await pilot.press("d")
        await pilot.pause(0.3)
        assert isinstance(app.screen, DetailReader)
        text = "\n".join(line.plain for line in app.screen._lines)
        assert "Select a line under this heading" in text
        await pilot.press("escape")
        await pilot.pause(0.2)


async def test_d_on_a_scans_tab_raw_report_shows_the_log_and_the_title(tmp_path):
    from seek.tui.nmap.reader import DetailReader

    app = _app(tmp_path, "basic")
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.3)
        app.query_one(Tabs).active = "scans"
        await pilot.pause(0.3)
        assert app._rows, "basic.xml appears as history"
        app._report_mode = "raw"
        app._refresh_detail()
        await pilot.press("d")
        await pilot.pause(0.3)
        assert isinstance(app.screen, DetailReader)
        title = _render(app.screen.query_one(".title"))
        assert "Scan" in title and "basic" in title
        await pilot.press("escape")
        await pilot.pause(0.2)


async def test_a_running_scans_raw_log_keeps_streaming_into_an_open_reader(tmp_path):
    from seek.tui.nmap.reader import DetailReader

    slow = _stub(tmp_path, "#!/bin/sh\necho first\nsleep 0.4\necho SECOND_LINE\nsleep 5\n",
                name="slow-nmap")
    config = Config(nmap_path=slow, nmap_presets={"Quick": "-sV"},
                    scan_output_dir=str(tmp_path))
    app = _app(tmp_path, "basic", config=config)
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.3)
        await _run_a_scan(pilot, app)
        for _ in range(60):
            await pilot.pause(0.1)
            if app.runner.runs:
                break
        await pilot.press("d")
        await pilot.pause(0.3)
        reader = app.screen
        assert isinstance(reader, DetailReader)
        assert reader._follow is True
        for _ in range(20):
            await pilot.pause(0.1)
            if any("SECOND_LINE" in line.plain for line in reader._lines):
                break
        assert any("SECOND_LINE" in line.plain for line in reader._lines), \
            "the reader kept receiving output while it was open"
        await pilot.press("escape")
        await pilot.pause(0.3)
        app.runner.cancel()
        await pilot.pause(1.0)


async def test_freezing_from_inside_the_reader_matches_the_pane(tmp_path):
    """`p` cannot bubble out of a modal - the reader forwards it explicitly."""
    from seek.tui.nmap.reader import DetailReader

    app = _app(tmp_path, "basic", config=_slow(tmp_path))
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.3)
        await _run_a_scan(pilot, app)
        for _ in range(60):
            await pilot.pause(0.1)
            if app.runner.runs:
                break
        await pilot.press("d")
        await pilot.pause(0.3)
        reader = app.screen
        assert isinstance(reader, DetailReader)
        await pilot.press("p")
        await pilot.pause(0.2)
        assert app._log_frozen is True
        assert any("still running" in line.plain for line in reader._lines)
        await pilot.press("p")
        await pilot.pause(0.2)
        assert app._log_frozen is False
        await pilot.press("escape")
        await pilot.pause(0.3)
        app.runner.cancel()
        await pilot.pause(1.0)


async def test_the_hint_bar_and_help_mention_both_keys(tmp_path):
    app = _app(tmp_path, "basic")
    async with app.run_test(size=(140, 30)) as pilot:
        await pilot.pause(0.3)
        shown = _render(app.query_one("#hint-bar"))
        assert "read record" in shown or "detail" in shown or "pane" in shown, \
            "the keys that move through the record have to be on the bar"
        from rich.console import Console

        from seek.tui.nmap.help import help_body
        console = Console(width=90)
        with console.capture() as cap:
            console.print(help_body())
        text = cap.get()
        assert "full-screen" in text or "full screen" in text
        assert "pane" in text


# --- g/G in a modal, and stepping entries from the reader ---------------


async def test_g_and_G_move_the_reader_not_the_list_underneath(tmp_path):
    """`home,g` / `end,G` are priority bindings so they beat DataTable's own
    home/end - priority is checked before the screen, so they used to fire
    straight past the reader and jump the list underneath instead."""
    from seek.tui.nmap.reader import DetailReader

    app = _app(tmp_path, "basic")
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.3)
        table = app.query_one(DataTable)
        table.move_cursor(row=1)
        await pilot.pause(0.2)
        await pilot.press("d")
        await pilot.pause(0.3)
        assert isinstance(app.screen, DetailReader)
        await pilot.press("G")
        await pilot.pause(0.2)
        assert table.cursor_row == 1, "the list stayed where it was"
        await pilot.press("g")
        await pilot.pause(0.2)
        assert table.cursor_row == 1
        assert app.screen.top_line == 0


async def test_g_and_G_still_jump_the_list_with_no_modal_open(tmp_path):
    app = _app(tmp_path, "basic")
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.3)
        table = app.query_one(DataTable)
        await pilot.press("G")
        await pilot.pause(0.2)
        assert table.cursor_row == table.row_count - 1
        await pilot.press("g")
        await pilot.pause(0.2)
        assert table.cursor_row == 0


async def test_g_and_G_do_not_leak_through_the_help_screen(tmp_path):
    app = _app(tmp_path, "basic")
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.3)
        table = app.query_one(DataTable)
        table.move_cursor(row=1)
        await pilot.pause(0.2)
        await pilot.press("question_mark")
        await pilot.pause(0.3)
        await pilot.press("G")
        await pilot.pause(0.2)
        assert table.cursor_row == 1


async def test_arrows_step_through_entries_from_inside_the_reader(tmp_path):
    from seek.tui.nmap.reader import DetailReader

    app = _app(tmp_path, "basic")
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.3)
        table = app.query_one(DataTable)
        table.move_cursor(row=0)
        await pilot.pause(0.2)
        await pilot.press("d")
        await pilot.pause(0.3)
        reader = app.screen
        assert isinstance(reader, DetailReader)
        opened_on = reader._title
        await pilot.press("right")
        await pilot.pause(0.3)
        assert table.cursor_row == 1, "the list moved with the reader"
        assert reader._title != opened_on, "the title names the new entry"
        assert reader._title.endswith(app._rows[1].cells[0])
        await pilot.press("left")
        await pilot.pause(0.3)
        assert table.cursor_row == 0
        assert reader._title == opened_on


async def test_leaving_the_reader_lands_on_the_entry_last_read(tmp_path):
    app = _app(tmp_path, "basic")
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.3)
        table = app.query_one(DataTable)
        table.move_cursor(row=0)
        await pilot.pause(0.2)
        await pilot.press("d")
        await pilot.pause(0.3)
        await pilot.press("right")
        await pilot.pause(0.3)
        await pilot.press("escape")
        await pilot.pause(0.3)
        assert table.cursor_row == 1


async def test_stepping_shows_the_same_record_the_pane_shows(tmp_path):
    """The reader is a bigger pane, never a second description of a record -
    stepping must not be the one path where the two drift apart."""
    app = _app(tmp_path, "basic")
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.3)
        app.query_one(DataTable).move_cursor(row=0)
        await pilot.pause(0.2)
        await pilot.press("d")
        await pilot.pause(0.3)
        await pilot.press("right")
        await pilot.pause(0.3)
        reader_text = "\n".join(line.plain for line in app.screen._lines)
        await pilot.press("escape")
        await pilot.pause(0.3)
        pane = _render(app.query_one("#detail-body"))
        for token in app._rows[1].cells[0].split():
            assert token in reader_text and token in pane


async def test_opened_on_two_directories_a_scan_writes_into_the_first(tmp_path):
    roots = [tmp_path / "x", tmp_path / "y"]
    for root in roots:
        root.mkdir()
    config = Config(nmap_path=_stub(tmp_path), nmap_presets={"Quick": "-sV"})
    app = NmapApp(prepare(load([FIX / "basic.xml"])), config, sources=roots,
                  scan_dir=roots[0])
    async with app.run_test(size=(220, 40)) as pilot:
        await pilot.pause(0.3)
        assert "output → " in _render(app.query_one("#status")), "said before anything runs"
        await pilot.press("n")
        await pilot.pause(0.4)
        app.screen.query_one(TextArea).text = "10.0.0.1\n"
        await pilot.pause(0.3)
        await pilot.press("ctrl+s")
        await pilot.pause(0.4)
        await _choose(pilot, app, "Quick")
        await pilot.press("ctrl+s")
        await pilot.pause(0.5)
        assert isinstance(app.screen, ReviewScreen)
        shown = _modal_text(app).replace("\n", "")
        assert str(roots[0]) in shown and str(roots[1]) not in shown
