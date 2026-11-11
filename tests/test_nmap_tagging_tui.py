"""Tagging in the terminal viewer: `t`, the definition editor, `T` and `R`."""

from __future__ import annotations

from pathlib import Path

import pytest
from textual.widgets import Input, OptionList, SelectionList

from seek.config import Config
from seek.nmap.merge import load
from seek.nmap.views import prepare
from seek.tui.menu import ChoiceScreen, MultiChoiceScreen, PromptScreen
from seek.tui.nmap.app import NmapApp

pytestmark = [pytest.mark.asyncio, pytest.mark.slow]
FIX = Path(__file__).parent / "fixtures" / "nmap"


def _port(n, name):
    return (f'<port protocol="tcp" portid="{n}"><state state="open" reason="syn-ack"/>'
            f'<service name="{name}"/></port>')


def _printers_xml() -> str:
    """Five printers (192.0.2.x) and twenty look-alikes that also run ssh."""
    hosts = []
    for n in range(1, 6):
        hosts.append((f"192.0.2.{n}", [_port(80, "http"), _port(515, "printer"),
                                       _port(9100, "jetdirect")]))
    for n in range(1, 21):
        hosts.append((f"198.51.100.{n}", [_port(22, "ssh"), _port(80, "http"),
                                          _port(515, "printer"), _port(9100, "jetdirect")]))
    body = "".join(f'<host><status state="up" reason="syn-ack"/><address addr="{a}" '
                   f'addrtype="ipv4"/><ports>{"".join(ps)}</ports></host>' for a, ps in hosts)
    return ('<?xml version="1.0"?><nmaprun scanner="nmap" args="nmap -p 22,80,515,9100" '
            'start="1767225600"><scaninfo type="syn" protocol="tcp" numservices="4" '
            f'services="22,80,515,9100"/>{body}</nmaprun>')


def _app(tmp_path, xml: str | None = None) -> tuple[NmapApp, Path]:
    eng = tmp_path / "eng"
    eng.mkdir(exist_ok=True)
    scan = eng / "scan.xml"
    if xml is None:
        scan.write_bytes((FIX / "basic.xml").read_bytes())
    else:
        scan.write_text(xml)
    app = NmapApp(prepare(load([scan])), Config(nmap_path="/nonexistent/nmap"),
                  sources=[eng], scan_dir=eng)
    return app, eng


async def _choose(pilot, app, choice_id):
    options = app.screen.query_one(OptionList)
    options.highlighted = options.get_option_index(choice_id)
    await pilot.press("enter")
    await pilot.pause(0.3)


async def _answer(pilot, app, text):
    assert isinstance(app.screen, PromptScreen)
    app.screen.query_one(Input).value = text
    await pilot.press("enter")
    await pilot.pause(0.3)


async def _settle(pilot, seconds=0.6):
    await pilot.pause(seconds)


def _plain(lines) -> str:
    from rich.console import Console

    from seek.tui.nmap import detail as detail_pane
    console = Console(width=160, record=True, file=open("/dev/null", "w"))  # noqa: SIM115
    console.print(detail_pane.as_group(lines))
    return console.export_text()


def _screen_text(widget) -> str:
    from textual.geometry import Region
    region = Region(0, 0, widget.size.width, max(1, widget.size.height))
    return "\n".join("".join(s.text for s in strip) for strip in widget.render_lines(region))


def _row(app, address):
    return next(r for r in app._rows if r.cells[0] == address)


async def test_t_tags_the_marked_hosts_and_the_list_shows_it(tmp_path):
    app, eng = _app(tmp_path)
    async with app.run_test(size=(140, 40)) as pilot:
        await _settle(pilot, 0.4)
        await pilot.press("m", "down", "m")
        await pilot.press("t")
        await _settle(pilot, 0.4)
        assert isinstance(app.screen, ChoiceScreen)
        await _choose(pilot, app, "\x00new")
        await _answer(pilot, app, "explored")
        await _settle(pilot, 1.0)
        assert "explored" in (eng / "seek-tags.yaml").read_text()
        assert _row(app, "192.0.2.1").cells[-1] == "explored"
        assert _row(app, "192.0.2.2").cells[-1] == "explored"
        assert _row(app, "192.0.2.3").cells[-1] == ""
        # Again on the same marks: the choice now removes the manual tag.
        await pilot.press("t")
        await _settle(pilot, 0.4)
        options = app.screen.query_one(OptionList)
        label = str(options.get_option("explored").prompt)
        assert label.startswith("remove") and "2/2 carry it" in label
        await _choose(pilot, app, "explored")
        await _settle(pilot, 1.0)
        assert _row(app, "192.0.2.1").cells[-1] == ""


async def test_a_name_that_is_not_allowed_says_why_and_saves_nothing(tmp_path):
    app, eng = _app(tmp_path)
    async with app.run_test(size=(140, 40)) as pilot:
        await _settle(pilot, 0.4)
        await pilot.press("t")
        await _settle(pilot, 0.4)
        await _choose(pilot, app, "\x00new")
        await _answer(pilot, app, "my tag")
        assert isinstance(app.screen, PromptScreen), "asked again"
        prompt = str(app.screen._prompt)
        assert "not a tag name" in prompt
        await pilot.press("escape")
        await _settle(pilot, 0.4)
        assert not (eng / "seek-tags.yaml").exists()


async def test_an_issue_added_in_the_editor_reaches_the_record(tmp_path):
    app, eng = _app(tmp_path)
    async with app.run_test(size=(140, 40)) as pilot:
        await _settle(pilot, 0.4)
        await pilot.press("t")
        await _settle(pilot, 0.4)
        await _choose(pilot, app, "\x00edit")
        await _choose(pilot, app, "\x00new")
        await _answer(pilot, app, "camera-x")
        await _answer(pilot, app, "Camera model X")
        await _choose(pilot, app, "\x00new")            # add an issue
        await _answer(pilot, app, "Default credentials")
        await _choose(pilot, app, "high")
        await _answer(pilot, app, "")
        await _choose(pilot, app, "\x00done")
        await _settle(pilot, 1.0)
        text = (eng / "seek-tags.yaml").read_text()
        assert "Default credentials" in text and "high" in text
        # Tag the selected host with it: its record lists the issue.
        await pilot.press("t")
        await _settle(pilot, 0.4)
        await _choose(pilot, app, "camera-x")
        await _settle(pilot, 1.0)
        lines, _title = app._detail_content(_row(app, "192.0.2.1"))
        rendered = _plain(lines)
        assert "camera-x" in rendered and "Default credentials" in rendered


async def test_T_builds_the_five_printer_rule_end_to_end(tmp_path):
    app, eng = _app(tmp_path, _printers_xml())
    async with app.run_test(size=(160, 50)) as pilot:
        await _settle(pilot, 0.4)
        for _ in range(5):
            await pilot.press("m", "down")
        await pilot.press("T")
        await _settle(pilot, 1.0)
        assert isinstance(app.screen, MultiChoiceScreen)
        offered = dict(app.screen._choices)
        wanted = [cid for cid, label in offered.items()
                  if label.split("  (")[0] in ("80/tcp open", "515/tcp open", "9100/tcp open")]
        assert len(wanted) == 3
        for cid in wanted:
            app.screen.query_one(SelectionList).select(cid)
        app.screen.confirm()
        await _settle(pilot, 1.0)
        assert isinstance(app.screen, MultiChoiceScreen), "the exclusions"
        exclusions = dict(app.screen._choices)
        ssh = next(cid for cid, label in exclusions.items()
                   if label.startswith("not 22/tcp open"))
        assert "excludes 20/20" in exclusions[ssh]
        app.screen.query_one(SelectionList).select(ssh)
        app.screen.confirm()
        await _settle(pilot, 1.0)
        assert "Matches 5 host(s): 5 of 5 selected" in str(app.screen._prompt)
        await _choose(pilot, app, "\x00save")
        await _answer(pilot, app, "zebra")
        await _settle(pilot, 1.2)
        assert "built from 5 host(s)" in (eng / "seek-tags.yaml").read_text()
        tagged = sorted(r.cells[0] for r in app._rows if r.cells[-1])
        assert tagged == [f"192.0.2.{n}" for n in range(1, 6)]


async def test_R_reads_a_rule_file_edited_outside_the_viewer(tmp_path):
    app, eng = _app(tmp_path)
    async with app.run_test(size=(140, 40)) as pilot:
        await _settle(pilot, 0.4)
        assert all(r.cells[-1] == "" for r in app._rows)
        (eng / "seek-rules.yaml").write_text(
            "tags:\n  any-web:\n    rules: [{when: [{port: 80}]}]\n")
        await pilot.press("R")
        await _settle(pilot, 1.2)
        assert _row(app, "192.0.2.1").cells[-1] == "any-web"


async def test_a_broken_rule_file_is_named_on_the_status_line(tmp_path):
    app, eng = _app(tmp_path)
    (eng / "seek-rules.yaml").write_text("tags:\n  a: [unclosed\n")
    async with app.run_test(size=(160, 40)) as pilot:
        await _settle(pilot, 0.6)
        app._refresh_status()
        await _settle(pilot, 0.2)
        assert "some tag rules have problems" in _screen_text(app.query_one("#status"))
