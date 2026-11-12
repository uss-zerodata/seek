"""Tagging in the terminal viewer: `t`, the definition editor, `T` and `R`."""

from __future__ import annotations

from pathlib import Path

import pytest
from textual.widgets import Button, Input, Label, OptionList, Select, Static

from seek.config import Config
from seek.nmap import tagbuild as tb
from seek.nmap.merge import load
from seek.nmap.views import prepare
from seek.tui.menu import ChoiceScreen, PromptScreen
from seek.tui.nmap.app import NmapApp
from seek.tui.nmap.rulebench import FactEditScreen, RuleBenchScreen, RuleSaveScreen
from seek.tui.nmap.tageditor import IssueScreen, TagEditScreen

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


async def _fill_issue(pilot, app, title, severity="high", description="", refs=""):
    assert isinstance(app.screen, IssueScreen)
    app.screen.query_one("#title", Input).value = title
    app.screen.query_one("#severity", Select).value = severity
    app.screen.query_one("#description", Input).value = description
    app.screen.query_one("#references", Input).value = refs
    app.screen.action_take()
    await _settle(pilot, 0.4)


async def _add_issue(pilot, editor):
    issues = editor.query_one("#issues", OptionList)
    issues.focus()
    issues.highlighted = issues.get_option_index("\x00add")
    await pilot.press("enter")
    await _settle(pilot, 0.4)


async def test_an_issue_added_in_the_editor_reaches_the_record(tmp_path):
    app, eng = _app(tmp_path)
    async with app.run_test(size=(140, 40)) as pilot:
        await _settle(pilot, 0.4)
        await pilot.press("t")
        await _settle(pilot, 0.4)
        await _choose(pilot, app, "\x00edit")
        await _choose(pilot, app, "\x00new")
        editor = app.screen
        assert isinstance(editor, TagEditScreen)
        editor.query_one("#name", Input).value = "camera-x"
        editor.query_one("#description", Input).value = "Camera model X"
        await _add_issue(pilot, editor)
        await _fill_issue(pilot, app, "Default credentials", description="admin/admin",
                          refs="https://example.test/advisory")
        assert "Default credentials" in str(editor.query_one("#issues", OptionList)
                                            .get_option("i0").prompt)
        editor.action_save()
        await _settle(pilot, 1.0)
        text = (eng / "seek-tags.yaml").read_text()
        assert "Default credentials" in text and "https://example.test/advisory" in text
        # Tag the selected host with it: its record lists the issue and its description.
        await pilot.press("t")
        await _settle(pilot, 0.4)
        await _choose(pilot, app, "camera-x")
        await _settle(pilot, 1.0)
        lines, _title = app._detail_content(_row(app, "192.0.2.1"))
        rendered = _plain(lines)
        assert "camera-x" in rendered and "Default credentials" in rendered
        assert "admin/admin" in rendered and "Camera model X" in rendered


def _facts_of(screen) -> dict[str, str]:
    """The workbench's fact rows by label, as option ids."""
    out = {}
    for fid, fact in screen._fact_ids.items():
        out.setdefault(fact.label, fid)
    return out


async def _on_fact(pilot, screen, label, *keys):
    facts = screen.query_one("#facts", OptionList)
    facts.focus()
    facts.highlighted = facts.get_option_index(_facts_of(screen)[label])
    await pilot.press(*keys)
    await _settle(pilot, 0.5)


async def _open_bench(pilot, app, marks=5):
    for _ in range(marks):
        await pilot.press("m", "down")
    await pilot.press("T")
    await _settle(pilot, 1.2)
    assert isinstance(app.screen, RuleBenchScreen)
    return app.screen


def _total(screen) -> str:
    return str(screen.query_one("#total", Static).content)


async def test_T_builds_the_five_printer_rule_end_to_end(tmp_path):
    app, eng = _app(tmp_path, _printers_xml())
    async with app.run_test(size=(160, 50)) as pilot:
        await _settle(pilot, 0.4)
        bench = await _open_bench(pilot, app)
        for label in ("80/tcp open", "515/tcp open", "9100/tcp open"):
            await _on_fact(pilot, bench, label, "space")
        assert "matches 25 · 5/5 selected · 20 others" in _total(bench)
        assert "22/tcp open" in _facts_of(bench), "the exclusion is proposed inline"
        await _on_fact(pilot, bench, "22/tcp open", "space")
        assert "matches 5 · 5/5 selected · 0 others" in _total(bench)
        await pilot.press("s")
        await _settle(pilot, 0.8)
        assert isinstance(app.screen, RuleSaveScreen)
        app.screen.query_one("#tag", Input).value = "zebra"
        app.screen.action_save()
        await _settle(pilot, 1.0)
        editor = app.screen
        assert isinstance(editor, TagEditScreen), "the rule goes to the tag editor"
        assert not (eng / "seek-tags.yaml").exists(), "nothing written before it is saved"
        editor.query_one("#description", Input).value = "Zebra label printers"
        await _add_issue(pilot, editor)
        await _fill_issue(pilot, app, "Admin PIN of 4 digits", "medium")
        editor.action_save()
        await _settle(pilot, 1.2)
        text = (eng / "seek-tags.yaml").read_text()
        assert "built from 5 host(s)" in text and "Zebra label printers" in text
        assert "Admin PIN of 4 digits" in text
        tagged = sorted(r.cells[0] for r in app._rows if r.cells[-1])
        assert tagged == [f"192.0.2.{n}" for n in range(1, 6)]


async def test_changing_ones_mind_and_leaving_asks_first(tmp_path):
    app, _eng = _app(tmp_path, _printers_xml())
    async with app.run_test(size=(160, 50)) as pilot:
        await _settle(pilot, 0.4)
        bench = await _open_bench(pilot, app)
        await _on_fact(pilot, bench, "80/tcp open", "plus")
        await _on_fact(pilot, bench, "22/tcp open", "minus")
        await _on_fact(pilot, bench, "80/tcp open", "space", "space")   # require → … → ignore
        assert "matches 5 ·" in _total(bench), "the exclusion alone is kept"
        await pilot.press("escape")
        await _settle(pilot, 0.4)
        assert isinstance(app.screen, ChoiceScreen)
        await _choose(pilot, app, "stay")
        assert app.screen is bench


async def test_a_forgotten_printer_is_added_from_the_matches(tmp_path):
    app, _eng = _app(tmp_path, _printers_xml())
    async with app.run_test(size=(160, 50)) as pilot:
        await _settle(pilot, 0.4)
        bench = await _open_bench(pilot, app, marks=4)
        await _on_fact(pilot, bench, "9100/tcp open", "space")
        hosts = bench.query_one("#hosts", OptionList)
        hosts.focus()
        hosts.highlighted = hosts.get_option_index("o:192.0.2.5")
        await pilot.press("a")
        await _settle(pilot, 0.8)
        assert "5/5 selected" in _total(bench)
        assert "5 selected" in _screen_text(bench.query_one("#title"))


async def test_an_edit_widens_a_fact_and_an_invalid_one_says_why(tmp_path):
    app, eng = _app(tmp_path, _printers_xml())
    async with app.run_test(size=(160, 50)) as pilot:
        await _settle(pilot, 0.4)
        bench = await _open_bench(pilot, app)
        await _on_fact(pilot, bench, "80/tcp service = 'http'", "e")
        edit = app.screen
        assert isinstance(edit, FactEditScreen)
        edit.query_one("#value", Input).value = "htt("
        edit.query_one("#mode", Select).value = "regex"
        await _settle(pilot, 0.5)
        assert "not a valid expression" in str(edit.query_one("#error", Static).content)
        assert edit.query_one("#take", Button).disabled
        edit.query_one("#value", Input).value = "HTT"
        edit.query_one("#mode", Select).value = "contains"
        edit.query_one("#ports", Input).value = ""
        await _settle(pilot, 0.6)
        assert "matches 5/5 selected · 20 others" in str(edit.query_one("#count", Static).content)
        edit.action_take()
        await _settle(pilot, 0.8)
        assert "any tcp port service contains 'HTT'" in _facts_of(bench)
        assert bench.draft.state_of(next(f for f in bench._fact_ids.values()
                                         if f.label == "any tcp port service contains 'HTT'"))\
            is tb.State.REQUIRE


async def test_T_on_a_filtered_view_offers_the_rows_in_view(tmp_path):
    app, _eng = _app(tmp_path, _printers_xml())
    async with app.run_test(size=(160, 50)) as pilot:
        await _settle(pilot, 0.4)
        app.query_one("#filter", Input).value = "192.0.2"
        await _settle(pilot, 1.0)
        from seek.tui.nmap.app import ScanTable
        app.query_one(ScanTable).focus()
        await pilot.press("T")
        await _settle(pilot, 0.4)
        assert isinstance(app.screen, ChoiceScreen)
        await _choose(pilot, app, "\x00view")
        await _settle(pilot, 1.0)
        assert isinstance(app.screen, RuleBenchScreen)
        assert len(app.screen.draft.selection) == 5


async def test_a_saved_rule_is_edited_in_the_builder_and_replaced(tmp_path):
    app, eng = _app(tmp_path)
    (eng / "seek-rules.yaml").write_text(
        "# my rules\ntags:\n  web:\n    rules:\n      - {name: plain web, when: [{port: 80}]}\n")
    async with app.run_test(size=(160, 50)) as pilot:
        await _settle(pilot, 0.6)
        await pilot.press("t")
        await _settle(pilot, 0.4)
        await _choose(pilot, app, "\x00edit")
        await _choose(pilot, app, "web")
        editor = app.screen
        assert isinstance(editor, TagEditScreen)
        rules = editor.query_one("#rules", OptionList)
        rules.focus()
        rules.highlighted = 0
        await pilot.press("enter")
        await _settle(pilot, 1.0)
        bench = app.screen
        assert isinstance(bench, RuleBenchScreen) and "plain web" in str(
            bench.query_one("#title", Label).content)
        await _on_fact(pilot, bench, "80 open", "e")
        app.screen.query_one("#ports", Input).value = "80,8080"
        await _settle(pilot, 0.4)
        app.screen.action_take()
        await _settle(pilot, 0.8)
        await pilot.press("s")
        await _settle(pilot, 0.8)
        assert app.screen.query_one("#tag", Input).disabled, "the rule keeps its tag"
        app.screen.action_save()
        await _settle(pilot, 0.8)
        assert app.screen is editor and "~ plain web" in str(rules.get_option("r0").prompt)
        assert "8080" not in (eng / "seek-rules.yaml").read_text(), "not yet written"
        editor.action_save()
        await _settle(pilot, 0.6)
        assert isinstance(app.screen, ChoiceScreen), "the person's file: asked first"
        assert "seek-rules.yaml" in str(app.screen._prompt)
        await _choose(pilot, app, "yes")
        await _settle(pilot, 1.0)
        text = (eng / "seek-rules.yaml").read_text()
        assert "80,8080" in text and text.count("plain web") == 1


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


async def test_H_on_a_port_marks_its_host(tmp_path):
    app, _eng = _app(tmp_path)
    async with app.run_test(size=(140, 40)) as pilot:
        await _settle(pilot, 0.4)
        await pilot.press("enter")                 # into 192.0.2.1: its ports
        await _settle(pilot, 0.6)
        assert app._current_row().records[0].service is not None
        await pilot.press("H")
        await _settle(pilot, 0.3)
        assert list(app._marked) == [("192.0.2.1",)], "the host, not the port"
        await pilot.press("H")
        await _settle(pilot, 0.3)
        assert not app._marked


async def test_t_offers_the_tags_the_row_carries_first(tmp_path):
    app, eng = _app(tmp_path)
    (eng / "seek-rules.yaml").write_text("tags:\n  any-web:\n    rules: [{when: [{port: 80}]}]\n")
    async with app.run_test(size=(140, 40)) as pilot:
        await _settle(pilot, 0.8)
        await pilot.press("t")
        await _settle(pilot, 0.6)
        options = app.screen.query_one(OptionList)
        assert options.get_option_at_index(0).id == "\x00edit:any-web"
        await _choose(pilot, app, "\x00edit:any-web")
        await _settle(pilot, 0.6)
        assert isinstance(app.screen, TagEditScreen)
        assert app.screen.query_one("#name", Input).value == "any-web"
