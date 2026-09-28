"""The scan viewer: overviews, filtering, sorting, drill-down, exports."""

from __future__ import annotations

from pathlib import Path

import pytest
from rich.text import Text
from textual.geometry import Region
from textual.widgets import (
    DataTable,
    Input,
    Label,
    OptionList,
    SelectionList,
    Tab,
    Tabs,
)

from seek.config import Config
from seek.nmap.merge import load
from seek.nmap.views import prepare
from seek.tui.nmap.app import NmapApp

pytestmark = pytest.mark.asyncio
FIX = Path(__file__).parent / "fixtures" / "nmap"


def _app(*names, config: Config | None = None) -> NmapApp:
    return NmapApp(prepare(load([FIX / f"{n}.xml" for n in names])), config)


def _cells(app, col=0):
    return [r.cells[col] for r in app._rows]


def _render(w) -> str:
    region = Region(0, 0, w.size.width, max(1, w.size.height))
    return "\n".join("".join(s.text for s in strip) for strip in w.render_lines(region))


async def _choose(pilot, app, choice_id):
    """Pick a modal choice by id, the way the keyboard picks it.

    The choices are an option list rather than a stack of buttons, so there is
    no `#id` widget to click - six three-line buttons ran off a 24-row terminal
    and put the last choice out of reach.
    """
    options = app.screen.query_one(OptionList)
    options.highlighted = options.get_option_index(choice_id)
    await pilot.press("enter")
    await pilot.pause(0.25)


async def _type(pilot, text, leave=True):
    """Open the filter with `/`, type, and (by default) return to the list.

    Filtering is debounced by `config.debounce_ms`, so the pause has to outlast
    it; leaving the box with Enter flushes any pending filter at once.
    """
    await pilot.press("slash")
    for ch in text:
        await pilot.press(ch)
    if leave:
        await pilot.press("enter")
    await pilot.pause(0.35)


# --- overviews --------------------------------------------------------------


async def test_host_view_lists_hosts_with_summary_columns():
    app = _app("basic")
    async with app.run_test(size=(120, 30)) as pilot:
        await pilot.pause(0.1)
        assert app.view.columns[:5] == ("Address", "Hostname", "OS", "State", "Svcs")
        assert _cells(app) == ["192.0.2.1", "192.0.2.2", "192.0.2.3"]


async def test_missing_hostname_and_os_still_listed_as_absent():
    app = _app("basic")
    async with app.run_test(size=(120, 30)) as pilot:
        await pilot.pause(0.1)
        row = next(r for r in app._rows if r.cells[0] == "192.0.2.2")
        assert row.cells[1] == "—" and row.cells[2] == "—"


async def test_down_hosts_are_distinguishable():
    app = _app("basic")
    async with app.run_test(size=(120, 30)) as pilot:
        await pilot.pause(0.1)
        states = {r.cells[0]: r.cells[3] for r in app._rows}
        assert states["192.0.2.3"] == "down"
        assert states["192.0.2.1"] == "up"


async def test_tab_swaps_to_the_service_view_and_groups_hosts():
    app = _app("basic")
    async with app.run_test(size=(120, 30)) as pilot:
        await pilot.press("v")
        await pilot.pause(0.1)
        assert app.view.kind == "services"
        http = next(r for r in app._rows if r.cells[0] == "80")
        assert http.cells[6] == "2", "both hosts run nginx on 80 -> one row, two hosts"


# --- the -Pn case -----------------------------------------------------------


async def test_pn_scan_warns_and_lists_by_the_up_rule():
    app = _app("pn-asserted")
    async with app.run_test(size=(120, 30)) as pilot:
        await pilot.pause(0.1)
        warn = _render(app.query_one("#warn"))
        assert "asserted 10" in warn and "only 2" in warn
        states = [r.cells[3] for r in app._rows]
        assert states.count("unconfirmed") == 8
        assert states.count("up*") == 2


async def test_the_state_column_says_which_part_of_the_rule_applies():
    app = _app("up-rule-pn", "up-rule-discovery")
    async with app.run_test(size=(120, 30)) as pilot:
        await pilot.pause(0.2)
        state = {r.cells[0]: r.cells[3] for r in app._rows}
        assert state == {
            "203.0.113.1": "up*",           # -Pn, open port
            "203.0.113.2": "unconfirmed",   # -Pn, closed/filtered/OS/scripts only
            "203.0.113.3": "unconfirmed",   # -Pn, nothing
            "203.0.113.4": "up",            # answered discovery
            "203.0.113.5": "down",
            "203.0.113.6": "up*",           # recorded down, open port elsewhere
        }


async def test_u_lists_exactly_the_up_hosts_and_agrees_with_the_export():
    from seek.nmap.export import Record, export_all_hosts, export_up_hosts

    app = _app("up-rule-pn", "up-rule-discovery")
    async with app.run_test(size=(120, 30)) as pilot:
        await pilot.pause(0.2)
        everything = [rec for r in app._rows for rec in r.records]
        await pilot.press("u")
        await pilot.pause(0.2)
        assert _cells(app) == ["203.0.113.1", "203.0.113.4", "203.0.113.6"]
        filtered = [rec for r in app._rows for rec in r.records]
        assert export_all_hosts(filtered) == export_up_hosts(everything)
        assert all(isinstance(rec, Record) for rec in filtered)


async def test_r_keeps_hosts_with_an_open_port_and_pairs_with_u():
    app = _app("up-rule-pn", "up-rule-discovery")
    async with app.run_test(size=(120, 30)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("r")
        await pilot.pause(0.2)
        assert _cells(app) == ["203.0.113.1", "203.0.113.6"], "open ports only"
        assert app.view.title == "Hosts (open ports)"
        await pilot.press("u")                    # both: an open port is always up
        await pilot.pause(0.2)
        assert _cells(app) == ["203.0.113.1", "203.0.113.6"]
        assert app.view.title == "Hosts (up, open ports)"
        await pilot.press("r")                    # r off leaves u where it was
        await pilot.pause(0.2)
        assert _cells(app) == ["203.0.113.1", "203.0.113.4", "203.0.113.6"]
        assert app._only_up and not app._only_ports


async def test_r_from_another_tab_goes_to_the_host_list():
    app = _app("basic")
    async with app.run_test(size=(120, 30)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("s")
        await pilot.pause(0.2)
        await pilot.press("r")
        await pilot.pause(0.3)
        assert app.view.kind == "hosts"
        assert _cells(app) == ["192.0.2.1", "192.0.2.2"], ".3 is down with no ports"


async def test_r_on_a_hosts_ports_keeps_the_open_ones_like_u():
    app = _app("basic")
    async with app.run_test(size=(120, 30)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("enter")                # 192.0.2.1's ports
        await pilot.pause(0.2)
        await pilot.press("r")
        await pilot.pause(0.2)
        assert app.view.kind == "host-detail"
        assert [r.cells[0] for r in app._rows] == ["22/tcp", "80/tcp"]
        assert not app._only_ports, "the host list is not filtered"


async def test_r_names_itself_when_nothing_has_an_open_port(tmp_path):
    scan = tmp_path / "ping.xml"                  # up by discovery, no ports
    scan.write_text(
        '<?xml version="1.0"?>\n<nmaprun scanner="nmap" args="nmap -sn -oX ping.xml '
        '203.0.113.9" start="1756000000" version="7.94" xmloutputversion="1.05">\n'
        '<host><status state="up" reason="echo-reply" reason_ttl="64"/>'
        '<address addr="203.0.113.9" addrtype="ipv4"/></host>\n</nmaprun>\n')
    app = NmapApp(prepare(load([scan])))
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("u")
        await pilot.pause(0.2)
        assert _cells(app) == ["203.0.113.9"], "up, by discovery"
        await pilot.press("r")
        await pilot.pause(0.3)
        assert not app._rows
        shown = _empty_text(app)
        assert "No host has an open port" in shown and "u and r list every host" in shown


async def test_up_toggle_filters_by_the_rule():
    app = _app("pn-asserted")
    async with app.run_test(size=(120, 30)) as pilot:
        await pilot.pause(0.1)
        assert len(app._rows) == 10
        await pilot.press("u")
        await pilot.pause(0.1)
        assert len(app._rows) == 2
        assert _cells(app) == ["198.51.100.3", "198.51.100.7"]


async def test_no_warning_when_discovery_was_real():
    app = _app("discovery")
    async with app.run_test(size=(120, 30)) as pilot:
        await pilot.pause(0.1)
        assert _render(app.query_one("#warn")).strip() == ""


# --- filtering --------------------------------------------------------------


async def test_typing_narrows_the_rows():
    app = _app("basic")
    async with app.run_test(size=(120, 30)) as pilot:
        await _type(pilot, "alpha")
        assert _cells(app) == ["192.0.2.1"]


async def test_filter_honours_the_query_grammar():
    app = _app("basic")
    async with app.run_test(size=(120, 30)) as pilot:
        await pilot.press("v")          # services
        await _type(pilot, "'http !443")
        names = [r.cells[2] for r in app._rows]
        assert names and all(n == "http" for n in names)


async def test_clearing_the_filter_restores_every_row():
    app = _app("basic")
    async with app.run_test(size=(120, 30)) as pilot:
        await _type(pilot, "alpha")
        assert len(app._rows) == 1
        await pilot.press("escape")      # from the list, Esc clears the filter
        await pilot.pause(0.15)
        assert len(app._rows) == 3


# --- sorting ----------------------------------------------------------------


async def test_sorting_by_a_column_and_reversing_it():
    app = _app("basic")
    async with app.run_test(size=(120, 30)) as pilot:
        await pilot.press("5")            # Svcs
        await pilot.pause(0.1)
        # .1 has 22+80 open, .2 has only 80 (22 is filtered), .3 is down
        assert [r.cells[4] for r in app._rows] == ["0", "1", "2"]
        await pilot.press("5")            # the same column again reverses it
        await pilot.pause(0.1)
        assert [r.cells[4] for r in app._rows] == ["2", "1", "0"]
        await pilot.press("5")            # and again flips it back
        await pilot.pause(0.1)
        assert [r.cells[4] for r in app._rows] == ["0", "1", "2"]
        await pilot.press("2")            # another column starts ascending
        await pilot.pause(0.1)
        assert app._sort_col == 1 and not app._sort_desc


async def test_sorting_respects_an_active_filter():
    app = _app("basic")
    async with app.run_test(size=(120, 30)) as pilot:
        await _type(pilot, "192.0.2")
        await pilot.press("1")
        await pilot.pause(0.1)
        assert len(app._rows) == 3
        assert app.query_one("#filter", Input).value == "192.0.2"


# --- drill-down -------------------------------------------------------------


async def test_host_drill_down_lists_its_services_and_back_returns():
    app = _app("basic")
    async with app.run_test(size=(120, 30)) as pilot:
        app.query_one(DataTable).move_cursor(row=0)
        await pilot.press("enter")
        await pilot.pause(0.1)
        assert app.view.kind == "host-detail"
        assert "192.0.2.1" in app.view.title
        assert [r.cells[0] for r in app._rows] == ["22/tcp", "80/tcp", "443/tcp"]
        await pilot.press("escape")
        await pilot.pause(0.1)
        assert app.view.kind == "hosts"


async def test_u_on_a_hosts_ports_keeps_only_the_open_ones():
    """`u` asks the port list what it asks the host list: what was found, not
    what was merely recorded. It filters in place and carries to the next host."""
    app = _app("basic")
    async with app.run_test(size=(120, 30)) as pilot:
        app.query_one(DataTable).move_cursor(row=0)
        await pilot.press("enter")
        await pilot.pause(0.1)
        await pilot.press("u")
        await pilot.pause(0.1)
        assert app.view.kind == "host-detail", "it stays on the host"
        assert [r.cells[0] for r in app._rows] == ["22/tcp", "80/tcp"]
        assert not app._only_up, "hiding closed ports hides no hosts"
        await pilot.press("escape")
        await pilot.pause(0.1)
        assert len(app._rows) == 3, "the host list is unfiltered"
        app.query_one(DataTable).move_cursor(row=1)
        await pilot.press("enter")
        await pilot.pause(0.1)
        assert [r.cells[0] for r in app._rows] == ["80/tcp"], "22/tcp is filtered"
        await pilot.press("u")
        await pilot.pause(0.1)
        assert [r.cells[0] for r in app._rows] == ["22/tcp", "80/tcp"]


async def test_a_host_with_no_open_port_says_so(tmp_path):
    scan = tmp_path / "closed.xml"
    scan.write_text(
        '<?xml version="1.0"?>\n<nmaprun scanner="nmap" args="nmap -oX closed.xml '
        '192.0.2.9" start="1756000000" version="7.94" xmloutputversion="1.05">\n'
        '<host><status state="up" reason="syn-ack" reason_ttl="64"/>'
        '<address addr="192.0.2.9" addrtype="ipv4"/><ports>'
        '<port protocol="tcp" portid="443"><state state="closed" reason="conn-refused" '
        'reason_ttl="64"/></port></ports></host>\n</nmaprun>\n')
    app = NmapApp(prepare(load([scan])))
    async with app.run_test(size=(120, 30)) as pilot:
        await pilot.pause(0.1)
        await pilot.press("enter")
        await pilot.pause(0.1)
        await pilot.press("u")
        await pilot.pause(0.2)
        assert not app._rows
        shown = _empty_text(app)
        assert "No open port" in shown and "u lists every port" in shown


async def test_service_drill_down_lists_its_hosts():
    app = _app("basic")
    async with app.run_test(size=(120, 30)) as pilot:
        await pilot.press("v")
        await pilot.pause(0.1)
        idx = next(i for i, r in enumerate(app._rows) if r.cells[0] == "80")
        app.query_one(DataTable).move_cursor(row=idx)
        await pilot.press("enter")
        await pilot.pause(0.1)
        assert app.view.kind == "service-detail"
        assert _cells(app) == ["192.0.2.1", "192.0.2.2"]


async def test_hosts_at_different_versions_show_their_own():
    app = _app("merge-a", "merge-b")
    async with app.run_test(size=(120, 30)) as pilot:
        await pilot.press("v")
        await pilot.pause(0.1)
        idx = next(i for i, r in enumerate(app._rows) if r.cells[0] == "22")
        app.query_one(DataTable).move_cursor(row=idx)
        await pilot.press("enter")
        await pilot.pause(0.1)
        assert app._rows[0].cells[2] == "10.0p2"


async def test_breadcrumb_shows_the_path_and_esc_unwinds_one_level():
    app = _app("basic")
    async with app.run_test(size=(120, 30)) as pilot:
        await pilot.pause(0.1)
        app.query_one(DataTable).move_cursor(row=0)
        await pilot.press("enter")
        await pilot.pause(0.1)
        assert "›" in _render(app.query_one("#title")), "the breadcrumb is in the title"
        await _type(pilot, "22")          # returns to the list on Enter
        await pilot.press("escape")       # clears the filter
        await pilot.pause(0.15)
        assert app.view.kind == "host-detail"
        await pilot.press("escape")       # then pops the view
        await pilot.pause(0.15)
        assert app.view.kind == "hosts"


# --- statistics and grouping ------------------------------------------------


async def test_statistics_view_separates_asserted_from_up():
    app = _app("pn-asserted")
    async with app.run_test(size=(120, 30)) as pilot:
        await pilot.press("s")
        await pilot.pause(0.1)
        assert app.view.kind == "stats"
        text = {r.cells[0]: r.cells[1] for r in app._rows}
        assert text["Asserted up"] == "10"
        assert text["Up"] == "2"


async def test_grouping_cycles_through_service_product_and_port():
    app = _app("basic")
    async with app.run_test(size=(120, 30)) as pilot:
        await pilot.press("b")
        await pilot.pause(0.1)
        assert app.view.title == "Grouped by service"
        await pilot.press("b")
        await pilot.pause(0.1)
        assert app.view.title == "Grouped by product"
        await pilot.press("b")
        await pilot.pause(0.1)
        assert app.view.title == "Grouped by port"


# --- exports ----------------------------------------------------------------


async def test_export_uses_the_visible_rows(monkeypatch):
    captured = {}
    monkeypatch.setattr("seek.actions.copy_to_clipboard",
                        lambda text: captured.update(text=text))
    app = _app("basic")
    async with app.run_test(size=(120, 30)) as pilot:
        await _type(pilot, "alpha")       # only 192.0.2.1
        await pilot.press("x")
        await pilot.pause(0.2)
        await _choose(pilot, app, "hosts")
        await _choose(pilot, app, "text")        # the format
        await _choose(pilot, app, "clipboard")
    assert captured.get("text") == "192.0.2.1"


# --- the detail pane --------------------------------------------------------


async def test_detail_follows_the_cursor():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.1)
        first = _render(app.query_one("#detail-body"))
        assert "192.0.2.1" in first
        app.query_one(DataTable).move_cursor(row=1)
        await pilot.pause(0.1)
        second = _render(app.query_one("#detail-body"))
        assert "192.0.2.2" in second
        assert second != first


async def test_host_detail_shows_os_state_reason_and_provenance():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.1)
        shown = _render(app.query_one("#detail-body"))
        assert "Linux 5.X" in shown
        assert "syn-ack" in shown, "the reason a host was called up must be visible"
        # Provenance is a block of entries now rather than a run of file names:
        # the scan is named as the Scans tab names it, and says what it found.
        assert "Scans" in shown and "basic" in shown, "provenance"
        assert "port(s) open" in shown, "and what that scan established"


async def test_detail_labels_an_asserted_state():
    app = _app("pn-asserted")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.1)
        shown = _render(app.query_one("#detail-body"))
        assert "asserted" in shown.lower()
        assert "-Pn" in shown


async def test_vulnerability_detail_is_visible_without_navigating_away():
    app = _app("vuln")
    async with app.run_test(size=(130, 50)) as pilot:
        await pilot.press("enter")           # into the host's services
        await pilot.pause(0.2)
        shown = _render(app.query_one("#detail-body"))
        assert "CVE-2011-3192" in shown
        assert "VULNERABLE" in shown
        assert "Apache byterange filter DoS" in shown
        assert "BID:49303" in shown          # cross-reference ids
        assert "2011-08-19" in shown         # disclosure date
        assert "https://" in shown           # reference URLs


async def test_script_output_is_visible_in_the_detail():
    app = _app("scripts")
    async with app.run_test(size=(130, 44)) as pilot:
        await pilot.press("enter")
        await pilot.pause(0.2)
        shown = _render(app.query_one("#detail-body"))
        assert "ssl-cert" in shown or "http-title" in shown


async def test_service_group_detail_lists_its_hosts():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.press("v")
        await pilot.pause(0.1)
        idx = next(i for i, r in enumerate(app._rows) if r.cells[0] == "80")
        app.query_one(DataTable).move_cursor(row=idx)
        await pilot.pause(0.1)
        shown = _render(app.query_one("#detail-body"))
        assert "192.0.2.1" in shown and "192.0.2.2" in shown


async def test_detail_pane_can_be_dismissed():
    """`D` collapses the inline pane - `d` opens the full-screen reader instead;
    see tests/test_nmap_scanning.py for the reader's own coverage."""
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.1)
        assert app.query_one("#detail").display is True
        await pilot.press("D")
        await pilot.pause(0.1)
        assert app.query_one("#detail").display is False


async def test_detail_pane_is_dropped_on_a_short_terminal():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.1)
        assert app.query_one("#detail").display is True
        await pilot.resize_terminal(120, 12)
        await pilot.pause(0.5)
        assert app.query_one("#detail").display is False


# --- list navigation --------------------------------------------------------


async def test_paging_and_jumping_move_the_selection():
    app = _app("pn-asserted")
    async with app.run_test(size=(120, 20)) as pilot:
        await pilot.pause(0.1)
        table = app.query_one(DataTable)
        assert table.cursor_row == 0
        await pilot.press("end")
        await pilot.pause(0.1)
        assert table.cursor_row == len(app._rows) - 1
        await pilot.press("home")
        await pilot.pause(0.1)
        assert table.cursor_row == 0
        await pilot.press("pagedown")
        await pilot.pause(0.1)
        assert table.cursor_row > 0


async def test_arrows_move_the_selection_and_the_detail():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.1)
        await pilot.press("down")
        await pilot.pause(0.1)
        assert app.query_one(DataTable).cursor_row == 1
        assert "192.0.2.2" in _render(app.query_one("#detail-body"))


async def test_filtering_resets_the_selection_to_the_first_match():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.press("end")
        await pilot.pause(0.1)
        await _type(pilot, "alpha")
        assert app.query_one(DataTable).cursor_row == 0
        assert "192.0.2.1" in _render(app.query_one("#detail-body"))


# --- feedback fixes ---------------------------------------------------------


async def test_the_table_holds_focus_so_the_selected_row_is_visible():
    """The row cursor only renders while the table has focus; the filter is
    opened with `/` rather than holding focus permanently."""
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.1)
        table = app.query_one(DataTable)
        assert app.focused is table
        assert table.show_cursor is True
        assert table.cursor_type == "row"
        await pilot.press("slash")
        await pilot.pause(0.1)
        assert app.focused is app.query_one("#filter", Input)
        await pilot.press("escape")
        await pilot.pause(0.1)
        assert app.focused is table, "Esc returns to the list"


async def test_ip_addresses_sort_numerically_not_alphabetically():
    app = _app("pn-asserted")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.1)
        await pilot.press("4")                    # away from the address column,
        await pilot.press("1")                    # so `1` sorts it ascending
        await pilot.pause(0.1)
        got = _cells(app)
        assert got == sorted(got, key=lambda a: tuple(int(p) for p in a.split("."))), got
        assert got[:3] == ["198.51.100.1", "198.51.100.2", "198.51.100.3"]


async def test_the_already_sorted_column_reverses_on_its_first_press():
    """The list opens sorted by address; `1` names that column, so it reverses."""
    app = _app("pn-asserted")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.1)
        ascending = _cells(app)
        await pilot.press("1")
        await pilot.pause(0.1)
        assert _cells(app) == list(reversed(ascending))


async def test_the_sorted_column_is_named_in_the_status():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.press("3")
        await pilot.pause(0.1)
        status = _render(app.query_one("#status"))
        assert "sorted by 3 OS" in status
        assert "↑" in status
        await pilot.press("3")
        await pilot.pause(0.1)
        assert "↓" in _render(app.query_one("#status"))


async def test_filter_matches_are_highlighted_in_the_list():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await _type(pilot, "alpha")
        table = app.query_one(DataTable)
        cell = table.get_cell_at((0, 2))          # Hostname, past the mark column
        assert isinstance(cell, Text), "cells must be Rich Text to carry highlights"
        assert cell.plain == "alpha.example"
        styled = [pos for pos in range(len(cell.plain))
                  if any(sp.start <= pos < sp.end for sp in cell.spans)]
        assert styled, "the matched characters must be marked"
        assert set(styled) <= set(range(len("alpha")))


async def test_no_highlighting_when_the_filter_is_empty():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.1)
        cell = app.query_one(DataTable).get_cell_at((0, 0))
        assert cell.spans == []


async def test_every_action_key_is_bare_and_terminal_safe():
    """Terminals steal ctrl+s (XOFF), alt+digits (tab switching) and tab
    (focus traversal), so the viewer uses none of them."""
    keys = {k.strip() for b in NmapApp.BINDINGS for k in b.key.split(",")}
    stolen = {k for k in keys if k.startswith(("ctrl+", "alt+", "shift+"))}
    assert stolen == set(), f"terminal-conflicting bindings: {stolen}"
    assert "tab" not in keys
    for expected in ("v", "r", "s", "b", "u", "d", "x", "slash", "question_mark", "q"):
        assert expected in keys, f"missing {expected}"


async def test_help_overlay_lists_the_keys():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.press("question_mark")
        await pilot.pause(0.2)
        assert app.screen is not app.screen_stack[0]
        await pilot.press("escape")
        await pilot.pause(0.2)
        assert app.screen is app.screen_stack[0]


async def test_detail_report_uses_labelled_lines_and_bulleted_lists():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.1)
        shown = _render(app.query_one("#detail-body"))
        assert "Services" in shown
        assert "•" in shown, "collections are rendered as bullets"
        assert "os" in shown and "state" in shown


# --- style, layout and range filtering --------------------------------------


async def test_regions_are_fenced_by_rules_not_filled_bands():
    """Same convention as the search session: ANSI themes collapse background
    shades, so separation is a thin rule and nothing carries a fill."""
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        assert app.query_one("#list-area").styles.border_bottom[0] == "solid"
        assert app.query_one("#detail").styles.border_bottom[0] == "solid"
        for widget in ("#status", "#hint-bar", "#warn"):
            assert app.query_one(widget).styles.background.a == 0


@pytest.mark.parametrize("width", [56, 80, 120, 160])
async def test_the_table_never_overflows_horizontally(width):
    app = _app("merge-a", "merge-b")     # long product names to squeeze
    async with app.run_test(size=(width, 30)) as pilot:
        await pilot.pause(0.4)
        table = app.query_one(DataTable)
        budget = table.scrollable_content_region.width or width
        used = sum(app._widths) + 2 * len(app._widths)
        assert used <= budget, f"at width {width}: {used} > {budget}"


async def test_narrow_terminals_clip_cells_rather_than_overflow():
    app = _app("merge-a", "merge-b")
    async with app.run_test(size=(52, 24)) as pilot:
        await pilot.pause(0.4)
        table = app.query_one(DataTable)
        for col in range(len(app.view.columns)):
            cell = table.get_cell_at((0, col))
            assert len(cell.plain) <= app._widths[col]


async def test_the_detail_pane_scrolls():
    """The pane comes up to meet its cursor, rather than being scrolled blind.

    `J` moves the cursor a line; the record moves only once the cursor reaches
    the edge of what is visible, which is why a single press does not scroll.
    """
    app = _app("vuln")
    async with app.run_test(size=(120, 34)) as pilot:
        await pilot.press("enter")           # a report taller than the pane
        await pilot.pause(0.3)
        pane = app.query_one("#detail")
        assert pane.max_scroll_y > 0, "the report must exceed the pane"
        assert pane.scroll_offset.y == 0
        await pilot.press("J")
        await pilot.pause(0.1)
        assert pane.scroll_offset.y == 0, "the cursor is still on screen"
        for _ in range(len(app._lines)):
            await pilot.press("J")
        await pilot.pause(0.2)
        assert pane.scroll_offset.y > 0
        for _ in range(len(app._lines)):
            await pilot.press("K")
        await pilot.pause(0.2)
        assert pane.scroll_offset.y == 0 and app._line == 0


async def test_moving_to_another_row_returns_the_report_to_the_top():
    app = _app("vuln")
    async with app.run_test(size=(120, 34)) as pilot:
        await pilot.press("enter")
        await pilot.pause(0.3)
        for _ in range(len(app._lines)):
            await pilot.press("J")
        await pilot.pause(0.2)
        assert app.query_one("#detail").scroll_offset.y > 0
        await pilot.press("down")
        await pilot.pause(0.3)
        assert app.query_one("#detail").scroll_offset.y == 0
        assert app._line == 0, "and the cursor with it"


async def test_filtering_by_a_cidr_range():
    app = _app("pn-asserted")
    async with app.run_test(size=(120, 40)) as pilot:
        await _type(pilot, "198.51.100.0/29")
        assert _cells(app) == [f"198.51.100.{i}" for i in range(1, 8)]


async def test_a_cidr_range_and_a_fuzzy_term_compose():
    app = _app("pn-asserted")
    async with app.run_test(size=(120, 40)) as pilot:
        await _type(pilot, "198.51.100.0/29 lighttpd")
        # only .3 and .7 run lighttpd, and both are inside the /29
        assert _cells(app) == ["198.51.100.3", "198.51.100.7"]


async def test_the_resolved_range_is_shown_in_the_status():
    app = _app("pn-asserted")
    async with app.run_test(size=(120, 40)) as pilot:
        await _type(pilot, "198.51.100.4/30")
        assert "in 198.51.100.4/30" in _render(app.query_one("#status"))


async def test_a_complete_address_selects_exactly_that_host():
    app = _app("pn-asserted")
    async with app.run_test(size=(120, 40)) as pilot:
        await _type(pilot, "198.51.100.1")
        assert _cells(app) == ["198.51.100.1"], "a complete address is a /32"


async def test_an_incomplete_address_still_matches_many():
    app = _app("pn-asserted")
    async with app.run_test(size=(120, 40)) as pilot:
        await _type(pilot, "198.51.100.")
        assert len(_cells(app)) == 10, "still fuzzy until the address is complete"


async def test_cidr_filtering_works_in_the_service_view():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.press("v")
        await pilot.pause(0.2)
        before = len(app._rows)
        await _type(pilot, "192.0.2.2/32")
        assert 0 < len(app._rows) < before
        assert all("192.0.2.2" in r.addresses for r in app._rows)


# --- table titles and arrow-key roles ---------------------------------------


async def test_each_table_is_titled_by_its_tab():
    """At the top of an overview the tab is the title; the title row is spent
    only once there is a path back."""
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        tabs = app.query_one(Tabs)
        assert tabs.active == "hosts" and app.view.title == "Hosts"
        await pilot.press("v")
        await pilot.pause(0.3)
        assert tabs.active == "services" and app.view.title == "Services"
        await pilot.press("s")
        await pilot.pause(0.3)
        assert tabs.active == "stats" and app.view.title == "Statistics"


async def test_the_title_carries_the_breadcrumb_path():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("enter")
        await pilot.pause(0.2)
        title = _render(app.query_one("#title"))
        assert "Hosts" in title and "192.0.2.1" in title and "›" in title


async def test_columns_are_titled_and_numbered_for_sorting():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        table = app.query_one(DataTable)
        assert table.show_header is True
        labels = [str(c.label) for c in table.columns.values()]
        assert labels[0] == " ", "the mark column is first and carries no number"
        assert labels[1].startswith("1 Address")
        assert any("Hostname" in x for x in labels)
        assert "↑" in labels[1], "the sorted column is marked in its title"


async def test_left_and_right_act_on_the_pane_not_on_the_columns():
    """`DataTable` binds them to column movement; the viewer's binding wins.

    What they do on the pane changed - they jump between the lines that can be
    opened rather than scrolling it - but the thing this guards is unchanged:
    they must never move the table's own column cursor.
    """
    app = _app("vuln")
    async with app.run_test(size=(120, 34)) as pilot:
        await pilot.press("enter")
        await pilot.pause(0.3)
        table = app.query_one(DataTable)
        assert table.cursor_column == 0
        marks = app._openable()
        assert marks, "a service's record offers the scans that saw it"

        await pilot.press("right")
        await pilot.pause(0.1)
        assert app._line == marks[0], "the pane's cursor went to an entry"
        assert table.cursor_column == 0, "and the table's columns did not move"

        await pilot.press("left")
        await pilot.pause(0.1)
        assert table.cursor_column == 0


async def test_up_and_down_still_move_the_selection():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        table = app.query_one(DataTable)
        await pilot.press("down")
        await pilot.pause(0.2)
        assert table.cursor_row == 1
        await pilot.press("up")
        await pilot.pause(0.2)
        assert table.cursor_row == 0


async def test_arrows_still_edit_text_inside_the_filter():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.press("slash")
        for ch in "abc":
            await pilot.press(ch)
        await pilot.pause(0.2)
        box = app.query_one("#filter", Input)
        assert box.cursor_position == 3
        await pilot.press("left")
        await pilot.pause(0.2)
        assert box.cursor_position == 2, "← must move the text cursor, not scroll"


# --- overviews as tabs ------------------------------------------------------


async def test_the_overviews_are_shown_as_tabs():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        labels = [str(t.label) for t in app.query_one(Tabs).query(Tab)]
        assert labels == ["Hosts", "Services", "Statistics", "By service",
                          "By product", "By port", "Names", "Scans"]
        assert app.query_one(Tabs).active == "hosts"


async def test_v_cycles_forward_and_back_through_the_tabs():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        await pilot.press("v")
        await pilot.pause(0.3)
        assert app.query_one(Tabs).active == "services"
        assert app.view.title == "Services"
        await pilot.press("V")
        await pilot.pause(0.3)
        assert app.query_one(Tabs).active == "hosts"


async def test_direct_keys_activate_their_tab():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        await pilot.press("s")
        await pilot.pause(0.3)
        assert app.query_one(Tabs).active == "stats"
        await pilot.press("b")
        await pilot.pause(0.3)
        assert app.query_one(Tabs).active == "group-service"
        await pilot.press("b")
        await pilot.pause(0.3)
        assert app.query_one(Tabs).active == "group-product"


async def test_clicking_a_tab_switches_the_overview():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        app.query_one(Tabs).active = "services"
        await pilot.pause(0.4)
        assert app.view.title == "Services"
        assert app.focused is app.query_one(DataTable), "focus returns to the list"


async def test_switching_tab_drops_a_drill_down():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        await pilot.press("enter")
        await pilot.pause(0.3)
        assert len(app.stack) == 2
        await pilot.press("v")
        await pilot.pause(0.3)
        assert len(app.stack) == 1, "a tab is an overview, not a place in a path"


async def test_esc_returns_to_the_first_tab_before_quitting():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        await pilot.press("s")
        await pilot.pause(0.3)
        assert app.query_one(Tabs).active == "stats"
        await pilot.press("escape")
        await pilot.pause(0.3)
        assert app.query_one(Tabs).active == "hosts"
        assert app.is_running


async def test_the_title_row_is_only_spent_when_there_is_a_path():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        assert app.query_one("#title").display is False, "the tab already names it"
        await pilot.press("enter")
        await pilot.pause(0.3)
        assert app.query_one("#title").display is True


async def test_no_table_chrome_is_drawn_on_a_filled_background():
    """Textual fills the DataTable header with $primary, which is raw ANSI blue
    under this theme - the same unreadable band removed from the search
    session's status bar. Nothing in the table chrome may carry a fill."""
    app = _app("basic")
    async with app.run_test(size=(120, 30)) as pilot:
        await pilot.pause(0.3)
        table = app.query_one(DataTable)
        for component in ("datatable--header", "datatable--cursor",
                          "datatable--hover", "datatable--header-hover"):
            styles = table.get_component_styles(component)
            assert styles.background.a == 0, f"{component} is drawn on a fill"


async def test_the_header_and_the_selection_are_visually_distinct():
    app = _app("basic")
    async with app.run_test(size=(120, 30)) as pilot:
        await pilot.pause(0.3)
        table = app.query_one(DataTable)
        header = table.get_component_styles("datatable--header")
        cursor = table.get_component_styles("datatable--cursor")
        assert "bold" in str(header.text_style)
        assert header.color.ansi is not None, "the header carries its own colour"
        assert "reverse" in str(cursor.text_style), "the selection inverts"


async def test_the_active_tab_is_marked_without_a_fill():
    app = _app("basic")
    async with app.run_test(size=(120, 30)) as pilot:
        await pilot.pause(0.4)
        strips = app.screen._compositor.render_strips()
        tab_row = [s for s in strips[0] if s.text.strip()]
        active = next(s for s in tab_row if s.text.strip() == "Hosts")
        inactive = next(s for s in tab_row if s.text.strip() == "Services")
        assert active.style.color != inactive.style.color, "the active tab is marked"
        assert all(seg.style.bgcolor is None or seg.style.bgcolor.name == "default"
                   for seg in tab_row), "no tab is drawn on a fill"


# --- grouping rows carry what they group ------------------------------------


async def test_export_from_a_filtered_grouping_view_follows_the_filter():
    """Exports come from what the filter left on screen, in every overview.

    Grouping rows used to carry no target, so `_visible_hosts` found neither a
    host nor a service group and fell back to every host in the scan set - a
    filtered `by service` view silently exported the whole engagement.
    """
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("b")                      # -> group by service
        await pilot.pause(0.2)
        assert app.view.kind == "grouping"
        await _type(pilot, "http")

        assert _cells(app) == ["http"], "the filter must narrow the grouping"
        exported = [r.host.address for r in app._visible_records(app._rows)]
        assert exported == ["192.0.2.1", "192.0.2.2"]
        assert len(exported) < len(app.scans.hosts), "not every host in the set"


async def test_enter_opens_a_grouping_row_into_its_hosts():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("b")
        await pilot.pause(0.2)
        await pilot.press("enter")
        await pilot.pause(0.3)

        assert len(app.stack) == 2, "Enter must drill, as it does on every other row"
        assert app.view.columns[:3] == ("Address", "Hostname", "Port")
        assert all(r.target is not None for r in app._rows)

        await pilot.press("escape")
        await pilot.pause(0.3)
        assert len(app.stack) == 1, "Esc unwinds the drill-down"


async def test_the_detail_pane_reports_a_grouping_row():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("b")
        await pilot.pause(0.3)
        shown = _render(app.query_one("#detail-body"))
        assert "grouped by service" in shown
        assert "192.0.2." in shown, "the pane names the hosts in the bucket"


async def test_the_status_line_names_included_and_excluded_ranges():
    """A negated-only filter used to render a bare `· in ` with nothing after it.

    The line was gated on `spec.networks`, which counts excludes too, but only
    ever printed `spec.include`.
    """
    app = _app("basic")
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause(0.2)
        await _type(pilot, "!192.0.2.0/28")
        status = _render(app.query_one("#status"))
        assert "not in 192.0.2.0/28" in status
        assert "·  in " not in status, "no dangling 'in' with nothing to name"


async def test_the_status_line_spells_a_union_of_ranges():
    app = _app("basic")
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause(0.2)
        await _type(pilot, "192.0.2.0/25 192.0.2.128/25")
        assert "in 192.0.2.0/25 or 192.0.2.128/25" in _render(app.query_one("#status"))


# --- work done per interaction ----------------------------------------------


async def test_a_view_is_projected_once_per_operation(monkeypatch):
    """`_column_widths` and `_reload_rows` each used to call `View.rows`.

    Every sort, tab switch and resize therefore recomputed the whole projection
    twice - for the service and grouping overviews, twice over every host.
    """
    from seek.tui.nmap import views as vdefs

    calls = []
    original = vdefs.View.rows
    monkeypatch.setattr(
        vdefs.View, "rows",
        lambda self, scans: (calls.append(self.title), original(self, scans))[1],
    )

    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.4)
        for key in ("2", "r", "v"):
            calls.clear()
            await pilot.press(key)
            await pilot.pause(0.3)
            assert len(calls) == 1, f"{key!r} projected the view {len(calls)} times"


def _count_rebuilds(monkeypatch) -> list[str]:
    from seek.tui.nmap import views as vdefs

    calls: list[str] = []
    original = vdefs.View.rows
    monkeypatch.setattr(
        vdefs.View, "rows",
        lambda self, scans: (calls.append(self.title), original(self, scans))[1],
    )
    return calls


async def test_no_rebuild_while_the_keystrokes_are_still_coming(monkeypatch):
    """Each keystroke used to re-filter, re-sort and re-add every row.

    The debounce is set long rather than the assertion being made quickly: a
    loaded machine could stretch a short wait past the default 150 ms and fail
    a test that is about behaviour, not about timing.
    """
    calls = _count_rebuilds(monkeypatch)
    app = _app("basic", config=Config(debounce_ms=3000))
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.4)
        calls.clear()
        await pilot.press("slash")
        for ch in "192.0.2":
            await pilot.press(ch)
        await pilot.pause(0.1)
        assert calls == [], "seven keystrokes, no rebuild yet"

        await pilot.press("enter")      # leaving the box flushes what is pending
        await pilot.pause(0.2)
        assert len(calls) == 1, "and exactly one rebuild for the seven of them"


async def test_the_debounce_timer_rebuilds_without_leaving_the_box(monkeypatch):
    """The other path: stop typing and the list catches up on its own."""
    calls = _count_rebuilds(monkeypatch)
    app = _app("basic")                 # the real debounce
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.4)
        calls.clear()
        await pilot.press("slash")
        for ch in "192.0.2.1":
            await pilot.press(ch)
        await pilot.pause(0.5)          # well past config.debounce_ms
        assert calls, "the timer fired without Enter"
        assert _cells(app) == ["192.0.2.1"]


async def test_leaving_the_filter_applies_a_pending_keystroke(monkeypatch):
    """Enter and Esc must not drop a filter still inside the debounce window."""
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        await pilot.press("slash")
        for ch in "192.0.2.1":
            await pilot.press(ch)
        await pilot.press("enter")          # leaves at once, before the timer
        await pilot.pause(0.05)
        assert _cells(app) == ["192.0.2.1"], "the filter was applied on the way out"


# --- digging down, and coming back ------------------------------------------


async def test_by_port_sorts_the_column_as_numbers():
    """`443/tcp` before `80/tcp` is what comparing the labels as text gives."""
    app = _app("vuln")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        for _ in range(3):                  # hosts -> service -> product -> port
            await pilot.press("b")
            await pilot.pause(0.1)
        assert app.view.title == "Grouped by port"
        assert _cells(app) == ["80/tcp", "443/tcp", "8080/tcp"], "opens on the Port column"
        await pilot.press("1")              # the sorted column again: reversed
        await pilot.pause(0.2)
        assert _cells(app) == ["8080/tcp", "443/tcp", "80/tcp"]
        await pilot.press("1")
        await pilot.pause(0.2)
        assert _cells(app) == ["80/tcp", "443/tcp", "8080/tcp"]


async def test_a_grouping_row_drills_on_into_one_hosts_record():
    """The overviews reach a single host without unwinding to the host list."""
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("b")              # by service
        await pilot.pause(0.2)
        await pilot.press("enter")          # -> the hosts in that bucket
        await pilot.pause(0.3)
        assert app.view.kind == "group-hosts"
        address = app._rows[0].cells[0]
        await pilot.press("enter")          # -> that host's full record
        await pilot.pause(0.3)
        assert app.view.kind == "host-detail"
        assert app.view.title == f"Host {address}"
        assert len(app.stack) == 3, "the path is three levels deep"


async def test_a_service_row_drills_on_into_that_service_everywhere():
    """From one host's port to every host running it - the loop closes."""
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("enter")          # 192.0.2.1 -> its services
        await pilot.pause(0.3)
        assert _cells(app) == ["22/tcp", "80/tcp", "443/tcp"]
        app.query_one(DataTable).move_cursor(row=1)      # 80/tcp nginx
        await pilot.press("enter")
        await pilot.pause(0.3)
        assert app.view.kind == "service-detail"
        assert _cells(app) == ["192.0.2.1", "192.0.2.2"], "both nginx hosts"


async def test_a_port_that_is_open_nowhere_still_opens_something():
    """443 is closed on the only host reporting it, so it is in no overview
    row - `Enter` falls back to every host that reports the port at all."""
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("enter")
        await pilot.pause(0.3)
        app.query_one(DataTable).move_cursor(row=2)      # 443/tcp, closed
        await pilot.press("enter")
        await pilot.pause(0.3)
        assert app.view.title == "Port 443/tcp"
        assert _cells(app) == ["192.0.2.1"]


async def test_a_statistics_row_opens_the_hosts_behind_the_count():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.press("s")
        await pilot.pause(0.2)
        row = next(i for i, r in enumerate(app._rows) if r.cells[0] == "http")
        app.query_one(DataTable).move_cursor(row=row)
        await pilot.press("enter")
        await pilot.pause(0.3)
        assert app.view.title == "Service http"
        assert _cells(app) == ["192.0.2.1", "192.0.2.2"]


async def test_esc_comes_back_to_the_row_that_was_opened():
    """Landing back at the top of the list loses the place you were working."""
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("1")                           # reverse the host list
        await pilot.pause(0.2)
        app.query_one(DataTable).move_cursor(row=1)
        opened = app._rows[1].cells[0]
        await pilot.press("enter")
        await pilot.pause(0.3)
        assert len(app.stack) == 2
        await pilot.press("escape")
        await pilot.pause(0.3)
        assert app._sort_desc, "the order the list was left in comes back too"
        assert app.query_one(DataTable).cursor_row == 1
        assert app._rows[1].cells[0] == opened


async def test_esc_clearing_the_filter_keeps_the_selected_row():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        await _type(pilot, "192.0.2.2")
        assert _cells(app) == ["192.0.2.2"]
        await pilot.press("escape")                      # clears the filter
        await pilot.pause(0.4)
        assert len(app._rows) == 3, "the whole list is back"
        assert app._rows[app.query_one(DataTable).cursor_row].cells[0] == "192.0.2.2"


# --- the statistics tab: sections, order, and a way into every figure --------


def _stats(app):
    """The visible statistics lines, as (label, count) with headings marked."""
    return [(r.cells[0], r.cells[1], r.heading) for r in app._rows]


async def test_the_statistics_tab_is_divided_into_headed_sections():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.press("s")
        await pilot.pause(0.2)
        headings = [label for label, _, is_heading in _stats(app) if is_heading]
        assert headings == ["Coverage", "Services", "Ports"], "in a fixed order"
        sections = [r.section for r in app._rows]
        assert sections == sorted(sections, key=["Coverage", "Services", "Ports"].index), \
            "the lines of one section never interleave with another's"


async def test_the_section_machinery_is_a_no_op_in_every_other_view():
    """Sections lead the sort key, so every unsectioned view must be untouched."""
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        assert all(not r.heading and r.section_rank == 0 for r in app._rows)
        assert _cells(app) == ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
        await pilot.press("1")                 # the sorted column again: reversed
        await pilot.pause(0.2)
        assert _cells(app) == ["192.0.2.3", "192.0.2.2", "192.0.2.1"]


async def test_every_distinct_open_port_is_a_line_of_its_own():
    """Ports used to be a comma list truncated to ten inside one detail cell."""
    app = _app("vuln")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.press("s")
        await pilot.pause(0.2)
        ports = [r.cells[0] for r in app._rows if r.section == "Ports" and not r.heading]
        assert ports == ["80/tcp", "443/tcp", "8080/tcp"], "each with its own line"
        counts = {r.cells[0]: r.cells[1] for r in app._rows if r.section == "Ports"}
        assert counts["80/tcp"] == "1", "how many hosts expose it"


async def test_the_statistics_tab_opens_ordered_by_count():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.press("s")
        await pilot.pause(0.2)
        services = [r.cells[0] for r in app._rows
                    if r.section == "Services" and not r.heading]
        assert services == ["http", "ssh"], "most occurrences first, not alphabetical"
        assert app._sort_col == 1 and app._sort_desc, "the view declares its own order"


async def test_reversing_a_sectioned_view_keeps_its_sections():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.press("s")
        await pilot.pause(0.2)
        await pilot.press("2")                 # opens on Count: again reverses it
        await pilot.pause(0.2)
        headings = [(i, label) for i, (label, _, h) in enumerate(_stats(app)) if h]
        assert [label for _, label in headings] == ["Coverage", "Services", "Ports"]
        first_of_section = {r.section: i for i, r in reversed(list(enumerate(app._rows)))}
        for section, index in first_of_section.items():
            assert app._rows[index].heading, f"{section} still opens with its heading"
        services = [r.cells[0] for r in app._rows
                    if r.section == "Services" and not r.heading]
        assert services == ["ssh", "http"], "reversing orders the lines, not the sections"


async def test_filtering_a_section_empty_drops_its_heading():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.press("s")
        await pilot.pause(0.2)
        await _type(pilot, "targets")
        labels = [r.cells[0] for r in app._rows]
        assert labels == ["Coverage", "Targets"], \
            "the sections with nothing left lose their headings too"

        await pilot.press("escape")          # clear the filter
        await pilot.pause(0.4)
        await _type(pilot, "http")
        labels = [r.cells[0] for r in app._rows]
        assert labels == ["Services", "http", "Ports", "80/tcp"], \
            "and the coverage heading goes when no figure matches"


async def test_a_filter_matching_nothing_leaves_an_empty_statistics_table():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.press("s")
        await pilot.pause(0.2)
        await _type(pilot, "zzzznothing")
        assert app._rows == [], "headings included"


async def test_the_row_count_ignores_the_headings():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.press("s")
        await pilot.pause(0.2)
        lines = sum(1 for r in app._rows if not r.heading)
        assert f"{lines} rows" in _render(app.query_one("#status"))


async def _open_stat(pilot, app, label):
    """Put the cursor on the statistics line named `label` and open it."""
    await pilot.press("s")
    await pilot.pause(0.2)
    row = next(i for i, r in enumerate(app._rows) if r.cells[0] == label)
    app.query_one(DataTable).move_cursor(row=row)
    await pilot.press("enter")
    await pilot.pause(0.3)


async def test_a_coverage_figure_opens_exactly_the_hosts_it_counts():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        await _open_stat(pilot, app, "With open ports")
        assert app.view.title == "With open ports"
        assert _cells(app) == ["192.0.2.1", "192.0.2.2"], "not the down host"
        assert app.view.columns[:2] == ("Address", "Hostname"), "the host columns"


async def test_a_total_opens_the_breakdown_behind_it():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        await _open_stat(pilot, app, "Distinct open ports")
        assert app.view.title == "Grouped by port"
        assert app.view.kind == "grouping"
        assert len(app.stack) == 2, "pushed onto the statistics view, not replacing it"


async def test_a_port_line_opens_the_hosts_exposing_it():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        await _open_stat(pilot, app, "80/tcp")
        assert app.view.title == "Port 80/tcp"
        assert _cells(app) == ["192.0.2.1", "192.0.2.2"]


async def test_a_heading_opens_nothing():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        await _open_stat(pilot, app, "Ports")
        assert len(app.stack) == 1, "a heading is not a statistic"
        assert app.view.kind == "stats"
        assert "Ports" in _render(app.query_one("#detail-body")), \
            "the pane explains the section rather than going blank"


async def test_going_back_from_a_statistic_keeps_the_line_selected():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        await _open_stat(pilot, app, "Up")
        assert app.view.title == "Up"
        await pilot.press("escape")
        await pilot.pause(0.3)
        assert app.view.kind == "stats"
        selected = app._rows[app.query_one(DataTable).cursor_row]
        assert selected.cells[0] == "Up"


async def test_clicking_a_column_heading_sorts_by_it():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        table = app.query_one(DataTable)
        table.post_message(DataTable.HeaderSelected(
            table, list(table.columns)[2], 2, label=Text("OS")))
        await pilot.pause(0.2)
        assert (app._sort_col, app._sort_desc) == (2, False)
        assert "3 OS ↑" in _render(app.query_one(DataTable)), "the marker follows"
        table.post_message(DataTable.HeaderSelected(
            table, list(table.columns)[2], 2, label=Text("OS")))
        await pilot.pause(0.2)
        assert app._sort_desc is True, "clicking the sorted heading again reverses it"
        assert "3 OS ↓" in _render(app.query_one(DataTable))


# --- the tab row follows the drill-down --------------------------------------


def _active_tab(app) -> str:
    return app.query_one(Tabs).active


async def test_opening_a_service_marks_the_services_tab():
    """Landing on another overview's subject must not leave `Hosts` marked."""
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("enter")               # 192.0.2.1 -> its services
        await pilot.pause(0.3)
        assert _active_tab(app) == "hosts", "a host's own record stays where it was"
        app.query_one(DataTable).move_cursor(row=1)
        await pilot.press("enter")               # 80/tcp -> that service everywhere
        await pilot.pause(0.3)
        assert app.view.kind == "service-detail"
        assert _active_tab(app) == "services" and app._active_tab == "services"
        assert len(app.stack) == 3, "the tab moved, the path did not collapse"
        assert "›" in _render(app.query_one("#title"))


async def test_going_back_returns_the_tab_too():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("enter")
        await pilot.pause(0.3)
        app.query_one(DataTable).move_cursor(row=1)
        await pilot.press("enter")
        await pilot.pause(0.3)
        assert _active_tab(app) == "services"
        await pilot.press("escape")
        await pilot.pause(0.3)
        assert _active_tab(app) == "hosts", "back to the tab the record belongs to"
        assert app.view.kind == "host-detail", "and only one level was unwound"


async def test_a_statistics_total_marks_the_grouping_tab():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        await _open_stat(pilot, app, "Distinct open ports")
        assert _active_tab(app) == "group-port"
        assert app.view.title == "Grouped by port"
        assert len(app.stack) == 2, "a drill-down, not a tab switch"
        await pilot.press("escape")
        await pilot.pause(0.3)
        assert _active_tab(app) == "stats" and app.view.kind == "stats"


async def test_a_statistics_port_line_marks_the_by_port_tab():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        await _open_stat(pilot, app, "80/tcp")
        assert _active_tab(app) == "group-port"
        assert _cells(app) == ["192.0.2.1", "192.0.2.2"]


async def test_a_host_opened_from_a_grouping_keeps_the_grouping_tab():
    """A host record claims no tab, so it keeps the context it was opened from."""
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("b")                   # by service
        await pilot.pause(0.2)
        await pilot.press("enter")               # the hosts in that bucket
        await pilot.pause(0.3)
        assert _active_tab(app) == "group-service"
        await pilot.press("enter")               # one host's record
        await pilot.pause(0.3)
        assert app.view.kind == "host-detail"
        assert _active_tab(app) == "group-service"


async def test_selecting_a_tab_still_replaces_the_drill_down():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("enter")
        await pilot.pause(0.3)
        assert len(app.stack) == 2
        app.query_one(Tabs).active = "services"
        await pilot.pause(0.3)
        assert len(app.stack) == 1, "a tab the user picks is not a drill-down"
        assert app.view.kind == "services"


# --- marking and exporting a selection --------------------------------------


def _marks(app):
    return [r.identity for r in app._marked.values()]


def _prompts(app):
    """The text of the modal on top - a modal covers the app, so `_render` of it
    shows what is underneath rather than the dialog."""
    return [str(w.render()) for w in app.screen.query(Label)]


def _glyphs(app):
    table = app.query_one(DataTable)
    return [str(table.get_cell_at((i, 0))) for i in range(table.row_count)]


async def test_a_mark_survives_everything_that_rebuilds_the_list():
    """Every view is rebuilt on every keystroke, so a mark cannot be a row."""
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        app.query_one(DataTable).move_cursor(row=1)
        await pilot.press("m")
        await pilot.pause(0.2)
        assert _marks(app) == [("192.0.2.2",)]

        await _type(pilot, "alpha")            # filter it off screen
        await pilot.press("1")                 # sort
        await pilot.press("enter")             # drill in
        await pilot.pause(0.3)
        await pilot.press("escape")            # and back
        await pilot.pause(0.3)
        await pilot.press("escape")            # clear the filter
        await pilot.pause(0.4)
        app.query_one(Tabs).active = "services"
        await pilot.pause(0.3)
        assert _marks(app) == [("192.0.2.2",)], "still marked, wherever we went"


async def test_one_key_marks_a_whole_bucket():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        app.query_one(Tabs).active = "services"
        await pilot.pause(0.3)
        row = next(i for i, r in enumerate(app._rows) if r.cells[0] == "80")
        app.query_one(DataTable).move_cursor(row=row)
        await pilot.press("m")
        await pilot.pause(0.2)
        assert _marks(app) == [("192.0.2.1", "tcp", 80), ("192.0.2.2", "tcp", 80)], \
            "the service across every host running it"
        assert "3 marked" not in _render(app.query_one("#status"))
        assert "2 marked" in _render(app.query_one("#status"))


async def test_marking_a_marked_row_unmarks_it():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("m")
        await pilot.pause(0.2)
        assert len(app._marked) == 1
        await pilot.press("m")
        await pilot.pause(0.2)
        assert app._marked == {}


async def test_the_marker_column_shows_whole_and_partial_marks():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("m")                 # mark 192.0.2.1 (a host record)
        await pilot.pause(0.2)
        assert _glyphs(app)[0] == "●"
        assert _glyphs(app)[1] == "", "an unmarked row carries no glyph"

        app.query_one(Tabs).active = "group-service"
        await pilot.pause(0.3)
        row = next(i for i, r in enumerate(app._rows) if r.cells[0] == "http")
        app.query_one(DataTable).move_cursor(row=row)
        await pilot.press("m")                 # both hosts of the http bucket
        await pilot.pause(0.2)
        assert _glyphs(app)[row] == "●"
        # unmark one of the two pairs, from the bucket's host list
        await pilot.press("enter")
        await pilot.pause(0.3)
        await pilot.press("m")
        await pilot.pause(0.2)
        await pilot.press("escape")
        await pilot.pause(0.3)
        assert _glyphs(app)[row] == "◐", "a partly marked bucket says so"


async def test_a_heading_marks_nothing():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.press("s")
        await pilot.pause(0.2)
        row = next(i for i, r in enumerate(app._rows) if r.heading)
        app.query_one(DataTable).move_cursor(row=row)
        await pilot.press("m")
        await pilot.pause(0.2)
        assert app._marked == {}


async def test_clearing_marks_takes_one_key():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("m")
        app.query_one(DataTable).move_cursor(row=1)
        await pilot.press("m")
        await pilot.pause(0.2)
        assert len(app._marked) == 2
        await pilot.press("M")
        await pilot.pause(0.2)
        assert app._marked == {}
        assert "marked" not in _render(app.query_one("#status"))


async def test_the_mark_column_does_not_shift_which_column_the_digits_sort():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("2")                 # Hostname
        await pilot.pause(0.2)
        assert app._sort_col == 1
        assert app.view.columns[app._sort_col] == "Hostname"


async def test_an_export_uses_the_marks_and_ignores_the_filter(monkeypatch):
    captured = {}
    monkeypatch.setattr("seek.actions.copy_to_clipboard",
                        lambda text: captured.update(text=text))
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        app.query_one(DataTable).move_cursor(row=1)
        await pilot.press("m")                 # 192.0.2.2
        await pilot.pause(0.2)
        await _type(pilot, "alpha")            # the filter says 192.0.2.1
        await pilot.press("x")
        await pilot.pause(0.3)
        assert any("1 marked record(s)" in t for t in _prompts(app))
        await _choose(pilot, app, "all-hosts")
        await _choose(pilot, app, "text")
        await _choose(pilot, app, "clipboard")
    assert captured.get("text") == "192.0.2.2", "the marks win over the view"


async def test_the_export_prompt_names_the_rows_when_nothing_is_marked():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("x")
        await pilot.pause(0.3)
        assert any("record(s) on screen" in t for t in _prompts(app))
        await pilot.press("escape")
        await pilot.pause(0.2)


async def test_a_custom_field_export_reaches_the_clipboard_as_csv(monkeypatch):
    captured = {}
    monkeypatch.setattr("seek.actions.copy_to_clipboard",
                        lambda text: captured.update(text=text))
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        app.query_one(Tabs).active = "services"
        await pilot.pause(0.3)
        await pilot.press("m")                 # the 22/tcp ssh group
        await pilot.pause(0.2)
        await pilot.press("x")
        await pilot.pause(0.3)
        await _choose(pilot, app, "custom")
        app.screen.query_one(SelectionList).deselect_all()
        for field in ("address", "port", "service"):
            app.screen.query_one(SelectionList).select(field)
        app.screen.confirm()
        await pilot.pause(0.3)
        await _choose(pilot, app, "csv")
        await _choose(pilot, app, "clipboard")
    assert captured["text"].splitlines() == ["address,port,service", "192.0.2.1,22,ssh"]


async def test_cancelling_the_export_writes_nothing(monkeypatch):
    captured = {}
    monkeypatch.setattr("seek.actions.copy_to_clipboard",
                        lambda text: captured.update(text=text))
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("x")
        await pilot.pause(0.3)
        await _choose(pilot, app, "hosts")
        await pilot.press("escape")            # cancel at the format step
        await pilot.pause(0.3)
    assert captured == {}


# --- the states a list can be in, and the keys it can show -------------------


def _empty_text(app) -> str:
    """The empty-state message itself - the widget grows and shrinks with the
    layout, so render its content rather than a fixed region of the screen."""
    from textual.widgets import Static
    return str(app.query_one("#empty", Static).render())


async def test_a_filter_matching_nothing_says_so_and_says_how_to_get_out():
    """Headers over blank space reads the same as a scan that found nothing."""
    app = _app("basic")
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.2)
        assert not app.query_one("#empty").has_class("-shown"), "not while there are rows"
        await _type(pilot, "zzzznothing")
        shown = _empty_text(app)
        assert app.query_one("#empty").has_class("-shown")
        assert 'Nothing matches "zzzznothing"' in shown
        assert "Esc clears the filter" in shown
        assert "3 row(s) without it" in shown, "and how much is behind the filter"


async def test_the_headers_stay_when_the_list_is_empty():
    """They say what would be here; the message sits directly under them."""
    app = _app("basic")
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.2)
        await _type(pilot, "zzzznothing")
        table = app.query_one(DataTable)
        assert table.show_header and table.row_count == 0
        assert table.has_class("-empty"), "the table shrinks to its headers"
        assert app.query_one("#list-area").styles.border_bottom[0] == "solid", \
            "the region is still fenced, with the message inside it"


async def test_the_empty_message_follows_the_reason(tmp_path):
    scan = tmp_path / "pn.xml"                       # asserted up, nothing found
    scan.write_text(
        '<?xml version="1.0"?>\n<nmaprun scanner="nmap" args="nmap -Pn -oX pn.xml '
        '203.0.113.9" start="1756000000" version="7.94" xmloutputversion="1.05">\n'
        '<host><status state="up" reason="user-set" reason_ttl="0"/>'
        '<address addr="203.0.113.9" addrtype="ipv4"/></host>\n</nmaprun>\n')
    app = NmapApp(prepare(load([scan])))
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("u")                       # up only
        await pilot.pause(0.3)
        assert not app._rows
        shown = _empty_text(app)
        assert "No host is up" in shown and "u lists every host" in shown


async def test_the_empty_state_clears_when_rows_come_back():
    app = _app("basic")
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.2)
        await _type(pilot, "zzzznothing")
        assert app.query_one("#empty").has_class("-shown")
        await pilot.press("escape")
        await pilot.pause(0.4)
        assert not app.query_one("#empty").has_class("-shown")
        assert not app.query_one(DataTable).has_class("-empty")


async def test_the_hint_bar_keeps_the_keys_that_matter_when_it_cannot_fit():
    """Clipping dropped whatever came last - mark, export and `?` with it."""
    app = _app("basic")
    async with app.run_test(size=(70, 24)) as pilot:
        await pilot.pause(0.3)
        shown = _render(app.query_one("#hint-bar"))
        assert "↑↓ select" in shown, "navigation stays"
        assert "? help" in shown, "and the door to everything else"
        assert "…" in shown, "and it admits that something was dropped"
        assert len(shown.rstrip()) <= 70


async def test_a_wide_terminal_shows_every_hint_without_an_ellipsis():
    app = _app("basic")
    async with app.run_test(size=(200, 24)) as pilot:
        await pilot.pause(0.3)
        shown = _render(app.query_one("#hint-bar"))
        for key in ("m mark", "x export", "? help", "^P commands"):
            assert key in shown
        assert "…" not in shown


async def test_fitting_hints_keeps_navigation_and_help_first():
    # async only because this module carries a module-wide asyncio mark; the
    # function under test is pure.
    from seek.tui.nmap.app import _fit_hints
    items = [("↑↓", "select"), ("←→", "scroll detail"), ("v", "swap"),
             ("m", "mark"), ("x", "export"), ("?", "help"), ("Esc", "back")]
    kept, dropped = _fit_hints(items, 40)
    keys = [k for k, _ in kept]
    assert keys[:2] == ["↑↓", "←→"], "the two navigation hints are never dropped"
    assert "?" in keys and "Esc" in keys
    assert dropped is True
    assert _fit_hints(items, 400) == (items, False), "everything fits when it fits"


async def test_a_modal_fits_a_short_terminal_and_says_how_to_leave():
    """Six three-line buttons needed twenty rows: the last choice was unreachable."""
    app = _app("basic")
    async with app.run_test(size=(100, 24)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("x")
        await pilot.pause(0.4)
        options = app.screen.query_one(OptionList)
        assert options.option_count >= 6, "every recipe is on the list"
        assert options.region.height <= 24
        last = options.get_option_at_index(options.option_count - 1)
        assert options.get_option_index(last.id) == options.option_count - 1, \
            "the last choice is reachable, whatever the list has grown to"
        assert any("Esc cancel" in t for t in _prompts(app))
        await pilot.press("escape")
        await pilot.pause(0.2)


async def test_a_modal_moves_with_j_and_k_like_every_other_list():
    app = _app("basic")
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("x")
        await pilot.pause(0.4)
        options = app.screen.query_one(OptionList)
        start = options.highlighted or 0
        await pilot.press("down")
        await pilot.pause(0.15)
        assert options.highlighted == start + 1
        await pilot.press("escape")
        await pilot.pause(0.2)


# --- the names a host answers to, wherever they are worth showing ------------


async def test_the_hostname_column_admits_when_more_names_are_known():
    """`—` for a host whose only name is in a certificate is the app knowing
    something and not saying it."""
    app = _app("scripts")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        assert app._rows[0].cells[1] == "scripted.example +1"


async def test_a_host_can_be_filtered_by_a_name_from_its_certificate():
    app = _app("scripts")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        await _type(pilot, "example.test")
        assert _cells(app) == ["192.0.2.10"], "found by a name no column shows first"


async def test_the_host_record_lists_every_name_and_where_it_came_from():
    app = _app("scripts")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        shown = _render(app.query_one("#detail-body"))
        assert "Names (2)" in shown
        assert "scripted.example" in shown and "resolved" in shown
        assert "example.test" in shown and "certificate on 443/tcp" in shown


async def test_a_service_record_lists_its_certificate_names_and_urls():
    app = _app("scripts")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        await pilot.press("enter")                  # into the host's services
        await pilot.pause(0.4)
        shown = _render(app.query_one("#detail-body"))
        assert "Names (1)" in shown and "example.test" in shown
        assert "certificate" in shown, "and what revealed it"
        assert "URLs (3)" in shown
        assert "https://192.0.2.10" in shown
        assert "https://example.test" in shown, "the name, not only the address"


async def test_the_names_tab_lists_every_name_with_its_source():
    app = _app("scripts", "basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        app.query_one(Tabs).active = "names"
        await pilot.pause(0.4)
        rows = {r.cells[0]: r.cells[1] for r in app._rows}
        assert rows == {"alpha.example": "resolved",
                        "example.test": "certificate",
                        "scripted.example": "resolved"}


async def test_a_name_opens_the_hosts_that_answer_to_it():
    app = _app("scripts", "basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        app.query_one(Tabs).active = "names"
        await pilot.pause(0.4)
        row = next(i for i, r in enumerate(app._rows) if r.cells[0] == "example.test")
        app.query_one(DataTable).move_cursor(row=row)
        await pilot.press("enter")
        await pilot.pause(0.4)
        assert app.view.title == "example.test"
        assert _cells(app) == ["192.0.2.10"]


async def test_the_names_tab_says_so_when_nothing_has_a_name():
    app = _app("pn-asserted")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        app.query_one(Tabs).active = "names"
        await pilot.pause(0.4)
        if not app._rows:
            shown = str(app.query_one("#empty").render())
            assert "No name is known" in shown
            assert "DNS names preset" in shown


async def test_the_names_tab_shows_every_kind_of_evidence():
    app = _app("vhosts")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        app.query_one(Tabs).active = "names"
        await pilot.pause(0.4)
        rows = {r.cells[0]: r.cells[1] for r in app._rows}
        assert rows["gamma.example"] == "resolved"
        assert rows["blog.example.test"] == "certificate"
        assert rows["api.example.test"] == "certificate transparency"
        assert rows["gamma.corp.example"] == "host identity"
        assert rows["shop.example.test"] == "certificate, redirect", "both"


async def test_a_multi_site_host_says_so_in_its_row_and_its_record():
    app = _app("vhosts")
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause(0.3)
        assert app._rows[0].cells[1] == "gamma.example +7"
        shown = _render(app.query_one("#detail-body"))
        assert "Names (8)" in shown
        assert "blog.example.test" in shown and "certificate on 443/tcp" in shown


async def test_a_web_service_lists_the_vhosts_to_try_against_it():
    app = _app("vhosts")
    async with app.run_test(size=(140, 44)) as pilot:
        await pilot.pause(0.3)
        await pilot.press("enter")                   # the host's services
        await pilot.pause(0.4)
        app.query_one(DataTable).move_cursor(row=1)  # 443/tcp
        await pilot.pause(0.3)
        shown = _render(app.query_one("#detail-body"))
        assert "https://blog.example.test" in shown
        assert "https://www.example.test" in shown


# --- several directories ----------------------------------------------------


async def test_same_named_scans_in_two_directories_are_both_listed(tmp_path):
    import shutil

    from seek.nmap.merge import Pending, discover, naming

    for name, src in (("x", "merge-a"), ("y", "merge-b")):
        (tmp_path / name).mkdir()
        shutil.copy(FIX / f"{src}.xml", tmp_path / name / "scan.xml")
    roots = [tmp_path / "x", tmp_path / "y"]
    app = NmapApp(Pending(discover(roots), naming(roots)), sources=roots,
                  config=Config(nmap_path="/nonexistent/nmap"))
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause(0.5)
        row = next(i for i, r in enumerate(app._rows) if r.cells[0] == "192.0.2.40")
        app.query_one(DataTable).move_cursor(row=row)
        await pilot.pause(0.3)
        record = _render(app.query_one("#detail-body"))
        assert "x/scan" in record and "y/scan" in record, "one entry per file"
        app.query_one(Tabs).active = "scans"
        await pilot.pause(0.5)
        labels = " ".join(" ".join(r.cells) for r in app._rows)
        assert "x/scan" in labels and "y/scan" in labels


GW_DB = Path(__file__).parent / "fixtures" / "gowitness" / "capture.sqlite3"


def _capture_in(root):
    from seek.gowitness.capture import capture_dir

    paths = capture_dir(root)
    paths.root.mkdir(parents=True)
    paths.db.write_bytes(GW_DB.read_bytes())


def _opened_on(tmp_path, *with_capture):
    from seek.nmap.models import ScanSet

    roots = []
    for name in ("x", "y"):
        (tmp_path / name).mkdir()
        roots.append(tmp_path / name)
        if name in with_capture:
            _capture_in(tmp_path / name)
    return NmapApp(ScanSet(), Config(nmap_path="/nonexistent/nmap"),
                   sources=roots, scan_dir=roots[0])


async def test_a_capture_in_the_second_directory_is_read(tmp_path):
    app = _opened_on(tmp_path, "y")
    assert len(app.shots) == 7, "read, although output goes to the first directory"
    assert [run.label for run in app.captures.runs] == ["capture · y/gowitness"]


async def test_captures_in_both_directories_are_both_listed(tmp_path):
    app = _opened_on(tmp_path, "x", "y")
    assert len(app.shots) == 7, "the same URLs, one result each"
    assert [run.label for run in app.captures.runs] == [
        "capture · x/gowitness", "capture · y/gowitness"]
    assert all(run.total == 7 for run in app.captures.runs), "each counts its own"


async def test_no_capture_anywhere_is_silent(tmp_path):
    app = _opened_on(tmp_path)
    assert len(app.shots) == 0 and app.shots.problems == []
    assert app.captures.runs == []


# --- structured queries -----------------------------------------------------


async def _filter(pilot, app, text):
    """Set the filter box as a paste would; parentheses do not survive `press`."""
    app.query_one("#filter", Input).value = text
    await pilot.pause(0.4)


async def test_open_on_the_host_list_is_the_port_state_not_the_text():
    app = _app("basic")
    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause(0.2)
        await _filter(pilot, app, "open:22")
        assert _cells(app) == ["192.0.2.1"], ".2 has 22 filtered"
        assert "where open:22" in _render(app.query_one("#status"))


async def test_a_port_list_is_filtered_port_by_port():
    app = _app("basic")
    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("enter")                      # 192.0.2.1's ports
        await pilot.pause(0.3)
        await _filter(pilot, app, "service:ssh OR open:80")
        assert [r.cells[0] for r in app._rows] == ["22/tcp", "80/tcp"]


async def test_an_unclosed_group_still_lists_rows():
    app = _app("basic")
    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause(0.2)
        await _filter(pilot, app, "service:telnet OR (open:80 product:nginx")
        assert _cells(app) == ["192.0.2.1", "192.0.2.2"]
        assert "(open:80 AND product:nginx)" in _render(app.query_one("#status"))


async def test_an_empty_field_keeps_the_list_and_says_so():
    app = _app("basic")
    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause(0.2)
        await _filter(pilot, app, "service:")
        assert len(app._rows) == 3
        assert "ignored: service:" in _render(app.query_one("#status"))


async def test_each_alternative_is_highlighted_under_or():
    app = _app("basic")
    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause(0.2)
        await _filter(pilot, app, "alpha OR nosuchthing")
        assert _cells(app) == ["192.0.2.1"]
        cell = app.query_one(DataTable).get_cell_at((0, 2))
        assert cell.plain == "alpha.example"
        styled = {pos for pos in range(len(cell.plain))
                  if any(sp.start <= pos < sp.end for sp in cell.spans)}
        assert styled and styled <= set(range(len("alpha")))
