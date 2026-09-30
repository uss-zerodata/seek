"""One shape, four producers, and the contract the renderer relies on.

Reading files, building the scan history and projecting an overview are
different jobs, but the interface draws all of them with one bar. That only
works if each of them reports the same way: the figure never goes backwards,
the last report says the work is finished, and every report names what it
counted - so the bar can say "of 24 200 hosts" without the renderer knowing
which step it is drawing for.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from seek.nmap import timeline
from seek.nmap import views as proj
from seek.nmap.merge import discover, read
from seek.nmap.models import Host, ScanSet, ScriptResult, Service
from seek.nmap.progress import FILES, HOSTS, SCANS
from seek.tui.nmap import detail as detail_pane
from seek.tui.nmap import views as vdefs

FIX = Path(__file__).parent / "fixtures" / "nmap"


def _reports(run) -> list[tuple[int, int, str]]:
    seen: list[tuple[int, int, str]] = []
    run(lambda done, total, unit: seen.append((done, total, unit)))
    return seen


def _model(hosts: int) -> ScanSet:
    return ScanSet(
        hosts=[Host(address=f"10.0.{i // 254}.{i % 254}", reason="echo-reply",
                    services=[Service(protocol="tcp", port=80, state="open",
                                      name="http", product="nginx")])
               for i in range(hosts)],
        sources=["one.xml"],
    )


def _render(renderable) -> list[str]:
    """The record as the lines a terminal would be given."""
    from rich.console import Console

    if isinstance(renderable, list):
        # A record is a list of lines; what a terminal is given is the lines
        # joined, not the list's repr - which grows with every field a line
        # carries and says nothing about the record's size.
        renderable = detail_pane.as_group(renderable)
    console = Console(width=100, no_color=True)
    with console.capture() as captured:
        console.print(renderable)
    return captured.get().splitlines()


def _assert_contract(seen: list[tuple[int, int, str]], unit: str) -> None:
    assert seen, "a step that can count itself has to report"
    assert {u for _, _, u in seen} == {unit}, f"every report names {unit}"
    done = [d for d, _, _ in seen]
    assert done == sorted(done), f"the figure went backwards: {done}"
    last_done, last_total, _ = seen[-1]
    assert last_done == last_total, "the last report has to say the work is done"
    assert all(d <= t for d, t, _ in seen), "and never claim more done than there is"


def test_reading_files_reports_files(tmp_path):
    for name in ("basic", "discovery", "scripts"):
        shutil.copy(FIX / f"{name}.xml", tmp_path / f"{name}.xml")
    paths = discover([tmp_path])
    _assert_contract(_reports(lambda r: read(paths, r)), FILES)


def test_the_scan_history_reports_scans(tmp_path):
    for name in ("basic", "discovery"):
        shutil.copy(FIX / f"{name}.xml", tmp_path / f"{name}.xml")
    files = read(discover([tmp_path])).files
    _assert_contract(_reports(lambda r: timeline.build(files, r)), SCANS)


def test_every_overview_reports_hosts():
    """Not only the Scans tab: each tab that walks the model counts it.

    The set is deliberately bigger than one reporting interval, so a producer
    that only reported its endpoints would be visibly different from one that
    reports as it goes.
    """
    scans = _model(1200)
    for view in (vdefs.hosts_view(), vdefs.services_view(),
                 vdefs.statistics_view(), vdefs.names_view(),
                 vdefs.grouping_view("service"), vdefs.grouping_view("product"),
                 vdefs.grouping_view("port")):
        assert view.reports, f"{view.title} does not take a report"
        seen = _reports(lambda r, view=view: view.rows(scans, r))
        _assert_contract(seen, HOSTS)
        assert len(seen) > 2, \
            f"{view.title} reported only its endpoints over 1200 hosts"
        assert seen[-1][1] == len(scans.hosts), \
            f"{view.title} counted something other than the hosts it walked"


def test_a_view_without_a_report_is_left_alone():
    """The default is the one-argument builder every drill-down still uses."""
    view = vdefs.host_list("Picked", _model(3).hosts)
    assert not view.reports
    assert len(view.rows(_model(3), lambda *a: None)) == 3, \
        "a report offered to a view that does not take one is simply not passed"


# --- what the interface must not do on the event loop ------------------------
# Three costs that are invisible at fixture size and seconds long at engagement
# scale. Each was found by driving the viewer over 24 200 hosts
# (`benchmarks/drive_nmap.py`), and each is asserted here on a model small
# enough to keep the suite fast but large enough that the old behaviour would
# be obvious.


def test_the_model_does_not_repr_its_contents():
    """Textual describes a worker by `repr`-ing its arguments.

    So handing the model to a thread worker used to walk every host, every
    service and every script result - 2.8 s on the event loop for a string
    nobody reads.
    """
    scans = _model(4000)
    text = repr(scans)
    assert "4000 host(s)" in text
    assert len(text) < 200, "a summary, not the contents"
    assert "Host(" not in text and "Service(" not in text


def test_a_buckets_record_is_bounded():
    """A record pane is a dozen rows; a bucket can hold twenty-four thousand.

    Building a line per member is a second of the event loop for one movement
    of the cursor, and `Enter` already opens the bucket as a table.
    """
    scans = _model(3000)
    group = vdefs.Grouping(
        key="service", label="https",
        members=[(h, h.services[0]) for h in scans.hosts])
    lines = _render(detail_pane.grouping_detail(group))
    assert len(lines) < 200, f"{len(lines)} lines for a 3000-host bucket"
    assert "and 2900 more" in "\n".join(lines), "and it says how many it left out"
    assert "3000" in "\n".join(lines), "while still reporting the real count"


def test_a_service_groups_scripts_are_bounded_too():
    """One `ssl-cert` per host is fifteen thousand lines across a group."""
    scans = _model(3000)
    for host in scans.hosts:
        host.services[0].scripts = [ScriptResult(id="ssl-cert", output="a\nb\nc")]
    group = proj.ServiceGroup(protocol="tcp", port=443, name="https",
                              members=[(h, h.services[0]) for h in scans.hosts])
    lines = _render(detail_pane.group_detail(group))
    assert len(lines) < 300, f"{len(lines)} lines for a 3000-host service group"
    assert "3000" in "\n".join(lines), "the counts are still the real ones"
