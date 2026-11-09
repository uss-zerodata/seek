"""`U`: a version scan of exactly the ports the inventory has no version for."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from seek.config import Config
from seek.nmap import presets
from seek.nmap.export import Record, records_for
from seek.nmap.merge import load
from seek.nmap.session import ScanError, Session
from seek.nmap.views import prepare
from seek.web.app import create_app
from seek.web.source import CachedSource

FIX = Path(__file__).parent / "fixtures" / "nmap"
PATHS = [FIX / "inventory.xml"]
WEB, PORTAL = "198.51.100.10", "198.51.100.20"


def _stub(tmp_path: Path) -> Path:
    path = tmp_path / "fake-nmap"
    path.write_text("#!/bin/sh\necho 'Nmap 7.94'\n")
    path.chmod(0o755)
    return path


def _session(tmp_path, nmap: str | None = None, paths=PATHS) -> Session:
    return Session(Config(nmap_path=nmap or str(_stub(tmp_path))), list(paths), tmp_path,
                   databases=[], scans=prepare(load(list(paths))))


def _host(sess, address):
    return next(h for h in sess.scans.hosts if h.address == address)


def test_the_gaps_are_the_open_ports_nothing_versioned(tmp_path):
    sess = _session(tmp_path)
    gaps = sess.version_gaps(records_for(sess.scans.hosts))
    assert {a: [(s.port, s.protocol) for s in ss] for a, ss in gaps.items()} == {
        WEB: [(25, "tcp"), (3128, "tcp")],
        PORTAL: [(80, "tcp"), (161, "udp")],
    }


def test_one_scan_over_the_union_with_its_cost_stated(tmp_path):
    sess = _session(tmp_path)
    command, note, out_base, targets = sess.draft_version_gaps(
        records_for(sess.scans.hosts))
    assert targets == [WEB, PORTAL]
    assert "-sV --version-all" in command
    assert "-pT:25,80,3128,U:161" in command
    assert command.endswith(f"-sU -sS {WEB} {PORTAL}"), "UDP ports need a UDP scan"
    assert "4 unversioned port(s) on 2 host(s)" in note
    assert "adds 4 host/port pair(s)" in note
    assert out_base.name.startswith("nmap_03")


def test_scan_only_what_is_missing(tmp_path):
    """The spec's example: A has 22 versioned and 8080 not, B has 443 not."""
    sess = _session(tmp_path)
    web = _host(sess, WEB)
    portal = _host(sess, PORTAL)
    picked = [Record(web, s) for s in web.services if s.port in (22, 3128)]
    picked += [Record(portal, s) for s in portal.services if s.port == 80]
    command, note, _out, targets = sess.draft_version_gaps(picked)
    assert targets == [WEB, PORTAL]
    assert "-p80,3128 " in command and "-sU" not in command
    assert "22" not in command.split("-p", 1)[1].split()[0], "the versioned port is left out"
    assert "adds 2 host/port pair(s)" in note


def test_the_draft_is_an_ordinary_reviewed_command(tmp_path):
    sess = _session(tmp_path)
    command, _note, out_base, targets = sess.draft_version_gaps(
        records_for(sess.scans.hosts))
    plan = sess.plan_scan(presets.VERSION_GAPS_PRESET, command, targets, out_base)
    assert plan.targets == targets
    assert "--version-all" in plan.argv
    assert plan.elevated == (__import__("os").geteuid() != 0), "-sU/-sS need root"


def test_nothing_to_do(tmp_path):
    sess = _session(tmp_path)
    web = _host(sess, WEB)
    versioned = [Record(web, s) for s in web.services if s.port in (22, 80)]
    with pytest.raises(ScanError, match="already has a version"):
        sess.draft_version_gaps(versioned)


def test_unavailable_nmap_blocks_the_start_not_the_plan(tmp_path):
    sess = _session(tmp_path, nmap="/nonexistent/nmap")
    command, _note, out_base, targets = sess.draft_version_gaps(
        records_for(sess.scans.hosts))
    plan = sess.plan_scan(presets.VERSION_GAPS_PRESET, command, targets, out_base)
    assert plan.blocked and plan.blocked.startswith("cannot scan")
    assert plan.copy_local is None, "nothing here to run it"
    assert plan.copy_remote.startswith("sudo nmap ") and str(tmp_path) not in plan.copy_remote


def test_the_result_joins_the_inventory(tmp_path):
    """A finished scan is folded in by re-reading; its versions fill the gap."""
    later = tmp_path / "versions.xml"
    later.write_text("""<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV" start="1757000500" version="7.94">
<host><status state="up" reason="syn-ack"/><address addr="198.51.100.10" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="25"><state state="open" reason="syn-ack"/>
<service name="smtp" product="Postfix smtpd" version="3.6.4" method="probed" conf="10">
<cpe>cpe:/a:postfix:postfix:3.6.4</cpe></service></port></ports></host>
</nmaprun>""")
    sess = _session(tmp_path)
    assert not sess.inventory().service_versioned(
        _host(sess, WEB), next(s for s in _host(sess, WEB).services if s.port == 25))
    sess.publish(prepare(load([*PATHS, later])))
    web = _host(sess, WEB)
    comps = sess.inventory().of_service(web, next(s for s in web.services if s.port == 25))
    assert [(c.product, c.version) for c in comps] == [("Postfix", "3.6.4")]
    gaps = sess.version_gaps(records_for(sess.scans.hosts))
    assert [s.port for s in gaps[WEB]] == [3128]


def test_the_browser_drafts_the_same_command(tmp_path):
    sess = _session(tmp_path)
    client = TestClient(create_app(CachedSource(lambda: sess.scans, lambda: sess.shots),
                                   sess))
    out = client.post("/api/v1/scans/gaps", json={"tab": "hosts"}).json()
    command, note, _out, targets = sess.draft_version_gaps(records_for(sess.scans.hosts))
    assert (out["command"], out["note"], out["targets"]) == (command, note, targets)
    assert out["error"] == "" and "--version-all" in out["argv"]
    review = client.post("/api/v1/scans/review", json={
        "preset": out["preset"], "targets": out["targets"], "command": out["command"]}).json()
    assert review["argv"] == out["argv"]


def test_the_browser_is_told_when_there_is_nothing_to_do(tmp_path):
    sess = _session(tmp_path, nmap="/nonexistent/nmap")
    client = TestClient(create_app(CachedSource(lambda: sess.scans, lambda: sess.shots),
                                   sess))
    response = client.post("/api/v1/scans/gaps", json={"tab": "hosts"})
    body = response.json()
    assert response.status_code == 200, "a plan without nmap can still be copied"
    assert body["blocked"].startswith("cannot scan") and body["copy_local"] is None
    assert body["copy_remote"].startswith("sudo nmap ")
    started = client.post("/api/v1/scans", json={"preset": body["preset"],
                                                  "targets": body["targets"],
                                                  "command": body["command"]})
    assert started.status_code == 409 and "cannot scan" in started.json()["detail"]


@pytest.mark.asyncio
async def test_u_opens_the_command_for_review(tmp_path):
    from textual.widgets import TextArea

    from seek.tui.nmap.app import NmapApp

    app = NmapApp(prepare(load(PATHS)), Config(nmap_path=str(_stub(tmp_path))),
                  sources=PATHS, scan_dir=tmp_path)
    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause(0.3)
        await pilot.press("U")
        await pilot.pause(0.5)
        assert type(app.screen).__name__ == "CommandScreen"
        shown = " ".join(w.text for w in app.screen.query(TextArea))
        assert "--version-all" in shown and "T:25,80,3128,U:161" in shown
        await pilot.press("escape")
        await pilot.pause(0.3)
        assert len(app.screen_stack) == 1
        assert not app.runner.runs, "nothing ran"
