"""The browser at parity with the terminal: same rows, records, exports, marks, runs.

The comparisons run the terminal viewer headless and ask the web API the same
question about the same session, so "the same" is checked rather than assumed.
"""

from __future__ import annotations

import asyncio
import json
import re
import threading
import urllib.request
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from rich.console import Console

from seek.config import Config
from seek.nmap import export as exporter
from seek.nmap.merge import load
from seek.nmap.session import Session
from seek.nmap.views import prepare
from seek.runner import State
from seek.tui.nmap import detail as detail_pane
from seek.tui.nmap.app import NmapApp
from seek.web.app import create_app
from seek.web.server import WebServer
from seek.web.source import CachedSource

FIX = Path(__file__).parent / "fixtures" / "nmap"
PATHS = [FIX / "basic.xml", FIX / "vuln.xml", FIX / "merge-a.xml", FIX / "merge-b.xml"]


def _stub(tmp_path: Path, body: str = "echo 'Nmap 7.94'") -> Path:
    path = tmp_path / "fake-nmap"
    path.write_text(f"#!/bin/sh\n{body}\n")
    path.chmod(0o755)
    return path


def _session(tmp_path, nmap: Path | None = None) -> Session:
    return Session(Config(nmap_path=str(nmap or _stub(tmp_path))), PATHS, tmp_path,
                   databases=[], scans=prepare(load(PATHS)))


def _client(sess: Session) -> TestClient:
    return TestClient(create_app(CachedSource(lambda: sess.scans, lambda: sess.shots), sess))


def _plain(lines) -> str:
    console = Console(width=160, record=True, file=open("/dev/null", "w"))  # noqa: SIM115
    console.print(detail_pane.as_group(lines))
    return console.export_text()


# --- the same rows as the terminal ----------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("tab, q", [
    ("hosts", ""), ("hosts", "open:443"), ("hosts", "192.0.2.0/28 !ssh"),
    ("services", ""), ("services", "nginx OR apache"), ("stats", ""),
    ("group-service", ""), ("group-product", ""), ("group-port", "80"), ("names", ""),
    ("inventory", ""), ("inventory", "nmap"), ("findings", ""), ("findings", "vulners"),
])
async def test_every_overview_lists_what_the_terminal_lists(tmp_path, tab, q):
    app = NmapApp(prepare(load(PATHS)), Config(nmap_path=str(_stub(tmp_path))),
                  sources=PATHS, scan_dir=tmp_path)
    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause(0.3)
        app._activate(tab)
        await pilot.pause(0.3)
        if q:
            app._set_filter(q)
            app._reload_rows()
            await pilot.pause(0.3)
        terminal = [list(r.cells) for r in app._rows]
        web = _client(app.session).get(f"/api/v1/views/{tab}", params={"q": q}).json()
        assert [r["cells"] for r in web["rows"]] == terminal


def test_a_drill_path_resolves_and_names_its_levels(tmp_path):
    client = _client(_session(tmp_path))
    top = client.get("/api/v1/views/hosts").json()
    host = next(r for r in top["rows"] if r["cells"][0] == "192.0.2.1")
    ports = client.get("/api/v1/views/hosts", params={"path": host["step"]}).json()
    port80 = next(r for r in ports["rows"] if r["cells"][0] == "80/tcp")
    deeper = client.get("/api/v1/views/hosts",
                        params={"path": f"{host['step']}|{port80['step']}"}).json()
    assert [c["title"] for c in deeper["crumbs"]] == ["Hosts", "Host 192.0.2.1",
                                                      deeper["title"]]
    assert deeper["marked_tab"] == "services", "the tab follows the subject"
    assert deeper["crumbs"][1]["path"] == host["step"], "each crumb leads back"


def test_a_level_page_carries_its_own_state_in_links(tmp_path):
    """Back is the browser's history: each level's URL holds its filter and sort."""
    client = _client(_session(tmp_path))
    html = client.get("/v/hosts", params={"q": "192.0.2", "sort": 1, "desc": 1}).text
    link = re.search(r'href="/v/hosts\?path=(h%3A[^"]+)"', html)
    assert link, "a row links to its drill-down"
    sort_links = re.findall(r'class="sort" href="\?([^"]+)"', html)
    assert all("q=192.0.2" in s.replace("&amp;", "&") for s in sort_links)


# --- the same record --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_record_is_the_terminals_reader(tmp_path):
    app = NmapApp(prepare(load(PATHS)), Config(nmap_path=str(_stub(tmp_path))),
                  sources=PATHS, scan_dir=tmp_path)
    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause(0.3)
        client = _client(app.session)
        for tab in ("hosts", "services", "group-product", "names"):
            app._activate(tab)
            await pilot.pause(0.3)
            rows = client.get(f"/api/v1/views/{tab}").json()["rows"]
            for index, row in enumerate(app._rows[:4]):
                lines, _title = app._detail_content(row, full=True)
                web = client.get(f"/api/v1/records/{tab}",
                                 params={"step": rows[index]["step"]}).json()
                assert web["text"] == _plain(lines), (tab, row.cells)


def test_nmaps_own_text_steps_between_the_scans_of_a_subject(tmp_path):
    client = _client(_session(tmp_path))
    record = client.get("/api/v1/records/hosts", params={"step": "h:192.0.2.40"}).json()
    raw_links = re.findall(r'data-raw="([^"]+)"', record["html"])
    assert len(raw_links) == 2, "merge-a and merge-b both saw it"
    first = client.get(f"/api/v1/raw?{raw_links[0].replace('&amp;', '&')}").json()
    assert (first["position"], first["total"]) == (1, 2) and first["next"]
    second = client.get(f"/api/v1/raw?{first['next']}").json()
    assert second["position"] == 2 and second["previous"] and not second["next"]
    assert second["scan"] != first["scan"]


# --- marks and export ---------------------------------------------------------------------


def test_marks_are_the_sessions_both_ways(tmp_path):
    sess = _session(tmp_path)
    client = _client(sess)
    out = client.post("/api/v1/marks", json={"tab": "hosts", "step": "h:192.0.2.1"}).json()
    assert out["marked"] and list(sess.marks) == [r.identity for r in
                                                  exporter.records_for(sess.scans.hosts[:1])]
    host = next(h for h in sess.scans.hosts if h.address == "192.0.2.30")
    sess.toggle((exporter.Record(host),), origin="tui")
    assert client.get("/api/v1/marks").json()["count"] == 2
    view = client.get("/api/v1/views/hosts").json()
    marked = {r["cells"][0] for r in view["rows"] if r["mark"] == "all"}
    assert marked == {"192.0.2.1", "192.0.2.30"}
    client.delete("/api/v1/marks")
    assert not sess.marks


@pytest.mark.parametrize("which, fmt", [("hosts", "text"), ("urls", "csv"),
                                        ("host-ports", "json"), ("ports", "csv")])
def test_exports_are_the_terminals_text(tmp_path, which, fmt):
    sess = _session(tmp_path)
    client = _client(sess)
    for host in sess.scans.hosts[:3]:
        sess.toggle(tuple(exporter.Record(host, s) for s in host.open_services) or
                    (exporter.Record(host),))
    expected, _used = exporter.produce(list(sess.marks.values()), which, fmt)
    got = client.get("/api/v1/export", params={"which": which, "fmt": fmt}).text
    assert got == expected + "\n"


def test_with_nothing_marked_an_export_follows_the_filter(tmp_path):
    client = _client(_session(tmp_path))
    got = client.get("/api/v1/export",
                     params={"which": "all-hosts", "tab": "hosts", "q": "=192.0.2.3"}).text
    assert got.split() == ["192.0.2.3"], "`=` is that host alone"
    begins = client.get("/api/v1/export",
                        params={"which": "all-hosts", "tab": "hosts", "q": "192.0.2.3"}).text
    assert begins.split() == ["192.0.2.3", "192.0.2.30"], "a plain address is a beginning"


def test_a_change_from_another_origin_is_refused(tmp_path):
    sess = _session(tmp_path)
    client = _client(sess)
    body = {"tab": "hosts", "step": "h:192.0.2.1"}
    assert client.post("/api/v1/marks", json=body,
                       headers={"Origin": "https://evil.example"}).status_code == 403
    assert client.post("/api/v1/marks", json=body,
                       headers={"Referer": "https://evil.example/page"}).status_code == 403
    assert not sess.marks
    own = "http://testserver"
    assert client.post("/api/v1/marks", json=body, headers={"Origin": own}).status_code == 200
    assert client.get("/api/v1/marks", headers={"Origin": "https://evil.example"}
                      ).status_code == 200, "reading is not guarded"


@pytest.mark.parametrize("own", ["http://localhost:7272", "http://127.0.0.1:7272",
                                 "http://localhost:9000", "http://[::1]:7272"])
def test_a_change_from_the_address_the_page_was_opened_on_is_accepted(tmp_path, own):
    """`localhost` instead of `127.0.0.1`, or an SSH forward on another port:
    the page's origin is the address the request went to, whatever it is."""
    sess = _session(tmp_path)
    client = TestClient(create_app(CachedSource(lambda: sess.scans, lambda: sess.shots),
                                   sess), base_url=own)
    response = client.post("/api/v1/marks", json={"tab": "hosts", "step": "h:192.0.2.1"},
                           headers={"Origin": own})
    assert response.status_code == 200, response.text
    assert client.post("/api/v1/marks", json={"tab": "hosts", "step": "h:192.0.2.1"},
                       headers={"Origin": "https://evil.example"}).status_code == 403


# --- scans from the browser -----------------------------------------------------------------


def _preset(sess, root: bool = False) -> str:
    from seek.nmap import presets as presets_mod

    return next(name for name, args in sess.config.nmap_presets.items()
                if presets_mod.needs_root(args.split()) == root
                and presets_mod.PORTS_PLACEHOLDER not in args)


def test_the_review_is_what_the_terminal_would_run(tmp_path):
    sess = _session(tmp_path)
    client = _client(sess)
    name = _preset(sess)
    review = client.post("/api/v1/scans/review",
                         json={"preset": name, "targets": ["192.0.2.1"]}).json()
    command, _note, out_base = sess.draft_command(name, ["192.0.2.1"])
    assert review["command"] == command
    assert review["argv"] == sess.plan_scan(name, command, out_base).argv


def test_the_copied_commands_are_the_terminals(tmp_path):
    from seek.nmap import remote

    sess = _session(tmp_path)
    name = _preset(sess, root=True)
    review = _client(sess).post("/api/v1/scans/review",
                                json={"preset": name, "targets": ["192.0.2.1"]}).json()
    command, _note, out_base = sess.draft_command(name, ["192.0.2.1"])
    plan = sess.plan_scan(name, command, out_base)
    assert review["copy_local"] == remote.local_text(plan.argv)
    assert review["copy_remote"] == plan.copy_remote
    snippet = review["copy_remote"]
    assert snippet.startswith("sudo nmap ") and str(tmp_path) not in snippet


def test_a_capture_review_without_gowitness_copies_and_writes_nothing(tmp_path):
    from seek.gowitness.detect import Probe

    sess = _session(tmp_path)
    sess.gowitness = Probe(reason="not on PATH")
    client = _client(sess)
    review = client.post("/api/v1/captures/review", json={"tab": "hosts"})
    assert review.status_code == 200
    body = review.json()
    assert body["urls"] and body["blocked"] == "gowitness unavailable: not on PATH"
    assert body["copy_local"] is None and body["copy_remote"].startswith("mkdir -p gowitness/")
    started = client.post("/api/v1/captures/runs", json={"tab": "hosts"})
    assert started.status_code == 409 and "not on PATH" in started.json()["detail"]
    assert not (tmp_path / "gowitness").exists()


def test_a_shell_metacharacter_is_refused_by_name(tmp_path):
    client = _client(_session(tmp_path))
    sess_preset = _preset(_session(tmp_path))
    out = client.post("/api/v1/scans/review", json={
        "preset": sess_preset, "targets": ["192.0.2.1"],
        "command": "nmap -sT 192.0.2.1; rm -rf /"}).json()
    assert "';'" in out["error"]
    started = client.post("/api/v1/scans", json={
        "preset": sess_preset, "targets": ["192.0.2.1"],
        "command": "nmap -sT 192.0.2.1; rm -rf /"})
    assert started.status_code == 422


def test_a_root_preset_is_reviewed_as_needing_sudo(tmp_path, monkeypatch):
    import os

    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    sess = _session(tmp_path)
    review = _client(sess).post("/api/v1/scans/review", json={
        "preset": _preset(sess, root=True), "targets": ["192.0.2.1"]}).json()
    assert review["elevated"] and review["argv"][:2] == ["sudo", "-n"]
    assert review["privilege"]


# --- live runs: events, cancel, one per tool --------------------------------------------------


def _fetch(url: str, method: str = "GET", body: dict | None = None):
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, method=method,
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=10) as response:
        return response.status, json.loads(response.read() or b"null")


@pytest.mark.asyncio
async def test_a_browser_started_scan_streams_and_can_be_cancelled(tmp_path):
    nmap = _stub(tmp_path, 'case "$1" in --version) echo "Nmap 7.94";; '
                           '*) echo started; i=0; while [ $i -lt 100 ]; do echo "line $i"; '
                           'i=$((i+1)); sleep 0.1; done;; esac')
    sess = _session(tmp_path, nmap)
    server = WebServer(CachedSource(lambda: sess.scans, lambda: sess.shots), "127.0.0.1", 0,
                       session=sess)
    await server.start()
    seen: list[dict] = []

    def listen():
        with urllib.request.urlopen(server.url + "/api/v1/events", timeout=10) as stream:
            for raw in stream:
                line = raw.decode().strip()
                if line.startswith("data:"):
                    seen.append(json.loads(line[5:]))
                    if sum(1 for e in seen if e["type"] == "line") >= 3:
                        return

    try:
        listener = threading.Thread(target=listen, daemon=True)
        listener.start()
        await asyncio.sleep(0.3)
        status, run = await asyncio.to_thread(
            _fetch, server.url + "/api/v1/scans", "POST",
            {"preset": _preset(sess), "targets": ["192.0.2.1"]})
        assert status == 200 and run["running"]
        await asyncio.to_thread(listener.join, 10)
        assert [e["type"] for e in seen][:1] == ["run"], "started, then its lines"
        assert any(e["type"] == "line" and e["text"].startswith("line") for e in seen)

        with pytest.raises(urllib.error.HTTPError) as second:
            await asyncio.to_thread(_fetch, server.url + "/api/v1/scans", "POST",
                                    {"preset": _preset(sess), "targets": ["192.0.2.2"]})
        assert second.value.code == 409, "one scan at a time, whoever asks"

        await asyncio.to_thread(_fetch, server.url + "/api/v1/runs/nmap/cancel", "POST", {})
        for _ in range(50):
            if not sess.runner.busy():
                break
            await asyncio.sleep(0.1)
        assert sess.runner.runs[-1].state is State.CANCELLED
    finally:
        await server.aclose()


# --- keys -------------------------------------------------------------------------------------


TERMINAL_ONLY = {
    "D": "the detail pane is always shown in the browser",
    "W": "gowitness's own report server is a terminal action",
    "w": "the web interface itself",
    "K": None, "J": None,
}
_NAMES = {"slash": "/", "question_mark": "?", "escape": "Escape", "enter": "Enter",
          "up": "ArrowUp", "down": "ArrowDown", "left": "ArrowLeft", "right": "ArrowRight",
          "pageup": "PageUp", "pagedown": "PageDown", "home": "Home", "end": "End"}


def test_every_terminal_key_has_a_browser_key():
    js = (Path(__file__).parents[1] / "src/seek/web/static/js/keys.js").read_text()
    browser = set(re.findall(r'"([^"]+)"', js.split("export function")[0]))
    missing = []
    for binding in NmapApp.BINDINGS:
        for key in binding.key.split(","):
            key = key.strip()
            if key.startswith("ctrl+") or key in TERMINAL_ONLY:
                continue
            if _NAMES.get(key, key) not in browser:
                missing.append(key)
    assert missing == [], f"no browser key for {missing}"




def test_a_browser_start_carries_its_notification_choice(tmp_path, monkeypatch):
    sess = _session(tmp_path)
    sess.config.notify_url = "https://notify.example.test/default"
    started = []
    monkeypatch.setattr(sess, "start_scan", lambda run, origin="": started.append(run))
    client = _client(sess)
    name = _preset(sess)
    review = client.post("/api/v1/scans/review",
                         json={"preset": name, "targets": ["192.0.2.1"]}).json()
    assert review["notify_url"] == "https://notify.example.test/default"
    bad = client.post("/api/v1/scans", json={"preset": name, "targets": ["192.0.2.1"],
                                              "notify_url": "ftp://x/y"})
    assert bad.status_code == 422 and started == []
    ok = client.post("/api/v1/scans", json={"preset": name, "targets": ["192.0.2.1"],
                                             "notify_url": "ntfy.example.test/mine",
                                             "notify_progress": True})
    assert ok.status_code == 200, ok.text
    assert started[0].notify_url == "https://ntfy.example.test/mine"
    assert started[0].notify_progress
