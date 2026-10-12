"""The web interface: model indexes, API, pages, screenshots and the server.

Captures come from a copy of the gowitness fixture with some URLs pointed at the
nmap fixtures' hosts, so a capture has a host and a port to belong to.
"""

from __future__ import annotations

import asyncio
import re
import shutil
import socket
import sqlite3
import urllib.request
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from seek.gowitness import results as gw
from seek.nmap.merge import load
from seek.nmap.views import prepare
from seek.tui.nmap import views as vdefs
from seek.web import query
from seek.web import server as server_mod
from seek.web.app import create_app
from seek.web.server import WebError, WebServer, _probe, is_loopback, path_for
from seek.web.source import CachedSource, WebModel, capture_id

NMAP = Path(__file__).parent / "fixtures" / "nmap"
GOWITNESS = Path(__file__).parent / "fixtures" / "gowitness" / "capture.sqlite3"

# gowitness row id -> the URL it is made to have been captured for.
_POINTED = {6: "http://192.0.2.1", 2: "http://alpha.example",
            7: "https://192.0.2.30", 1: "http://192.0.2.30:8080"}


def _scans():
    return prepare(load([NMAP / "basic.xml", NMAP / "vuln.xml"]))


def _database(tmp_path: Path, name: str = "gowitness.sqlite3", shots: bool = True) -> Path:
    folder = tmp_path / name.rsplit(".", 1)[0]
    folder.mkdir(parents=True, exist_ok=True)
    db = folder / name
    shutil.copy(GOWITNESS, db)
    con = sqlite3.connect(db)
    for rid, url in _POINTED.items():
        con.execute("update results set url = ? where id = ?", (url, rid))
    con.commit()
    files = [r[0] for r in con.execute("select filename from results")]
    con.close()
    if shots:
        (folder / "screenshots").mkdir(exist_ok=True)
        for name_ in files:
            (folder / "screenshots" / name_).write_bytes(b"\xff\xd8\xff\xe0fake-jpeg")
    return db


def _captures(*dbs: Path) -> gw.Captures:
    shots = gw.Captures()
    for db in dbs:
        shots.add(gw.read_database(db, db.parent / "screenshots")[0])
    return shots


@pytest.fixture
def world(tmp_path):
    from seek.config import Config
    from seek.nmap.session import Session

    scans = _scans()
    session = Session(Config(nmap_path="/nonexistent/nmap"), [], tmp_path,
                      databases=[], scans=scans)
    shots = session.shots
    shots.add(_captures(_database(tmp_path)).all())
    source = CachedSource(lambda: scans, lambda: shots)
    return scans, shots, source, TestClient(create_app(source, session))


# --- the model and its indexes --------------------------------------------------


def test_captures_are_placed_on_their_host_and_port(tmp_path):
    scans = _scans()
    model = WebModel.build(scans, _captures(_database(tmp_path)).all())
    alpha = model.hosts["192.0.2.1"]
    port80 = next(s for s in alpha.services if s.port == 80)
    urls = sorted(p.capture.url for p in model.captures_of(alpha, port80))
    assert urls == ["http://192.0.2.1", "http://alpha.example"], "by address and by name"
    beta = model.hosts["192.0.2.30"]
    by_port = {s.port: [p.capture.url for p in model.captures_of(beta, s)]
               for s in beta.services}
    assert by_port == {80: [], 443: ["https://192.0.2.30"], 8080: ["http://192.0.2.30:8080"]}
    unplaced = [p for p in model.captures if p.host is None]
    assert len(unplaced) == 3, "the rest are listed, just not on a host"


def test_ids_are_stable_and_the_snapshot_is_cached(tmp_path):
    scans = _scans()
    shots = _captures(_database(tmp_path))
    source = CachedSource(lambda: scans, lambda: shots)
    first = source.snapshot()
    assert source.snapshot() is first, "nothing changed, nothing rebuilt"
    assert [p.id for p in first.captures] == [capture_id(c) for c in shots.all()]

    shots.add(gw.read_database(_database(tmp_path / "b", "other.sqlite3"))[0])
    second = source.snapshot()
    assert second is not first, "a new database rebuilds"
    assert {p.id for p in first.captures} <= {p.id for p in second.captures}


def test_a_new_scan_set_rebuilds(tmp_path):
    holder = {"scans": _scans()}
    shots = _captures(_database(tmp_path))
    source = CachedSource(lambda: holder["scans"], lambda: shots)
    first = source.snapshot()
    holder["scans"] = _scans()
    assert source.snapshot() is not first


def test_captures_from_two_databases_are_both_listed(tmp_path):
    scans = _scans()
    one, two = _database(tmp_path / "a"), _database(tmp_path / "b", "second.sqlite3")
    con = sqlite3.connect(two)
    con.execute("update results set probed_at = '2026-09-10 10:00:00+00:00'")
    con.commit()
    con.close()
    model = WebModel.build(scans, _captures(one, two).all())
    assert len(model.captures) == 14
    assert {str(p.capture.database) for p in model.captures} == {str(one), str(two)}


# --- query: the TUI's lists and grammar -----------------------------------------------


def test_a_filter_keeps_the_rows_the_tui_keeps(world):
    scans, _shots, source, _client = world
    from seek.nmap import filtering

    for q in ["", "alpha", "192.0.2.0/30", "open:443", "!ssh", "http AND NOT 8080"]:
        spec = filtering.parse_filter(q) if q else filtering.FilterSpec()
        tui = [r.target.address for r in vdefs.hosts_view().rows(scans)
               if filtering.matches(spec, r.text, r.addresses, r.records)]
        web = [h.address for h in query.hosts(source.snapshot(), q).items]
        assert sorted(web) == sorted(tui), q


def test_services_come_in_port_order(world):
    _scans_, _shots, source, _client = world
    ports = [s.port for s in query.services(source.snapshot()).items]
    assert ports == sorted(ports)


def test_pagination_reports_the_total(world):
    _scans_, _shots, source, _client = world
    page = query.captures(source.snapshot(), limit=3, offset=2)
    assert (page.total, page.offset, page.limit, len(page.items)) == (7, 2, 3, 3)


# --- the API ----------------------------------------------------------------------------


def test_the_host_list_as_json(world):
    _scans_, _shots, _source, client = world
    body = client.get("/api/v1/hosts").json()
    assert body["total"] == 4
    alpha = next(h for h in body["items"] if h["address"] == "192.0.2.1")
    assert alpha["names"] == ["alpha.example"] and alpha["up"] is True
    assert alpha["open_ports"] == ["22/tcp", "80/tcp"]
    assert alpha["captures"] == 2


def test_one_host_with_its_captures_per_port(world):
    _scans_, _shots, _source, client = world
    body = client.get("/api/v1/hosts/192.0.2.30").json()
    captured = {p["port"]: [c["url"] for c in p["captures"]] for p in body["ports"]}
    assert captured[443] == ["https://192.0.2.30"]
    assert captured[80] == []


def test_one_service_everywhere(world):
    _scans_, _shots, _source, client = world
    body = client.get("/api/v1/services/tcp/80").json()
    assert sorted(m["address"] for m in body["members"]) == \
        ["192.0.2.1", "192.0.2.2", "192.0.2.30"]


def test_a_capture_in_full(world):
    _scans_, shots, _source, client = world
    cid = capture_id(next(c for c in shots.all() if c.url == "https://192.0.2.30"))
    body = client.get(f"/api/v1/captures/{cid}").json()
    assert body["address"] == "192.0.2.30" and body["port"] == 443
    assert body["headers"], "every recorded field"
    assert body["image"] == f"/media/shot/{cid}"


@pytest.mark.parametrize("path, named", [
    ("/api/v1/hosts/198.51.100.9", "198.51.100.9"),
    ("/api/v1/services/tcp/9999", "9999/tcp"),
    ("/api/v1/captures/deadbeef0000", "deadbeef0000"),
])
def test_something_that_is_not_there_is_a_json_404(world, path, named):
    _scans_, _shots, _source, client = world
    response = client.get(path)
    assert response.status_code == 404
    assert named in response.json()["detail"]


# --- screenshots -------------------------------------------------------------------------


def test_a_screenshot_is_served_by_its_capture(world):
    _scans_, shots, _source, client = world
    cid = capture_id(shots.all()[0])
    response = client.get(f"/media/shot/{cid}")
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/jpeg"
    assert response.content.startswith(b"\xff\xd8")


@pytest.mark.parametrize("path", [
    "/media/shot/../../etc/passwd",
    "/media/shot/..%2F..%2Fetc%2Fpasswd",
    "/media/shot/%2Fetc%2Fpasswd",
    "/media/shot/" + "a" * 12,
])
def test_a_path_is_not_a_way_in(world, path):
    _scans_, _shots, _source, client = world
    response = client.get(path)
    assert response.status_code == 404
    assert b"root:" not in response.content


def test_a_deleted_screenshot_is_404_and_the_page_still_renders(world):
    _scans_, shots, _source, client = world
    capture = shots.all()[0]
    capture.shot.unlink()
    assert client.get(f"/media/shot/{capture_id(capture)}").status_code == 404
    assert client.get("/").status_code == 200


# --- pages -------------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/", "/v/hosts", "/v/hosts?path=h:192.0.2.1", "/v/services",
                                  "/v/stats", "/?q=8080&fragment=1"])
def test_every_page_renders(world, path):
    _scans_, _shots, _source, client = world
    response = client.get(path)
    assert response.status_code == 200, response.text[:300]
    assert "<" in response.text


def test_the_gallery_shows_every_capture_and_failures_say_why(world):
    _scans_, shots, _source, client = world
    shots.add_failures({"http://192.0.2.2": "net::ERR_CONNECTION_REFUSED"})
    html = client.get("/").text
    assert html.count('class="card"') == 8
    assert "ERR_CONNECTION_REFUSED" in html


def test_the_gallery_filter_narrows_on_the_server(world):
    _scans_, _shots, _source, client = world
    html = client.get("/?q='8080&fragment=1").text
    assert html.count('class="card"') == 1 and "192.0.2.30:8080" in html
    assert "<html" not in html, "a fragment is the list alone"


@pytest.mark.parametrize("old, new", [
    ("/hosts", "/v/hosts"),
    ("/hosts/192.0.2.1", "/v/hosts?path=h%3A192.0.2.1"),
    ("/services", "/v/services"),
    ("/services/tcp/443?name=http&product=Apache+httpd&version=2.4.29",
     "/v/services?path=s%3Atcp%2F443%2Fhttp%2FApache+httpd%2F2.4.29"),
])
def test_the_first_versions_pages_lead_to_the_tabs(world, old, new):
    _scans_, _shots, _source, client = world
    response = client.get(old, follow_redirects=False)
    assert response.status_code == 302 and response.headers["location"] == new


def test_a_hosts_port_list_shows_each_ports_screenshots(world):
    _scans_, _shots, _source, client = world
    html = client.get("/v/hosts?path=h:192.0.2.30").text
    row = html.split('data-step="p:192.0.2.30/tcp/443"')[1].split("</tr>")[0]
    assert 'class="thumb-row"' in row and "/media/shot/" in row
    row80 = html.split('data-step="p:192.0.2.30/tcp/80"')[1].split("</tr>")[0]
    assert "thumb-row" not in row80, "nothing captured, nothing shown"


def test_a_port_record_links_and_shows_its_capture(world):
    _scans_, shots, _source, client = world
    capture = next(c for c in shots.all() if c.url == "https://192.0.2.30")
    html = client.get("/v/hosts?path=h:192.0.2.30&sel=p:192.0.2.30/tcp/443").text
    record = html.split('id="record"')[1]
    assert f'href="/captures/{capture_id(capture)}"' in record
    assert 'class="thumb-inline"' in record
    assert record.count('class="thumb-inline"') == 1, "one capture, one picture"


def test_a_hosts_record_links_each_port(world):
    _scans_, _shots, _source, client = world
    html = client.get("/v/hosts?sel=h:192.0.2.30").text
    record = html.split('id="record"')[1]
    for port in (80, 443, 8080):
        assert f"sel=p%3A192.0.2.30%2Ftcp%2F{port}" in record, port


def test_a_capture_page_shows_everything(world):
    _scans_, shots, _source, client = world
    capture = next(c for c in shots.all() if c.url == "https://192.0.2.30")
    html = client.get(f"/captures/{capture_id(capture)}").text
    assert 'class="full"' in html and "Headers" in html
    assert capture.headers[0][0] in html


def test_a_missing_page_is_404_html(world):
    _scans_, _shots, _source, client = world
    response = client.get("/hosts/198.51.100.9")
    assert response.status_code == 404 and "<html" in response.text


def test_no_page_loads_anything_from_another_host(world):
    _scans_, shots, _source, client = world
    pages = ["/", "/hosts", "/hosts/192.0.2.30", "/services", "/services/tcp/80",
             f"/captures/{capture_id(shots.all()[0])}"]
    for path in pages:
        html = client.get(path).text
        external = re.findall(r'<(?:script|link|img)[^>]+(?:src|href)="(https?://[^"]+)"', html)
        assert external == [], (path, external)
    assert client.get("/docs").status_code == 404, "Swagger UI loads from a CDN"


def test_browsing_writes_nothing(world, tmp_path):
    _scans_, shots, _source, client = world
    before = {p: p.stat().st_mtime_ns for p in tmp_path.rglob("*") if p.is_file()}
    for path in ["/", "/hosts", "/hosts/192.0.2.1", "/services", "/services/tcp/80",
                 f"/captures/{capture_id(shots.all()[0])}", "/api/v1/captures"]:
        client.get(path)
    after = {p: p.stat().st_mtime_ns for p in tmp_path.rglob("*") if p.is_file()}
    assert after == before


# --- where `w` lands ------------------------------------------------------------------------


def test_path_for_each_kind_of_row(tmp_path):
    scans = _scans()
    model = WebModel.build(scans, _captures(_database(tmp_path)).all())
    hosts = {r.target.address: r for r in vdefs.hosts_view().rows(scans)}
    assert path_for(hosts["192.0.2.1"], model) == "/v/hosts?path=h%3A192.0.2.1"
    service = next(r for r in vdefs.services_view().rows(scans) if r.target.port == 8080)
    assert path_for(service, model).startswith("/v/services?path=s%3Atcp%2F8080%2F")
    beta = model.hosts["192.0.2.30"]
    ports = {r.target.port: r for r in vdefs.host_detail(beta).rows(scans)}
    one = model.captures_of(beta, ports[443].target)[0]
    assert path_for(ports[443], model) == f"/captures/{one.id}", "exactly one capture"
    assert path_for(ports[80], model) == ("/v/hosts?path=h%3A192.0.2.30"
                                          "&sel=p%3A192.0.2.30%2Ftcp%2F80")
    assert path_for(None, model) == "/"


# --- the server -------------------------------------------------------------------------------


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.mark.asyncio
async def test_the_server_starts_serves_and_stops(tmp_path):
    import asyncio

    scans = _scans()
    shots = _captures(_database(tmp_path))
    server = WebServer(CachedSource(lambda: scans, lambda: shots), "127.0.0.1", _free_port())
    await server.start()
    try:
        assert server.running

        def fetch() -> bytes:
            with urllib.request.urlopen(server.url + "/api/v1/hosts", timeout=5) as r:
                return r.read()

        assert b"192.0.2.1" in await asyncio.to_thread(fetch)
        await server.start()                             # a second start is a no-op
    finally:
        await server.aclose()
    assert not server.running
    # Free again, the way a restart would take it: the closed connection leaves
    # the port in TIME_WAIT, which SO_REUSEADDR - as uvicorn sets it - allows.
    with socket.socket() as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", server.port))
        sock.listen()


def test_a_non_loopback_address_is_refused():
    assert is_loopback("127.0.0.1") and is_loopback("::1") and is_loopback("localhost")
    assert not is_loopback("0.0.0.0") and not is_loopback("192.0.2.1")
    with pytest.raises(WebError, match="loopback only"):
        asyncio.run(WebServer(CachedSource(_scans, gw.Captures), "0.0.0.0",
                              _free_port()).start())


def test_a_port_in_use_moves_on_to_the_next_free_one():
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        port = busy.getsockname()[1]
        assert _probe("127.0.0.1", port) > port


def test_a_run_of_busy_ports_is_reported_with_its_setting(monkeypatch):
    monkeypatch.setattr(server_mod, "_bindable", lambda host, port: False)
    with pytest.raises(WebError, match="ports 7272-7371 are all in use.*web_port"):
        asyncio.run(WebServer(CachedSource(_scans, gw.Captures), "127.0.0.1",
                              7272).start())


# --- sorting and narrowing the gallery ------------------------------------------------------


def _urls(page) -> list[str]:
    return [c.url for c in page.items]


def test_every_sort_is_offered_and_orders_the_gallery(world):
    _scans_, shots, source, _client = world
    shots.add_failures({"http://192.0.2.2": "refused"})
    model = source.snapshot()
    for sort in query.SORTS:
        for desc in (False, True):
            assert query.captures(model, sort=sort, desc=desc).total == 8, sort


def test_sorting_by_status_keeps_failures_last_both_ways(world):
    _scans_, shots, source, _client = world
    shots.add_failures({"http://192.0.2.2": "refused"})
    model = source.snapshot()
    for desc in (False, True):
        page = query.captures(model, sort="status", desc=desc)
        statuses = [c.status for c in page.items]
        known = [x for x in statuses if x]
        assert known == sorted(known, reverse=desc)
        assert page.items[-1].failed, "a failure has no status; it goes last"


def test_sorting_by_address_and_port_is_numeric(world):
    _scans_, _shots, source, _client = world
    model = source.snapshot()
    by_address = [c.address for c in query.captures(model, sort="address").items if c.address]
    assert by_address == sorted(by_address, key=lambda a: tuple(map(int, a.split("."))))
    ports = [c.port for c in query.captures(model, sort="port").items if c.port]
    assert ports == sorted(ports)


def test_the_gallery_narrows_to_one_service(world):
    _scans_, _shots, source, _client = world
    page = query.captures(source.snapshot(), address="192.0.2.1", protocol="tcp", port=80)
    assert sorted(_urls(page)) == ["http://192.0.2.1", "http://alpha.example"]
    everywhere = query.captures(source.snapshot(), protocol="tcp", port=443)
    assert _urls(everywhere) == ["https://192.0.2.30"]


def test_a_card_offers_the_other_captures_of_its_service(world):
    """Shown each on its own (`group=every`), a card links to its siblings."""
    _scans_, _shots, _source, client = world
    html = client.get("/?sort=url&group=every").text
    assert html.count("all 2 for this service") == 2, "both captures of 192.0.2.1:80"
    link = re.search(r'href="(/\?[^"]*address=192.0.2.1[^"]*)"', html).group(1)
    narrowed = client.get(link.replace("&amp;", "&")).text
    assert narrowed.count('class="card"') == 2
    assert "back to every port" in narrowed


def test_the_next_page_keeps_the_sort_and_the_scope(world):
    _scans_, _shots, _source, client = world
    html = client.get("/?sort=status&desc=1&limit=2").text
    link = re.search(r'class="more" href="\?([^"]+)"', html).group(1).replace("&amp;", "&")
    assert "sort=status" in link and "desc=1" in link and "offset=2" in link


def test_an_unknown_sort_is_refused_by_the_api_and_ignored_by_the_page(world):
    _scans_, _shots, _source, client = world
    assert client.get("/api/v1/captures?sort=colour").status_code == 422
    assert client.get("/?sort=colour").status_code == 200
    body = client.get("/api/v1/captures?sort=status&desc=true&address=192.0.2.30").json()
    assert body["total"] == 2


def test_gallery_path_for_rows(tmp_path):
    from seek.web.server import gallery_path_for

    scans = _scans()
    hosts = {r.target.address: r for r in vdefs.hosts_view().rows(scans)}
    assert gallery_path_for(hosts["192.0.2.30"]) == "/?address=192.0.2.30"
    alpha = scans.hosts[0]
    port80 = next(r for r in vdefs.host_detail(alpha).rows(scans) if r.target.port == 80)
    assert gallery_path_for(port80) == "/?address=192.0.2.1&protocol=tcp&port=80"
    group = next(r for r in vdefs.services_view().rows(scans)
                 if r.target.port == 80 and r.target.host_count > 1)
    assert gallery_path_for(group) == "/?protocol=tcp&port=80", "one port, several hosts"


def test_no_route_on_the_loop_reads_the_model():
    """The server shares the viewer's event loop: an `async def` endpoint runs
    on it, so one that built or walked the model would freeze the viewer.
    Everything that reads the model is a plain `def` - FastAPI's threadpool."""
    import inspect

    from fastapi.routing import APIRoute

    from seek.web.deps import model

    app = create_app(CachedSource(_scans, gw.Captures))
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        uses_model = any(d.call is model for d in route.dependant.dependencies)
        if uses_model:
            assert not inspect.iscoroutinefunction(route.endpoint), route.path


def test_captures_of_one_port_are_stacked_by_default(world):
    """Two captures of 192.0.2.1:80 (by address and by name) are one card with
    a count, the other behind it - not two services."""
    _scans_, _shots, source, client = world
    html = client.get("/?sort=url").text
    stacks = re.findall(r'<div class="stack" data-key="([^"]+)"', html)
    # ... and two of sso.hektor.cc:443, a host the scans do not have.
    assert sorted(stacks) == ["s:192.0.2.1/tcp/80", "u:sso.hektor.cc:443"]
    assert re.search(r'class="stack-count"[^>]*>2<', html), "the badge says how many"
    assert "1 more of 192.0.2.1  80/tcp" in html, "and opening it shows the rest"
    assert "all 2 for this service" not in html, "the stack replaces the sibling link"
    page = query.capture_stacks(source.snapshot(), sort="url")
    assert page.captures == len(source.snapshot().captures)
    assert page.total == page.captures - sum(st.count - 1 for st in page.stacks)
    stacked = next(st for st in page.stacks if st.key == "s:192.0.2.1/tcp/80")
    assert {stacked.first.url, *(c.url for c in stacked.rest)} == {
        "http://192.0.2.1", "http://alpha.example"}


def test_every_screenshot_is_still_one_click_away(world):
    _scans_, _shots, source, client = world
    flat = client.get("/", params={"group": "every"}).text
    assert flat.count('class="card"') == len(source.snapshot().captures)
    assert 'class="stack"' not in flat


def test_the_api_serves_the_stacks(world):
    _scans_, _shots, _source, client = world
    page = client.get("/api/v1/captures/stacks", params={"sort": "url"}).json()
    counts = sorted(st["count"] for st in page["stacks"])
    assert counts[-1] == 2 and page["captures"] == sum(counts)


def test_clearing_a_filter_keeps_the_rest_of_the_position(world):
    client = world[3]
    page = client.get("/v/hosts?q=zzzzzz&sort=3&desc=1").text
    link = page.split('">clear the filter')[0].rsplit('href="', 1)[1]
    assert "sort=3" in link and "desc=1" in link, "as Esc does"
    page = client.get("/?group=every&q=zzzzzz").text
    link = page.split('">clear the filter')[0].rsplit('href="', 1)[1]
    assert "group=every" in link


def test_the_title_is_a_heading_outside_the_trail(world):
    page = world[3].get("/v/hosts").text
    trail = page.split('<nav aria-label="breadcrumb">')[1].split("</nav>")[0]
    assert "<h1" not in trail and "<h1>" in page.split('class="viewer"')[0]
