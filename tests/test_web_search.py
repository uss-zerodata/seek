"""Searching: the header search, the lists' filters, and saying what was understood."""

from __future__ import annotations

import pytest
from test_web import world  # noqa: F401 - the fixture

from seek.nmap import filtering


class _Row:
    def __init__(self, text, heading=False):
        self.text, self.heading = text, heading


def test_rows_containing_the_words_win_over_scattered_letters():
    spec = filtering.parse_filter("synology")
    rows = [_Row("nas-box Synology NAS"), _Row("s y n o l o g y scattered")]
    assert all(filtering.matches(spec, r.text) for r in rows), "both match fuzzily"
    kept, loose = filtering.prefer_firm(spec, rows, lambda r: r.text)
    assert [r.text for r in kept] == ["nas-box Synology NAS"] and loose == 1


def test_with_no_firm_match_the_fuzzy_rows_stand():
    spec = filtering.parse_filter("snlgy")
    rows = [_Row("synology")]
    assert filtering.prefer_firm(spec, rows, lambda r: r.text) == (rows, 0)


def test_a_tilde_lists_the_loose_matches_too():
    spec = filtering.parse_filter("synology ~")
    assert spec.loose and "looser matches included (~)" in filtering.explain(spec)
    rows = [_Row("Synology"), _Row("s y n o l o g y")]
    assert filtering.prefer_firm(spec, rows, lambda r: r.text) == (rows, 0)


def test_a_host_is_found_by_what_its_screenshot_says(world):  # noqa: F811
    """Nothing in the scan names Hektor; the captured page's title does."""
    _scans, shots, _source, client = world
    title = next(c.title for c in shots.all() if c.url == "http://192.0.2.1")
    word = title.split()[-1].strip(".").lower()
    body = client.get("/api/v1/views/hosts", params={"q": word}).json()
    assert "192.0.2.1" in [r["cells"][0] for r in body["rows"]]


def test_the_header_search_groups_what_it_finds(world):  # noqa: F811
    _scans, _shots, _source, client = world
    body = client.get("/api/v1/search", params={"q": ":443"}).json()
    groups = {g["kind"]: g for g in body["groups"]}
    assert body["understood"] == ["port 443 (any state)"]
    hosts = [h["title"] for h in groups["hosts"]["hits"]]
    assert hosts == ["192.0.2.1", "192.0.2.30"], "every host with a port 443, any state"
    assert groups["hosts"]["more"] == "/v/hosts?q=%3A443"
    assert groups["hosts"]["hits"][1]["href"] == "/v/hosts?path=h%3A192.0.2.30"
    assert "screenshots" in groups


def test_an_address_beginning_lists_the_exact_host_first(world):  # noqa: F811
    _scans, _shots, _source, client = world
    body = client.get("/api/v1/search", params={"q": "192.0.2.3"}).json()
    hosts = next(g for g in body["groups"] if g["kind"] == "hosts")
    assert [h["title"] for h in hosts["hits"]] == ["192.0.2.3", "192.0.2.30"]


def test_nothing_found_says_so_and_offers_help(world):  # noqa: F811
    _scans, _shots, _source, client = world
    html = client.get("/search", params={"q": "zzqqnothing"}).text
    assert "Nothing matches" in html and "syntax-help" in html


@pytest.mark.parametrize("path", ["/search?q=nginx", "/search?q=nginx&fragment=1",
                                  "/search", "/v/hosts?q=:80"])
def test_search_pages_render(world, path):  # noqa: F811
    _scans, _shots, _source, client = world
    assert client.get(path).status_code == 200


def test_a_list_says_what_its_filter_was_read_as(world):  # noqa: F811
    _scans, _shots, _source, client = world
    html = client.get("/v/hosts", params={"q": "10.10.10.10:8080"}).text
    assert "Showing rows with: host 10.10.10.10 · port 8080 (any state)" in html
    body = client.get("/api/v1/views/hosts", params={"q": "open: nginx"}).json()
    assert "ignored while incomplete: open:" in body["understood"]


def test_every_search_box_offers_the_syntax(world):  # noqa: F811
    _scans, _shots, _source, client = world
    for path, boxes in (("/v/hosts", 2), ("/", 2), ("/search?q=x", 1)):
        html = client.get(path).text
        assert 'id="syntax"' in html, path
        assert html.count('class="syntax-help"') >= boxes, "one `?` per search box"
