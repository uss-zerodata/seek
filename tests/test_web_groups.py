"""The gallery, grouped: by host, service, page title, and by what the page looks like."""

from __future__ import annotations

import re
import sqlite3

import pytest
from test_web import _captures, _database, world  # noqa: F401 - the fixture

from seek.web import query
from seek.web.source import WebModel


def _groups(client, by, **params):
    return client.get("/api/v1/captures/groups", params={"by": by, **params}).json()


def test_by_host(world):  # noqa: F811
    _scans, _shots, _source, client = world
    body = _groups(client, "host")
    assert body["captures"] == 7
    placed = {g["label"].split(" · ")[0]: g["count"] for g in body["groups"]
              if "not in the scans" not in g["label"]}
    assert placed == {"192.0.2.1": 2, "192.0.2.30": 2}
    assert [g["label"] for g in body["groups"][:2]] == ["192.0.2.1 · alpha.example",
                                                        "192.0.2.30"], "address order"


def test_by_service(world):  # noqa: F811
    _scans, _shots, _source, client = world
    labels = [g["label"] for g in _groups(client, "service")["groups"]]
    assert labels[0].startswith("192.0.2.1  80/tcp")
    assert any(label.startswith("192.0.2.30  8080/tcp") for label in labels)


def test_by_title_largest_first_and_untitled_after(world):  # noqa: F811
    _scans, _shots, _source, client = world
    groups = _groups(client, "title")["groups"]
    counts = {g["label"]: g["count"] for g in groups}
    assert counts["Home - Hektor.cc"] == 2 and counts["sso.hektor.cc"] == 2
    assert groups[-1]["label"] == "(no title)" and groups[-1]["count"] == 2


def test_by_look_alike_uses_gowitness_s_perception_groups(world):  # noqa: F811
    _scans, _shots, _source, client = world
    groups = _groups(client, "similar")["groups"]
    assert sorted(g["count"] for g in groups) == [1, 2, 2, 2]
    assert "untitled pages · 404" in [g["label"] for g in groups], "named by what it is"
    assert "looks like: Home - Hektor.cc" in [g["label"] for g in groups]


def test_look_alike_groups_of_two_databases_are_not_merged(tmp_path):
    """gowitness numbers its groups per database: group 3 here is not group 3 there."""
    from test_web import _scans

    one = _database(tmp_path / "a")
    two = _database(tmp_path / "b", "other.sqlite3")
    con = sqlite3.connect(two)
    con.execute("update results set probed_at = '2026-09-10 10:00:00+00:00'")
    con.commit()
    con.close()
    model = WebModel.build(_scans(), _captures(one, two).all())
    page = query.capture_groups(model, "similar")
    assert page.total == 8 and all(g.count <= 2 for g in page.groups)


@pytest.mark.parametrize("by", ["host", "service", "title", "similar"])
def test_a_groups_link_lists_exactly_its_members(world, by):  # noqa: F811
    _scans, _shots, _source, client = world
    for group in _groups(client, by)["groups"]:
        html = client.get("/?" + group["more"]).text
        assert html.count('class="card"') == group["count"], (by, group["label"])


def test_the_grouped_gallery_switches_and_keeps_the_filter(world):  # noqa: F811
    _scans, _shots, _source, client = world
    html = client.get("/", params={"group": "title", "q": "hektor"}).text
    # Titles that say Hektor, and pages whose URL does - the filter reads both.
    labels = re.findall(r'class="group-label">([^<]+)<', html)
    assert {"Home - Hektor.cc", "sso.hektor.cc"} <= set(labels)
    assert html.count('class="card"') == 7, "every hektor capture, grouped"
    switch = dict(re.findall(r'<a href="/\?([^"]+)"[^>]*data-group="(\w+)"', html))
    assert set(switch.values()) == {"host", "service", "title", "similar"}
    for query_ in switch:
        assert "q=hektor" in query_.replace("&amp;", "&"), "the filter survives a switch"
    assert 'name="group" value="title"' in html, "and the filter keeps the grouping"


def test_an_unknown_grouping(world):  # noqa: F811
    _scans, _shots, _source, client = world
    assert client.get("/api/v1/captures/groups", params={"by": "colour"}).status_code == 422
    assert client.get("/", params={"group": "colour"}).status_code == 200
