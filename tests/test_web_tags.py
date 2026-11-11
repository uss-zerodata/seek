"""`/api/v1/tags`: the session's tags in the browser, tagging, definitions, the builder."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from seek.config import Config
from seek.nmap.merge import load
from seek.nmap.session import Session
from seek.nmap.views import prepare
from seek.web.app import create_app
from seek.web.source import CachedSource

FIX = Path(__file__).parent / "fixtures" / "nmap"
RULES = ("tags:\n  web-only:\n    issues: [{title: Exposed, severity: medium}]\n"
         "    rules: [{when: [{port: 80}, {not: {port: 22/tcp}}]}]\n")


def _client(tmp_path, rules: str | None = RULES):
    eng = tmp_path / "eng"
    eng.mkdir()
    scan = eng / "basic.xml"
    scan.write_bytes((FIX / "basic.xml").read_bytes())
    if rules:
        (eng / "seek-rules.yaml").write_text(rules)
    sess = Session(Config(nmap_path="/nonexistent/nmap"), [eng], eng, databases=[],
                   scans=prepare(load([scan])))
    client = TestClient(create_app(CachedSource(lambda: sess.scans, lambda: sess.shots), sess))
    return client, sess, eng


def _row(address: str) -> dict:
    return {"tab": "hosts", "path": "", "step": f"h:{address}"}


def test_the_tag_list_is_the_session_s(tmp_path):
    client, _sess, eng = _client(tmp_path)
    out = client.get("/api/v1/tags").json()
    (tag,) = out["tags"]
    assert tag["name"] == "web-only" and tag["hosts"] == 1
    assert tag["issues"][0]["severity"] == "medium"
    assert out["files"] == [str(eng / "seek-rules.yaml")] and out["problems"] == []


def test_tagging_rows_from_the_browser_saves_in_the_project(tmp_path):
    client, sess, eng = _client(tmp_path)
    r = client.post("/api/v1/tags/entries",
                    json={"tag": "explored", "rows": [_row("192.0.2.1"), _row("192.0.2.3")]})
    assert r.status_code == 200 and r.json()["saved"] == [str(eng / "seek-tags.yaml")]
    assert {"192.0.2.1", "192.0.2.3"} <= {a for a, per in sess.tags().hosts.items()
                                          if "explored" in per}
    view = client.get("/api/v1/views/hosts").json()
    cells = {row["cells"][0]: row["cells"][-1] for row in view["rows"]}
    assert cells["192.0.2.1"] == "explored", "the Tags column, as in the terminal"


def test_without_rows_the_marks_are_tagged(tmp_path):
    client, _sess, _eng = _client(tmp_path)
    client.post("/api/v1/marks", json=_row("192.0.2.2"))
    client.post("/api/v1/tags/entries", json={"tag": "high-value"})
    tagged = client.get("/api/v1/views/hosts", params={"q": "tag:high-value"}).json()
    assert [row["cells"][0] for row in tagged["rows"]] == ["192.0.2.2"]


def test_another_site_cannot_tag(tmp_path):
    client, _sess, eng = _client(tmp_path)
    r = client.post("/api/v1/tags/entries", json={"tag": "x", "rows": [_row("192.0.2.1")]},
                    headers={"Origin": "http://evil.example"})
    assert r.status_code == 403 and not (eng / "seek-tags.yaml").exists()


def test_bad_input_is_a_422_and_writes_nothing(tmp_path):
    client, _sess, eng = _client(tmp_path)
    assert client.post("/api/v1/tags/entries",
                       json={"tag": "my tag", "rows": [_row("192.0.2.1")]}).status_code == 422
    r = client.put("/api/v1/tags/x", json={"issues": [{"title": "t", "severity": "severe"}]})
    assert r.status_code == 422 and "severe" in r.json()["detail"]
    assert client.post("/api/v1/tags/entries",
                       json={"tag": "x", "rows": [_row("203.0.113.1")]}).status_code == 404
    assert not (eng / "seek-tags.yaml").exists()


def test_a_definition_set_in_the_browser_reaches_every_record(tmp_path):
    client, _sess, _eng = _client(tmp_path)
    r = client.put("/api/v1/tags/web-only",
                   json={"description": "Only a web page",
                         "issues": [{"title": "Default credentials", "severity": "high"}]})
    assert r.status_code == 200 and r.json()["summary"]
    record = client.get("/api/v1/records/hosts", params={"step": "h:192.0.2.2"}).json()
    assert "Default credentials" in record["text"]


def test_a_global_copy_carries_no_address(tmp_path, monkeypatch):
    config = tmp_path / "config"
    monkeypatch.setattr(Session, "_config_dir", lambda self: config)
    client, _sess, _eng = _client(tmp_path)
    client.post("/api/v1/tags/entries", json={"tag": "web-only", "rows": [_row("192.0.2.1")]})
    assert client.post("/api/v1/tags/web-only/global").status_code == 200
    text = (config / "tags.yaml").read_text()
    assert "Exposed" in text and "192.0.2" not in text


def test_reload_reads_a_new_file(tmp_path):
    client, _sess, eng = _client(tmp_path, rules=None)
    assert client.get("/api/v1/tags").json()["tags"] == []
    (eng / "sub").mkdir()
    (eng / "sub" / "seek-rules.yaml").write_text(
        "tags:\n  ssh:\n    rules: [{when: [{port: 22}]}]\n")
    out = client.post("/api/v1/tags/reload").json()
    assert [t["name"] for t in out["tags"]] == ["ssh"]


def test_the_builder_proposes_previews_and_saves_like_the_terminal(tmp_path):
    client, sess, eng = _client(tmp_path, rules=None)
    rows = [_row("192.0.2.2")]
    shared = client.post("/api/v1/tags/builder", json={"rows": rows}).json()
    open80 = next(p for p in shared["facts"] if p["fact"]["label"] == "80/tcp open")
    assert (open80["selected"], open80["others"]) == (1, 1)
    ex = client.post("/api/v1/tags/builder/exclusions",
                     json={"rows": rows, "positive": [open80["fact"]]}).json()
    assert ex["unwanted"] == 1
    ssh = next(p for p in ex["single"] if p["fact"]["label"] == "22/tcp open")
    body = {"rows": rows, "positive": [open80["fact"]], "negative": [ssh["fact"]]}
    shown = client.post("/api/v1/tags/builder/preview", json=body).json()
    assert shown["matched"] == ["192.0.2.2"] and shown["selected"] == 1
    saved = client.post("/api/v1/tags/web-only/rules", json=body)
    assert saved.status_code == 200 and "web-only" in (eng / "seek-tags.yaml").read_text()
    assert set(sess.tags().hosts) == {"192.0.2.2"}


def test_a_tag_made_in_the_browser_is_announced_to_the_terminal(tmp_path):
    client, sess, _eng = _client(tmp_path)
    seen = []
    sess.listen(seen.append)
    client.post("/api/v1/tags/entries", json={"tag": "explored", "rows": [_row("192.0.2.1")]})
    assert [(e.type, e.origin) for e in seen] == [("tags", "web")]
