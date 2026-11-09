"""The builder over HTTP: the terminal's model, with the state sent back."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from seek.config import Config
from seek.nmap import builder as model
from seek.nmap.merge import load
from seek.nmap.session import Session
from seek.nmap.views import prepare
from seek.web.app import create_app
from seek.web.source import CachedSource

FIX = Path(__file__).parent / "fixtures" / "nmap"
TARGETS = "192.0.2.10,192.0.2.11"


def _client(tmp_path):
    paths = [FIX / "timing.xml"]
    sess = Session(Config(nmap_path="/nonexistent/nmap"), paths, tmp_path, databases=[],
                   scans=prepare(load(paths)))
    return sess, TestClient(create_app(CachedSource(lambda: sess.scans, lambda: sess.shots),
                                       sess))


def _step(client, state="", **params):
    response = client.get("/api/v1/builder", params={"targets": TARGETS, "state": state,
                                                     **params})
    assert response.status_code == 200, response.text
    return response.json()


def test_the_same_answers_give_the_terminals_commands(tmp_path):
    sess, client = _client(tmp_path)
    out = _step(client)
    assert out["step"] == "goal" and len(out["steps"]) == 8
    assert [c["recommended"] for c in out["choices"]].count(True) == 1
    for choice in ("services", "tcp", "known", "pn", "no", "scans"):
        out = _step(client, out["state"], action="choose", value=choice)
    assert out["step"] == "tune" and len(out["groups"]) == 11
    facts = sess.builder_facts(TARGETS.split(","))
    fast, reliable = model.both(model.State.from_json(out["state"]), facts)
    by_profile = {c["profile"]: c for c in out["commands"]}
    assert by_profile["fast"]["args"] == fast.args
    assert by_profile["reliable"]["args"] == reliable.args
    assert "--max-rtt-timeout" in by_profile["reliable"]["args"]


def test_setting_and_refusing_values(tmp_path):
    _sess, client = _client(tmp_path)
    out = _step(client, action="choose", value="ports")
    out = _step(client, out["state"], action="set", value="--max-retries=3")
    for command in out["commands"]:
        args = command["args"]
        assert args[args.index("--max-retries") + 1] == "3", command["profile"]
    bad = client.get("/api/v1/builder", params={"targets": TARGETS, "state": out["state"],
                                                "action": "set", "value": "--host-timeout=fast"})
    assert bad.status_code == 422 and "expected a time" in bad.json()["detail"]
    owned = client.get("/api/v1/builder", params={"targets": TARGETS, "state": out["state"],
                                                  "action": "set", "value": "-oX=x.xml"})
    assert owned.status_code == 422


def test_a_measurement_needs_confirming(tmp_path):
    _sess, client = _client(tmp_path)
    refused = client.post("/api/v1/builder/measure", json={"targets": ["192.0.2.10"]})
    assert refused.status_code == 422 and "confirm" in refused.json()["detail"]


def test_measured_times_travel_with_the_state(tmp_path):
    _sess, client = _client(tmp_path)
    out = _step(client)
    for choice in ("services", "tcp", "known", "pn", "no", "measure"):
        out = _step(client, out["state"], action="choose", value=choice,
                    measured=json.dumps([["192.0.2.10", 250.0]]))
    reliable = out["commands"][1]["args"]
    assert reliable[reliable.index("--max-rtt-timeout") + 1] == "1000ms"


def test_help_and_earlier_commands(tmp_path):
    _sess, client = _client(tmp_path)
    lines = client.get("/api/v1/builder/help", params={"name": "-Pn"}).json()["lines"]
    assert lines[-1].endswith("man-host-discovery.html")
    earlier = client.get("/api/v1/scans/recent").json()
    assert earlier["recent"][0]["args"] == "-sS -T4 -p{ports}"
