"""Commands used before: arguments kept, targets never."""

from __future__ import annotations

import json
import shlex

import pytest

from seek.nmap import presets
from seek.nmap.models import ScanFile
from seek.nmap.recent import CommandHistory, frequent, recent, strip, text


@pytest.mark.parametrize("name, args", presets.DEFAULT_PRESETS.items())
def test_every_shipped_preset_survives_whole(name, args):
    argv = ["nmap", *presets.parse_args(args), "192.0.2.0/24"]
    assert strip(argv) == presets.parse_args(args), name


@pytest.mark.parametrize("command, kept", [
    ("nmap -sS -T4 -p 22,80 -oA out/scan 10.0.0.0/24", "-sS -T4 -p 22,80"),
    ("sudo -n /usr/bin/nmap -sU -p- 10.0.0.5 10.0.0.6", "-sU -p-"),
    ("nmap -sV --script vuln db.acme.test", "-sV --script vuln"),
    ("nmap -sV --script=vuln -iL /home/alice/acme/targets.txt", "-sV --script=vuln"),
    ("nmap -sn --exclude 10.0.0.1,10.0.0.2 10.0.0.0/24", "-sn"),
    ("nmap -sn --excludefile /etc/skip 10.0.0-255.1-254", "-sn"),
    ("nmap -6 -sS fe80::1%eth0", "-6 -sS"),
    ("nmap -oX /tmp/x.xml -oN - --append-output 10.0.0.1", ""),
    ("nmap --frobnicate 10.0.0.1 -sS", "--frobnicate -sS"),
    ("nmap -sUV --top-ports 100 10.0.0.1", "-sUV --top-ports 100"),
])
def test_targets_paths_and_output_never_survive(command, kept):
    assert text(strip(shlex.split(command))) == kept


def test_the_history_file_never_holds_a_target(tmp_path):
    history = CommandHistory(tmp_path / "nmap-commands.json")
    history.record(["sudo", "-n", "nmap", "-sV", "--script", "vuln", "-oA",
                    "/home/alice/acme/scan", "10.0.0.5", "db.acme.test"], when=100)
    history.record(["nmap", "-sV", "--script", "vuln", "10.9.9.9"], when=200)
    raw = (tmp_path / "nmap-commands.json").read_text()
    for secret in ("10.0.0.5", "db.acme", "alice", "10.9.9.9", "-oA"):
        assert secret not in raw
    assert json.loads(raw)["commands"]["-sV --script vuln"] == {"count": 2, "last": 200}


def test_the_history_is_capped(tmp_path):
    history = CommandHistory(tmp_path / "h.json")
    for n in range(205):
        history.record(["nmap", "--max-retries", str(n), "10.0.0.1"], when=n)
    assert len(history.entries) == 200
    assert "--max-retries 0" not in history.entries, "the least recently used went"


def test_a_broken_history_file_is_an_empty_one(tmp_path):
    (tmp_path / "h.json").write_text("{not json")
    assert CommandHistory(tmp_path / "h.json").entries == {}


def _scan(args: str, start: int) -> ScanFile:
    return ScanFile(path=None, hosts=[], args=args, start=start)


def test_recent_and_frequent_merge_the_scans_and_the_history(tmp_path):
    history = CommandHistory(tmp_path / "h.json")
    for when in (10, 20, 30):
        history.record(["nmap", "-sU", "--top-ports", "100", "x"], when=when)
    files = [_scan("nmap -sS -p 22,80 -oX a.xml 10.0.0.0/24", 500),
             _scan("nmap -sS -p 22,80 -oX b.xml 10.0.0.0/24", 400),
             _scan("nmap -sn 10.0.0.0/24", 450)]
    newest = recent(files, history)
    assert [e.args for e in newest] == ["-sS -p 22,80", "-sn", "-sU --top-ports 100"]
    assert newest[0].where == "this engagement" and newest[0].count == 2
    assert [e.args for e in frequent(files, history)][0] == "-sU --top-ports 100"


def test_the_known_ports_become_a_placeholder_again():
    files = [_scan("nmap -sV -p 22,80,443 10.0.0.5", 1)]
    assert recent(files, None, known_ports="22,80,443")[0].args == "-sV -p{ports}"
    assert recent(files, None, known_ports="22")[0].args == "-sV -p 22,80,443"


def test_two_processes_keep_each_others_commands(tmp_path):
    """The viewer and `seek nmap serve` each hold a history; neither may erase
    what the other recorded."""
    path = tmp_path / "h.json"
    viewer, server = CommandHistory(path), CommandHistory(path)
    viewer.record(["nmap", "-sS", "10.0.0.1"], when=1)
    server.record(["nmap", "-sU", "10.0.0.1"], when=2)
    viewer.record(["nmap", "-sV", "10.0.0.1"], when=3)
    assert set(CommandHistory(path).entries) == {"-sS", "-sU", "-sV"}


def test_the_entries_a_reader_holds_never_change_under_it(tmp_path):
    history = CommandHistory(tmp_path / "h.json")
    history.record(["nmap", "-sS", "x"], when=1)
    held = history.entries
    for args in ("-sU", "-sV", "-O", "-A"):
        history.record(["nmap", args, "x"], when=2)
    assert list(held) == ["-sS"], "a new dict is swapped in; the old one is untouched"
    assert not (tmp_path / "h.json.tmp").exists(), "written whole, then moved into place"
