"""Copied commands: the text form of a plan, here and for another machine."""

from __future__ import annotations

import shlex

from seek.gowitness.capture import settle_script
from seek.nmap import remote

URLS = ["https://192.0.2.1:443", "http://www.example.test:8080"]


def test_local_text_round_trips():
    argv = ["sudo", "-n", "/opt/nmap", "-sS", "--script", "http-title and not brute",
            "-oA", "/home/alice/eng/01 scan", "192.0.2.1"]
    assert shlex.split(remote.local_text(argv)) == argv


def test_nmap_snippet_elevates_interactively():
    text = remote.nmap_snippet(["-sS", "-p", "22,80"], ["192.0.2.1"], "01-scan")
    argv = shlex.split(text)
    assert argv[:2] == ["sudo", "nmap"] and "-n" not in argv[:3]
    assert argv[argv.index("-oA") + 1] == "01-scan"


def test_nmap_snippet_without_root_flags_has_no_sudo():
    argv = shlex.split(remote.nmap_snippet(["-sT"], ["192.0.2.1"], "x"))
    assert argv[0] == "nmap"


def test_nmap_snippet_quotes_shell_text():
    text = remote.nmap_snippet(["--script-args", "a=$(id);b"], ["192.0.2.1"], "x")
    assert "$(id)" in shlex.split(text)[2]


def test_capture_snippet_is_self_contained():
    text = remote.capture_snippet(URLS, settle_ms=4000, settle_cap_ms=30_000)
    lines = text.splitlines()
    assert lines[0] == "mkdir -p gowitness/screenshots"
    assert lines[1] == "cat > gowitness/urls.txt <<'SEEK_URLS'"
    assert lines[2:4] == URLS and lines[4] == remote.URLS_END
    argv = shlex.split(lines[5])
    assert argv[0] == "gowitness" and "docker" not in text
    assert argv[argv.index("-f") + 1] == "gowitness/urls.txt"
    assert argv[argv.index("--screenshot-path") + 1] == "gowitness/screenshots"
    assert settle_script(4000, 30_000) in argv
    assert argv[argv.index("--delay") + 1] == "1", "the default pause before the script"
    assert argv[argv.index("--write-db-uri") + 1] == "sqlite://gowitness/gowitness.sqlite3"


def test_no_local_path_in_either_snippet(tmp_path):
    nmap = remote.nmap_snippet(["-sS"], ["192.0.2.1"], "01-scan")
    gw = remote.capture_snippet(URLS)
    for text in (nmap, gw):
        assert str(tmp_path) not in text and "/home" not in text and "/data" not in text
