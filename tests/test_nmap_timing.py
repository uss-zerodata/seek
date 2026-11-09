"""RTT timeouts from round trips, and the bounded measurement."""

from __future__ import annotations

import socket
import threading
from pathlib import Path

from seek.nmap.merge import load
from seek.nmap.timing import Rtt, derive, from_hosts, measure_connect, measure_ping

FIX = Path(__file__).parent / "fixtures" / "nmap"


def _rtts(*ms: float, source="earlier scans") -> list[Rtt]:
    return [Rtt(f"192.0.2.{i}", value, source) for i, value in enumerate(ms, 1)]


def test_a_lan_is_raised_to_the_documented_floor():
    timing = derive(_rtts(0.4, 1.2, 0.8), "reliable")
    assert timing.values == {"--initial-rtt-timeout": "100ms", "--max-rtt-timeout": "100ms"}
    assert "raised to the 100 ms floor" in timing.note
    assert "slowest of 3 hosts 1.2 ms (192.0.2.2)" in timing.note


def test_an_internet_path_follows_the_two_three_four_rule():
    fast, reliable = derive(_rtts(60, 180), "fast"), derive(_rtts(60, 180), "reliable")
    assert fast.values == {"--initial-rtt-timeout": "360ms", "--max-rtt-timeout": "540ms"}
    assert reliable.values["--max-rtt-timeout"] == "720ms"


def test_a_far_host_is_capped_and_named():
    timing = derive(_rtts(20, 450), "reliable")
    assert timing.values == {"--initial-rtt-timeout": "900ms", "--max-rtt-timeout": "1000ms"}
    assert "capped at the 1000 ms ceiling" in timing.note and "(192.0.2.2)" in timing.note


def test_nothing_observed_sets_nothing():
    timing = derive([], "fast")
    assert timing.values == {} and "nothing measured" in timing.note


def test_partial_data_is_said():
    assert "only 1 of 24 targets have data" in derive(_rtts(5), "fast", targets=24).note


def test_earlier_scans_give_milliseconds_for_the_targets():
    hosts = load([FIX / "timing.xml"]).hosts
    rtts = from_hosts(hosts, {"192.0.2.10", "192.0.2.12"})
    assert rtts == [Rtt("192.0.2.10", 1.2, "earlier scans")]


def _listener():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(16)
    stop = threading.Event()

    def accept():
        server.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = server.accept()
                conn.close()
            except OSError:
                continue

    threading.Thread(target=accept, daemon=True).start()
    return server, stop


def test_connects_to_a_known_open_port_are_timed():
    server, stop = _listener()
    try:
        rtts = measure_connect([("127.0.0.1", server.getsockname()[1])], budget=3)
    finally:
        stop.set()
        server.close()
    assert len(rtts) == 1 and rtts[0].source == "measured now" and rtts[0].ms < 100


def test_a_port_that_does_not_answer_is_no_data():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        closed = s.getsockname()[1]
    assert measure_connect([("127.0.0.1", closed)], budget=1) == []


def test_a_cancelled_measurement_stops():
    cancel = threading.Event()
    cancel.set()
    assert measure_connect([("127.0.0.1", 1)], cancel=cancel) == []


def test_a_ping_measurement_reads_nmaps_times(tmp_path):
    stub = tmp_path / "nmap"
    stub.write_text("#!/bin/sh\ncat <<'EOF'\n<nmaprun><host><address addr=\"192.0.2.9\"/>"
                    "<times srtt=\"4200\" rttvar=\"100\" to=\"100000\"/></host>"
                    "<host><address addr=\"192.0.2.8\"/></host></nmaprun>\nEOF\n")
    stub.chmod(0o755)
    assert measure_ping(str(stub), ["192.0.2.9", "192.0.2.8"]) == [
        Rtt("192.0.2.9", 4.2, "measured now")]


def test_a_ping_measurement_without_nmap_is_no_data(tmp_path):
    assert measure_ping(str(tmp_path / "missing"), ["192.0.2.9"]) == []
