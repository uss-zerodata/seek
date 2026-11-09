"""Round-trip times, and the RTT timeouts nmap's guide derives from them.

**The rule** (nmap.org/book/man-performance.html): ping the network, "take the
maximum RTT", "double that for the --initial-rtt-timeout and triple or
quadruple it for the --max-rtt-timeout", and "I generally do not set the
maximum RTT below 100 ms ... Nor do I exceed 1000 ms." The fast profile takes
three times, the reliable one four. The *largest* round trip decides because
the timeout has to cover the slowest host, and the sentence that goes with the
values names that host, so one far-away target explains a large timeout.

**Measuring** sends packets, so it is never done here on its own initiative:
the builder asks first, then calls one of the two functions below from a
worker. Both are bounded in hosts and in time, and both treat a probe that
gets no answer as no data - a filtered port is not a slow host.
"""

from __future__ import annotations

import socket
import statistics
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass

FLOOR_MS = 100
CEILING_MS = 1000
HOSTS = 8               # at most this many hosts are measured
TRIES = 3               # connects per host
TRY_TIMEOUT = 2.0       # seconds, one connect
BUDGET = 8.0            # seconds, the whole measurement


@dataclass(frozen=True, slots=True)
class Rtt:
    host: str
    ms: float
    source: str          # "earlier scans" or "measured now"


@dataclass(frozen=True, slots=True)
class Timing:
    values: dict[str, str]     # option -> value, e.g. {"--max-rtt-timeout": "100ms"}
    note: str                  # where they came from, in one sentence


def from_hosts(hosts, targets: set[str] | None = None) -> list[Rtt]:
    """What earlier scans recorded for these hosts (all of them when no
    targets are given)."""
    return [Rtt(h.address, h.times.srtt / 1000, "earlier scans")
            for h in hosts if h.times is not None
            and (targets is None or h.address in targets)]


def _ms(value: float) -> str:
    return f"{int(round(value))}ms"


def derive(observations: list[Rtt], profile: str, targets: int = 0) -> Timing:
    """The RTT timeouts for `profile` ("fast" or "reliable") from observed round
    trips, clamped to nmap's documented 100-1000 ms. Empty when nothing was
    observed: the template's own adaptive timing then applies."""
    if not observations:
        return Timing({}, "nothing measured - nmap's own adaptive timing applies")
    slowest = max(observations, key=lambda r: r.ms)
    factor = 3 if profile == "fast" else 4
    initial = min(max(2 * slowest.ms, FLOOR_MS), CEILING_MS)
    maximum = min(max(factor * slowest.ms, FLOOR_MS), CEILING_MS)
    maximum = max(maximum, initial)
    bound = ""
    if factor * slowest.ms < FLOOR_MS:
        bound = f", raised to the {FLOOR_MS} ms floor"
    elif factor * slowest.ms > CEILING_MS:
        bound = f", capped at the {CEILING_MS} ms ceiling"
    hosts = len({r.host for r in observations})
    partial = ""
    if targets and hosts * 3 < targets:
        partial = f" - only {hosts} of {targets} targets have data"
    note = (f"{slowest.source}: slowest of {hosts} host{'s' if hosts != 1 else ''} "
            f"{slowest.ms:.1f} ms ({slowest.host}); initial 2×, max {factor}×{bound}{partial}")
    return Timing({"--initial-rtt-timeout": _ms(initial), "--max-rtt-timeout": _ms(maximum)},
                  note)


def measure_connect(pairs: list[tuple[str, int]], cancel: threading.Event | None = None,
                    tries: int = TRIES, timeout: float = TRY_TIMEOUT,
                    budget: float = BUDGET) -> list[Rtt]:
    """Time TCP connects to open ports already known - no root, no raw packets.
    One port per host, at most `HOSTS` hosts, `tries` each, all within `budget`."""
    deadline = time.monotonic() + budget
    per_host: dict[str, list[float]] = {}
    chosen: dict[str, int] = {}
    for host, port in pairs:
        if host not in chosen and len(chosen) < HOSTS:
            chosen[host] = port
    for _ in range(tries):
        for host, port in chosen.items():
            left = deadline - time.monotonic()
            if left <= 0 or (cancel is not None and cancel.is_set()):
                break
            start = time.perf_counter()
            try:
                with socket.create_connection((host, port), timeout=min(timeout, left)):
                    per_host.setdefault(host, []).append(
                        (time.perf_counter() - start) * 1000)
            except OSError:
                continue                    # no answer is no data, not a slow host
    return [Rtt(host, statistics.median(samples), "measured now")
            for host, samples in per_host.items()]


def measure_ping(nmap: str, hosts: list[str], budget: float = BUDGET) -> list[Rtt]:
    """`nmap -sn -n -oX -` over at most `HOSTS` hosts, reading the `<times>` it
    records. Unprivileged, nmap pings with connects to ports 80 and 443."""
    argv = [nmap, "-sn", "-n", "--host-timeout", f"{int(budget)}s", "-oX", "-",
            *hosts[:HOSTS]]
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=budget + 2,  # noqa: S603
                              stdin=subprocess.DEVNULL, check=False, process_group=0)
        root = ET.fromstring(done.stdout)
    except (OSError, subprocess.SubprocessError, ET.ParseError):
        return []
    found = []
    for host in root.findall("host"):
        addr, times = host.find("address"), host.find("times")
        if addr is None or times is None:
            continue
        try:
            found.append(Rtt(addr.get("addr") or "", int(times.get("srtt") or "") / 1000,
                             "measured now"))
        except ValueError:
            continue
    return found
