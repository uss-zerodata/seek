"""Which ports a host was actually probed on - so "not open" can be told from "never asked".

nmap states the ports a scan probed once per protocol, in `<scaninfo services>`,
and leaves most closed ports out of the port list. A rule that says "22/tcp is
not open" can therefore only be certain where some scan of the host probed
22/tcp. This module turns the per-file statements (`ScanFile.coverage`,
`timed_out`, `not_scanned`) into a per-host answer. It reads no file and holds
no opinion about rules; `tagging` asks it.
"""

from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass

from seek.nmap.models import Host, ScanFile

Ranges = tuple[tuple[int, int], ...]

# nmap's port numbers; a range outside them is a malformed statement.
PORT_MIN, PORT_MAX = 0, 65535


def parse_ranges(text: str) -> Ranges:
    """`"1-1000,8080,8443-8444"` as sorted, merged inclusive ranges.

    Raises ValueError for anything that is not a port list - a protocol whose
    list cannot be read has unknown coverage, never an empty one.
    """
    pairs: list[tuple[int, int]] = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        low, dash, high = part.partition("-")
        lo, hi = int(low), int(high) if dash else int(low)
        if not PORT_MIN <= lo <= hi <= PORT_MAX:
            raise ValueError(f"not a port range: {part!r}")
        pairs.append((lo, hi))
    return merge_ranges(pairs)


def merge_ranges(pairs) -> Ranges:
    """Sorted, with touching and overlapping ranges joined."""
    out: list[list[int]] = []
    for lo, hi in sorted(pairs):
        if out and lo <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], hi)
        else:
            out.append([lo, hi])
    return tuple((lo, hi) for lo, hi in out)


def contains(ranges: Ranges, port: int) -> bool:
    at = bisect_right(ranges, (port, PORT_MAX + 1)) - 1
    return at >= 0 and ranges[at][0] <= port <= ranges[at][1]


@dataclass(frozen=True, slots=True)
class HostCoverage:
    """The ports some scan probed on one host, per protocol."""

    by_protocol: dict[str, Ranges]
    unknown: frozenset[str] = frozenset()

    def covers(self, port: int, protocol: str | None = None) -> bool:
        """Probed on that protocol - or, with none named, on any protocol."""
        if protocol is not None:
            return contains(self.by_protocol.get(protocol.lower(), ()), port)
        return any(contains(r, port) for r in self.by_protocol.values())


EMPTY = HostCoverage({})


class Coverage:
    """Host coverage for one `ScanSet`, computed once per combination of sources.

    Thousands of hosts share the same few combinations of scan files, so the
    union is cached on the tuple of source labels plus the per-file exclusions
    that apply to the host.
    """

    def __init__(self, files: list[ScanFile]) -> None:
        self._files = {f.label or f.path.name: f for f in files}
        self._cache: dict[tuple, HostCoverage] = {}

    def of(self, host: Host) -> HostCoverage:
        usable = tuple(label for label in host.sources
                       if (f := self._files.get(label)) is not None
                       and host.address not in f.timed_out
                       and host.address not in f.not_scanned)
        found = self._cache.get(usable)
        if found is None:
            pairs: dict[str, list[tuple[int, int]]] = {}
            unknown: set[str] = set()
            for label in usable:
                f = self._files[label]
                for proto, ranges in f.coverage.items():
                    pairs.setdefault(proto, []).extend(ranges)
                unknown |= f.coverage_unknown
            found = HostCoverage({p: merge_ranges(r) for p, r in pairs.items()},
                                 frozenset(unknown)) if usable else EMPTY
            self._cache[usable] = found
        return found
