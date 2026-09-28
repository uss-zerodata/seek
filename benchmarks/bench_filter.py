"""What one filter keystroke costs over an engagement's host and service lists.

    uv run python benchmarks/gen_nmap_corpus.py /tmp/engagement
    uv run python benchmarks/bench_filter.py /tmp/engagement

Each figure is the best of five passes of `filtering.matches` over every row of
the projection - which is what `NmapApp._narrow` does on a keystroke - so it is
the filter's own cost, not the table fill that follows. The plain queries are
the path that existed before structured queries; the structured ones must stay
in the same range for typing to feel the same.

Not collected by `pytest`: it needs a corpus. Figures are recorded below the
line when they change.

-----------------------------------------------------------------------------

120 files / 24 200 hosts / 342 557 services (Python 3.12, loaded desktop):

    hosts: 24200 rows
      plain       nginx                             131 ms
      plain       10.0.0.0/8 nginx                   48 ms
      plain       apache !ssl                       166 ms
      structured  open:22                            39 ms
      structured  service:http product:nginx        135 ms
      structured  NOT service:ssh                    58 ms
      structured  service:ssh OR open:80             63 ms
      structured  10.0.0.0/8 open:445 !printer      120 ms

    services: 36 rows (each standing for up to ~20 000 host/port pairs)
      plain       nginx                               0 ms
      plain       10.0.0.0/8 nginx                  488 ms   (addresses, not ports)
      structured  any of the above                    0 ms   (27 ms with a range)

A service row's ports are reduced to one sample per distinct (port, protocol,
state, name, product) and kept for the model's lifetime: the *first*
structured keystroke on that tab pays ~200 ms to build them, every later one
0.1 ms. Before the samples, every structured keystroke there cost 144-243 ms.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

from seek.nmap import filtering
from seek.nmap.merge import load
from seek.nmap.views import prepare
from seek.tui.nmap import views as vdefs

QUERIES = [
    ("plain", "nginx"),
    ("plain", "10.0.0.0/8 nginx"),
    ("plain", "apache !ssl"),
    ("structured", "open:22"),
    ("structured", "service:http product:nginx"),
    ("structured", "NOT service:ssh"),
    ("structured", "service:ssh OR open:80"),
    ("structured", "10.0.0.0/8 open:445 !printer"),
]


def _best(rows, spec, passes: int = 5) -> tuple[float, int]:
    best, kept = float("inf"), 0
    for _ in range(passes):
        began = time.perf_counter()
        kept = sum(1 for r in rows
                   if filtering.matches(spec, r.text, r.addresses, r.records))
        best = min(best, time.perf_counter() - began)
    return best * 1000, kept


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/engagement")
    scans = prepare(load([root]))
    views = {"hosts": vdefs.hosts_view().rows(scans),
             "services": vdefs.services_view().rows(scans)}
    print(f"{len(scans.hosts)} hosts, "
          f"{sum(len(h.services) for h in scans.hosts)} services")
    for name, rows in views.items():
        print(f"\n{name}: {len(rows)} rows")
        for kind, query in QUERIES:
            spent, kept = _best(rows, filtering.parse_filter(query))
            print(f"  {kind:<11} {query:<34} {spent:8.1f} ms  {kept:>6} kept")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
