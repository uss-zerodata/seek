"""Where the time goes when an engagement is opened, and what it costs the user.

Two measurements, against a corpus written by `gen_nmap_corpus.py`::

    uv run python benchmarks/gen_nmap_corpus.py /tmp/engagement
    uv run python benchmarks/bench_nmap.py /tmp/engagement
    uv run python benchmarks/bench_nmap.py /tmp/engagement --latency

The first is the pipeline split - discover, parse, merge, prepare, the scan
history, and each overview projection - which says which phase is worth
attacking. The second is the one the user actually feels: an event loop ticking
every 5 ms while a projection runs in a thread, reporting how late each tick
was. A pause is not the average; it is the tail, so the p95 and the worst are
the figures that matter and the median is only there to show they are
different.

Not collected by `pytest` (`testpaths = ["tests"]`): it needs a corpus and
takes half a minute. It exists so the figures quoted in
``openspec/changes/responsive-large-engagements/`` stay reproducible.

Measured on the 120-file / 24 200-host / 106 MB corpus the generator writes by
default (342 557 services; Python 3.12, on a loaded desktop). "before" is
`--raw` - the pipeline as it stood, with the cycle collector running through
every phase; "after" is the policy `nmap.bulk` applies at the two phase owners.
Both columns are from the same session, because absolute figures move by a
third between one run and the next on a machine doing anything else; the ratio
does not.

                            before      after
    discover                    7 ms        7 ms
    parse                    8457 ms     3547 ms
    merge                    4002 ms     1677 ms
    prepare                  2213 ms      609 ms
    scan history             4450 ms     2466 ms
    hosts                    2149 ms      511 ms
    services                  889 ms      739 ms
    statistics               3474 ms     1428 ms
    by service               3950 ms     1155 ms
    by product                854 ms      822 ms
    by port                  1312 ms     1265 ms
    names                    5040 ms     1474 ms
    -----------------------------------------------
    total                   36796 ms    15701 ms

    input latency, median     5.2 ms      1.1 ms
                   p95       10.4 ms      1.2 ms
                   worst   1962.0 ms      2.4 ms

The software inventory (`openspec/changes/service-inventory/`) adds two rows,
measured on the same corpus under the same policy: `inventory` - building it,
once per model and capture generation - 544 ms, and `inventory tab` - grouping
it into the tab's rows - 582 ms. Both were 1.9 s and 5.6 s before memoising
the CPE bindings and per-place reconciliation (a corpus repeats a few
identifications across 342 557 services) and summarising each entry once.

The vulnerability lookup (`openspec/changes/vulnerability-lookup/`) adds three
more, against the test suite's feed fixtures built into a throwaway database:
`vuln lookup` 200 ms (each distinct product and version evaluated once),
`inventory tab` 751 ms with its Support / Vulns / Max columns, and `findings
tab` 1187 ms. The lookup's cost grows with distinct versions, not with hosts;
the tabs' with the places each product runs on.

Host tagging (`openspec/changes/host-tagging/`) adds `tags (200 rules)`: 200
generated rules - every fourth with an exclusion, every tenth testing a product
on any port, every twentieth asking for another tag - over the same corpus, as
the session's projection builds them: 1370 ms from cold, of which about half is
the rule-independent index (services by port, field values, port coverage) that
the session keeps per model and capture generation; a rebuild after a manual tag
or a rule edit reuses it and takes about 900 ms. The corpus is a hard case for
it: every host has most ports open, so each rule holds on about 40 % of hosts -
150 000 host grants in all. Evaluating host by host, over the same rules, took
13.6 s; clause by clause over sets of hosts is what brought it here.

Note that "to the first screen" has no row any more, because there no longer is
one: the viewer opens on the candidate files and reads them with the screen
already up. What the user waits for is the first publication, not the last -
see `drive_nmap.py`, which walks the viewer at this scale and checks that no
wait exceeds the fifth of a second the specs set.

The last row is the one that made the viewer feel broken: a second and a half
in which no keystroke is answered, and it is a generational collection walking
millions of tracked objects rather than any of the work above. The median is
the thread switch interval and nothing else, which is why `responsive` moves
it. Note that suspending collection alone does not buy the last row - it only
moves the pause to the moment the phase ends; freezing what the phase built is
what removes it. See `nmap/bulk.py`.
"""

from __future__ import annotations

import argparse
import asyncio
import random
import statistics
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from seek.nmap import bulk, inventory, tagfiles, tagging, tagrules, timeline
from seek.nmap import merge as merge_mod
from seek.nmap.parse import NmapParseError, parse_file
from seek.nmap.views import prepare
from seek.tui.nmap import views as vdefs


class Split:
    """Phase name -> seconds, in the order the phases ran."""

    def __init__(self) -> None:
        self.rows: list[tuple[str, float]] = []

    def time(self, label: str, fn):
        began = time.perf_counter()
        value = fn()
        self.rows.append((label, time.perf_counter() - began))
        return value

    def report(self) -> None:
        width = max(len(name) for name, _ in self.rows)
        for name, seconds in self.rows:
            print(f"    {name:<{width}}  {seconds * 1000:8.0f} ms")
        total = sum(s for _, s in self.rows)
        print(f"    {'total':<{width}}  {total * 1000:8.0f} ms")


@contextmanager
def _policy(applied: bool):
    """The collector policy the viewer's phase owners apply, or nothing.

    `--raw` is what makes the two columns in the docstring comparable: the
    phases are identical either way, and only the policy around them differs.
    """
    if not applied:
        yield
        return
    with bulk.bulk(), bulk.responsive():
        yield


class _Inventoried:
    """What `inventory_view` reads from a session, without a session: the
    model, a capture generation, and the inventory cached once built."""

    class _Shots:
        generation = 0

    unplaced_captures: list[str] = []          # no captures in the corpus

    def __init__(self, scans, store=None) -> None:
        self.scans, self.shots, self._inventory = scans, self._Shots(), None
        self._store, self._lookup = store, None

    def inventory(self, report=None):
        if self._inventory is None:
            self._inventory = inventory.build(self.scans.hosts, report=report)
        return self._inventory

    def vulndb(self):
        return self._store

    def lookup(self):
        if self._lookup is None:
            from seek.vulndb import match
            self._lookup = match.build(self.inventory(), self.scans.hosts, self._store)
        return self._lookup


def _fixture_store():
    """The test suite's feed fixtures, built into a throwaway database - small,
    but every code path of the matcher runs against it."""
    import tempfile

    sys.path.insert(0, str(Path(__file__).parents[1] / "tests"))
    import vulndb_fixtures as fx

    from seek.vulndb.store import Store
    return Store(fx.database(Path(tempfile.mkdtemp(prefix="seek-bench-"))))


RULES = 200
_PORTS = (22, 25, 53, 80, 110, 139, 443, 445, 631, 3128, 3306, 3389, 5432, 6379, 8080, 8443,
          9200, 27017)
_PRODUCTS = ("OpenSSH", "nginx", "Apache", "MySQL", "PostgreSQL", "Redis", "Squid", "CUPS",
             "Samba", "Elasticsearch", "MongoDB", "Postfix", "Dovecot", "BIND")


def _generated_tags(count: int):
    """`count` deterministic rules: positive ports with products, every fourth with
    an exclusion, every tenth port-free (the slow kind), every twentieth asking
    for the tag before it."""
    rnd = random.Random(0)
    lines = ["tags:"]
    for n in range(count):
        ports = rnd.sample(_PORTS, 2)
        when = [f"{{port: {ports[0]}, product: {rnd.choice(_PRODUCTS)}}}", f"{{port: {ports[1]}}}"]
        if n % 4 == 0:
            when.append(f"{{not: {{port: {rnd.choice(_PORTS)}/tcp}}}}")
        if n % 10 == 0:
            when.append(f"{{product: {rnd.choice(_PRODUCTS)}}}")
        if n % 20 == 0 and n:
            when.append(f"{{tag: t{n - 1}}}")
        lines.append(f"  t{n}:\n    rules: [{{when: [{', '.join(when)}]}}]")
    _doc, defs = tagrules.load("\n".join(lines) + "\n", "generated")
    order, disabled = tagrules.order(defs.tags)
    return tagfiles.Loaded(tags=defs.tags, order=order, disabled=disabled)


def pipeline(root: Path, policy: bool = True) -> None:
    """Every phase between "the directory" and "a tab full of rows"."""
    split = Split()
    paths = split.time("discover", lambda: merge_mod.collect_paths([root]))

    def read() -> list:
        files = []
        for path in paths:
            try:
                files.append(parse_file(path))
            except NmapParseError as exc:
                print(f"    ! {path.name}: {exc}", file=sys.stderr)
        return files

    # The reading phase, as the reading worker owns it.
    with _policy(policy):
        files = split.time("parse", read)
        scans = split.time("merge", lambda: merge_mod.merge(files))
        scans = split.time("prepare", lambda: prepare(scans))
    # And the projecting phase, as the projection worker owns it.
    with _policy(policy):
        split.time("scan history", lambda: timeline.build(scans.files))
        # The overviews, each built exactly as the viewer builds it - through
        # the same `View`, so a projection that gets cheaper here gets cheaper
        # there.
        for label, view in (
            ("hosts", vdefs.hosts_view()),
            ("services", vdefs.services_view()),
            ("statistics", vdefs.statistics_view()),
            ("by service", vdefs.grouping_view("service")),
            ("by product", vdefs.grouping_view("product")),
            ("by port", vdefs.grouping_view("port")),
            ("names", vdefs.names_view()),
        ):
            split.time(label, lambda view=view: view.rows(scans))
        # The inventory is built once per model (a session projection), then
        # the tab groups it - two phases, timed apart.
        owner = _Inventoried(scans, _fixture_store())
        split.time("inventory", owner.inventory)
        split.time("vuln lookup", owner.lookup)
        split.time("inventory tab", lambda: vdefs.inventory_view(owner).rows(scans))
        split.time("findings tab", lambda: vdefs.findings_view(owner).rows(scans))
        # Tagging: a session projection like the inventory, here over generated
        # rules with exclusions, port-free tests and tag dependencies.
        loaded = _generated_tags(RULES)
        split.time(f"tags ({RULES} rules)",
                   lambda: tagging.build(scans.hosts, scans.files, loaded, {}))

    size = sum(p.stat().st_size for p in paths)
    print(f"\n{len(paths)} files, {size / 1e6:.1f} MB, {len(scans.hosts)} hosts, "
          f"{sum(len(h.services) for h in scans.hosts)} services\n")
    split.report()


async def _tick(lateness: list[float], stop: threading.Event) -> None:
    """Sleep 5 ms in a loop and record how much longer than 5 ms it took.

    That difference is exactly what a user feels: the interval is the event
    loop's own heartbeat, so a tick that comes back 200 ms late is 200 ms in
    which no keystroke was answered.
    """
    interval = 0.005
    while not stop.is_set():
        began = time.perf_counter()
        await asyncio.sleep(interval)
        lateness.append((time.perf_counter() - began - interval) * 1000)


async def latency(root: Path, policy: bool = True,
                  quiet: bool = False) -> list[float]:
    """Tick an event loop while the heaviest projection runs in a thread."""
    with _policy(policy):
        scans = prepare(merge_mod.load([root]))
    view = vdefs.statistics_view()
    stop = threading.Event()
    lateness: list[float] = []

    def build() -> None:
        try:
            with _policy(policy):
                view.rows(scans)
        finally:
            stop.set()

    ticking = asyncio.create_task(_tick(lateness, stop))
    began = time.perf_counter()
    await asyncio.to_thread(build)
    elapsed = time.perf_counter() - began
    await ticking
    if not quiet:
        ordered = sorted(lateness)
        p95 = ordered[int(len(ordered) * 0.95)] if ordered else 0.0
        print(f"\nprojecting {len(scans.hosts)} hosts took {elapsed:.2f}s, "
              f"{len(lateness)} event-loop ticks\n")
        print(f"    median  {statistics.median(lateness):8.1f} ms late")
        print(f"    p95     {p95:8.1f} ms late")
        print(f"    worst   {max(lateness):8.1f} ms late")
    return lateness


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("corpus", type=Path, help="a directory of nmap XML")
    ap.add_argument("--latency", action="store_true",
                    help="measure event-loop responsiveness instead of the split")
    ap.add_argument("--raw", action="store_true",
                    help="without the collector policy - the 'before' column")
    args = ap.parse_args()
    if args.latency:
        asyncio.run(latency(args.corpus, policy=not args.raw))
    else:
        pipeline(args.corpus, policy=not args.raw)


if __name__ == "__main__":
    main()
