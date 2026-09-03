"""Drive the viewer at engagement scale and check what the spec promises.

    uv run python benchmarks/gen_nmap_corpus.py /tmp/engagement
    uv run python benchmarks/drive_nmap.py /tmp/engagement

Everything here is asserted by hand at the terminal too, but by hand it is
asserted once. This is the same walk-through, repeatable and timed: the viewer
is opened on the real corpus through Textual's own `Pilot`, an event loop tick
runs beside it for the whole session, and each claim in
``openspec/changes/responsive-large-engagements/specs/`` is checked where it is
observable - what the status line says, what the tab's own area draws, what
`Esc` does, and how late any tick was.

Not a test: it needs a 100 MB corpus and takes about a minute, so it lives here
rather than in `tests/`, next to the numbers it is checking.
"""

from __future__ import annotations

import argparse
import asyncio
import statistics
import sys
import time
from pathlib import Path

from textual.widgets import DataTable, Static

from seek.nmap.merge import Pending, discover
from seek.tui.nmap import app as app_mod
from seek.tui.nmap.app import NmapApp

# The bound the spec sets on any pause the interface takes for its own work.
BOUND_MS = 200


def _rss() -> float:
    """Resident memory in MB - a stall can be the machine, not the program."""
    try:
        with open("/proc/self/statm") as fh:
            return int(fh.read().split()[1]) * 4096 / 1e6
    except OSError:
        return 0.0
TABS = ("hosts", "services", "stats", "group-service", "group-product",
        "group-port", "names", "scans")


class Ticker:
    """A 5 ms heartbeat beside the viewer, recording how late each beat was."""

    def __init__(self) -> None:
        self.late: list[float] = []
        self._stop = False
        self._task: asyncio.Task | None = None

    def start(self) -> None:
        self._task = asyncio.create_task(self._run())

    async def _run(self) -> None:
        while not self._stop:
            began = time.perf_counter()
            await asyncio.sleep(0.005)
            self.late.append((time.perf_counter() - began - 0.005) * 1000)

    async def stop(self) -> None:
        self._stop = True
        if self._task is not None:
            await self._task

    def phase(self, label: str) -> bool:
        """Report the beats since the last call. Per phase, so it says *where*."""
        late, self.late = self.late, []
        return self.report(label, late)

    def report(self, label: str, late: list[float] | None = None) -> bool:
        late = self.late if late is None else late
        if not late:
            return True
        ordered = sorted(late)
        worst = ordered[-1]
        p95 = ordered[int(len(ordered) * 0.95)]
        ok = worst <= BOUND_MS
        print(f"  {'ok ' if ok else 'FAIL'} {label}: median "
              f"{statistics.median(late):.1f} ms, p95 {p95:.1f} ms, "
              f"worst {worst:.1f} ms late ({len(late)} ticks, {_rss():.0f} MB)")
        return ok


def check(ok: bool, what: str, detail: str = "") -> bool:
    print(f"  {'ok ' if ok else 'FAIL'} {what}" + (f" - {detail}" if detail else ""))
    return ok


def pane(app: NmapApp) -> str:
    return str(app.query_one("#empty", Static).render())


def status(app: NmapApp) -> str:
    return str(app.query_one("#status", Static).render())


async def drive(root: Path) -> int:
    paths = discover([root])
    print(f"\n{len(paths)} candidate files under {root}\n")
    app = NmapApp(Pending(paths))
    passed = True
    ticker = Ticker()
    async with app.run_test(size=(160, 50)) as pilot:
        ticker.start()

        # --- the viewer opens before the scans are read
        await pilot.pause(app_mod._READ_QUIET + 0.3)
        passed &= check(app._reading is not None and not app._reading.finished,
                        "the viewer is up while the read is still going")
        await pilot.press("s")
        passed &= check(app._active_tab == "stats",
                        "and answers a keystroke", f"tab is {app._active_tab}")
        await pilot.press("escape")
        passed &= check("reading scans" in status(app),
                        "reading progress is in the status line", status(app)[:70])
        passed &= check("Still reading" in pane(app) or app._rows != [],
                        "and an empty list says the read is unfinished")

        # --- it fills as the scans arrive. Counted in files rather than hosts:
        # the generated corpus covers its whole address pool within the first
        # third of the files, so the host count stops growing long before the
        # read does.
        passed &= ticker.phase("input latency while opening")
        # Counted in files read rather than hosts known: the generated corpus
        # covers its whole address pool within the first third of the files.
        read_before = app._reading.done
        published = [len(app.scans.sources)]
        emptied = 0
        for _ in range(600):
            await pilot.pause(0.1)
            rows = app.query_one(DataTable).row_count
            if published[0] and rows == 0:
                emptied += 1
            if len(app.scans.sources) != published[-1]:
                published.append(len(app.scans.sources))
            if app._reading is not None and app._reading.finished:
                break
        passed &= check(app._reading.done > read_before,
                        "the model grows while the viewer is open",
                        f"{read_before} -> {app._reading.done} files read, "
                        f"{len(published)} publications, "
                        f"{len(app.scans.hosts)} hosts")
        passed &= check(emptied == 0,
                        "and the list is never taken away while it does",
                        f"empty on {emptied} of the samples")
        passed &= check(app._reading is not None and app._reading.finished,
                        "the read finishes", f"{len(app.scans.hosts)} hosts")
        passed &= check("reading scans" not in status(app),
                        "and the status line stops saying it is reading")
        passed &= ticker.phase("input latency while reading")

        # --- every tab reports determinately, in hosts
        for tab in TABS:
            reports: list[tuple[int, int, str]] = []
            received = app._on_build_progress

            def watch(token, done, total, unit, seen=reports, on=received):
                seen.append((done, total, unit))
                on(token, done, total, unit)

            app._on_build_progress = watch
            app._activate(tab)
            app._refresh_view()
            await pilot.pause(0.2)
            drawn = pane(app) if app._busy is not None else ""
            for _ in range(600):
                await pilot.pause(0.05)
                if app._busy is None:
                    break
            app._on_build_progress = received
            units = {u for _, _, u in reports}
            passed &= check(
                bool(reports) and units <= {"hosts", "scans"},
                f"{tab}: reports determinately",
                f"{len(reports)} reports of {units or 'nothing'}")
            passed &= check(f"of {len(app.scans.hosts)} hosts" in drawn
                            or "scans" in drawn or not reports,
                            f"{tab}: draws a determinate bar while it builds",
                            drawn.replace("\n", " ")[:70])
            passed &= check(app.query_one(DataTable).row_count > 0,
                            f"{tab}: has rows", f"{len(app._rows)} rows")
            passed &= ticker.phase(f"{tab}: input latency")

        # --- Esc abandons a build
        app._activate("stats")
        vdefs_view = app.view
        vdefs_view._rows_of = None                  # make it build again
        app._refresh_view()
        # No pause before the key: `_refresh_view` starts the build
        # synchronously, and a projection this size sometimes finishes inside
        # any wait long enough to write down - leaving nothing to abandon.
        building = app._busy is not None
        await pilot.press("escape")
        abandoned, said = app._busy is None, pane(app)
        # Sampled the instant the key is handled. A pause first would let the
        # tab's own width poll notice that the table shrank to its headers and
        # start the build again, which is the tab doing what it is meant to do
        # and not what this line is asking about.
        passed &= check(building and abandoned,
                        "Esc abandons a build in progress")
        passed &= check("Stopped reading" in said,
                        "and says what was given up", said.replace("\n", " ")[:60])
        await pilot.pause(0.1)

        await ticker.stop()
        passed &= ticker.phase("input latency, closing")

    print()
    return 0 if passed else 1


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("corpus", type=Path)
    sys.exit(asyncio.run(drive(ap.parse_args().corpus)))


if __name__ == "__main__":
    main()
