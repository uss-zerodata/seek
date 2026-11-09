"""Starting things from the viewer: scans, captures and the vulnerability
database update - each a short conversation of modal screens that ends in a
run on the session.

A mixin on `NmapApp` (as `ActionsMixin` is on the search app): these flows
share nothing with the layout but `notify`, `push_screen_wait` and the session,
and kept apart they can be read, and changed, without the 3 000 lines of list,
pane and reading pipeline around them.
"""

from __future__ import annotations

import asyncio
import subprocess

from rich.text import Text
from textual import work
from textual.app import SuspendNotSupported

from seek.gowitness import capture as gw_capture
from seek.nmap import export as exporter
from seek.nmap import presets as presets_mod
from seek.nmap.recent import text
from seek.nmap.runner import ScanRun, elevation_help, sudo_ready
from seek.nmap.session import Busy as SessionBusy
from seek.nmap.session import Event as SessionEvent
from seek.nmap.session import ScanError
from seek.paths import short_path
from seek.tui.menu import ChoiceScreen
from seek.tui.nmap.builder import BuilderScreen, ChooserScreen
from seek.tui.nmap.scope import CommandScreen, ReviewScreen, ScopeScreen


class ScanFlows:
    """The scan, capture and vulnerability-database flows of the nmap viewer."""

    def action_new_scan(self) -> None:
        self._start_scan_flow(None)

    @work(exclusive=True, group="modal")
    async def _start_scan_flow(self, targets: list[str] | None) -> None:
        """Scope → preset → command → review → run. Any step can back out.

        Without nmap, or with a scan running, the flow still reaches the
        review: starting is what is refused there, and the plan can be copied
        to a machine that can run it."""
        if targets is None:
            targets = await self.push_screen_wait(ScopeScreen())
            if not targets:
                return

        presets = self.config.nmap_presets
        scope_line = ", ".join(targets[:4]) + (" …" if len(targets) > 4 else "")
        recent, frequent = self.session.earlier_commands()
        name = await self.push_screen_wait(ChooserScreen(
            f"New scan · {len(targets)} target(s)", scope_line, presets, recent, frequent))
        if name is None:
            return

        try:
            if name == "@build":
                facts = await asyncio.to_thread(self.session.builder_facts, targets)
                built = await self.push_screen_wait(BuilderScreen(
                    facts, self.config.nmap_path, self.nmap.available))
                if built is None:
                    return
                profile, args, goal = built
                name = f"build {goal} {profile}"
                command, note, out_base = self.session.draft_args(name, text(args), targets)
            elif name.startswith("@"):
                section, _, index = name[1:].partition(":")
                earlier = (recent if section == "recent" else frequent)[int(index)]
                name = "earlier"
                command, note, out_base = self.session.draft_args(name, earlier.args, targets)
            else:
                command, note, out_base = self.session.draft_command(name, targets)
        except ScanError as exc:
            self.notify(str(exc), severity="error", timeout=12)
            return
        await self._command_review_run(name, command, note, out_base, targets)

    # --- the vulnerability database -----------------------------------------

    _vulndb_offered = False

    def _offer_vulndb(self) -> None:
        """Once per session, when the database is missing or stale: say so, and
        name the key. An offer, never a download - nothing is fetched unless the
        user presses `A` and then confirms what it will fetch."""
        if self._vulndb_offered or not self.is_running:
            return
        self._vulndb_offered = True
        if not self.session.vulndb_stale():
            return
        store = self.session.vulndb()
        what = ("No vulnerability database" if store.missing
                else f"The vulnerability database is {store.age_days():.0f} days old")
        self.notify(f"{what} - press A to download public NVD, OSV and endoflife.date data. "
                    "Nothing is fetched unless you confirm.", severity="warning", timeout=15)

    def action_update_vulndb(self) -> None:
        self._vulndb_flow()

    @work(exclusive=True, group="modal")
    async def _vulndb_flow(self) -> None:
        if self.session.vulndb_updating:
            answer = await self.push_screen_wait(ChoiceScreen(
                f"Updating the vulnerability database - {self.session.vulndb_progress}",
                [("keep", "keep going"),
                 ("cancel", "cancel the update (the data stays as it was)")]))
            if answer == "cancel":
                self.session.cancel_vulndb()
            return
        from seek.vulndb import update as vulndb_update

        store = self.session.vulndb()
        if store.missing:
            size = f"about {vulndb_update.FIRST_DOWNLOAD_ESTIMATE_MB} MB the first time"
            age = "there is none yet"
        else:
            size = "only what changed since the last update"
            age = f"it is {store.age_days():.0f} days old"
        answer = await self.push_screen_wait(ChoiceScreen(
            f"Update the vulnerability database? {age}. Downloads NVD CVE feeds, OSV npm "
            f"advisories and endoflife.date release data - {size}. Nothing about this "
            "engagement is sent.",
            [("update", "download and update now"), ("no", "not now")]))
        if answer == "update":
            self._run_vulndb_update()

    @work(thread=True, exclusive=True, group="vulndb")
    def _run_vulndb_update(self) -> None:
        def progress(*_args) -> None:
            self.call_from_thread(self._refresh_status)

        try:
            results = self.session.update_vulndb(progress)
        except SessionBusy as exc:
            self.call_from_thread(self.notify, str(exc), severity="warning")
            return
        self.call_from_thread(self._vulndb_done, results)

    def _vulndb_done(self, results: list) -> None:
        failed = [r for r in results if r.error]
        summary = ", ".join(f"{r.source} {_update_outcome(r)}" for r in results)
        self.notify(f"vulnerability database: {summary}",
                    severity="error" if failed else "information", timeout=12)
        self.session.emit(SessionEvent("vulndb", "tui", text=summary))

    def action_scan_unversioned(self) -> None:
        self._start_gap_scan()

    @work(exclusive=True, group="modal")
    async def _start_gap_scan(self) -> None:
        """`U`: version the open ports of the marks - or of the rows on screen -
        that no source has versioned, through the same command and review."""
        records, _source = self._export_source()
        try:
            # The inventory may be built here for the first time; that walks
            # every host, which is not work for the event loop.
            command, note, out_base, targets = await asyncio.to_thread(
                self.session.draft_version_gaps, records)
        except ScanError as exc:
            self.notify(str(exc), severity="warning", timeout=12)
            return
        await self._command_review_run(presets_mod.VERSION_GAPS_PRESET, command, note,
                                       out_base, targets)

    async def _command_review_run(self, name: str, command: str, note: str,
                                  out_base, targets: list[str]) -> None:
        """Command → review → run: the tail every scan flow shares."""
        while True:
            edited = await self.push_screen_wait(
                CommandScreen(f"Scan · {name}", command, note))
            if edited is None:
                return
            try:
                plan = self.session.plan_scan(name, edited, targets, out_base)
            except presets_mod.CommandError as exc:
                self.notify(str(exc), severity="error", timeout=10)
                command = edited
                continue
            break

        body = Text()
        body.append(" ".join(plan.argv[:2]) + " ", style="bold")
        body.append(" ".join(plan.argv[2:]) + "\n\n")
        body.append(f"  {'scope':<11}", style="dim")
        body.append(f"{len(plan.targets)} target(s): " + ", ".join(plan.targets[:4])
                    + (" …" if len(plan.targets) > 4 else "") + "\n")
        body.append(f"  {'writes':<11}", style="dim")
        body.append(f"{plan.out_base}.{{xml,nmap,gnmap}}\n")
        body.append(f"  {'privilege':<11}", style="dim")
        body.append({"sudo": "sudo (asks for a password here if it needs one) — ",
                     "capabilities": "nmap's own capabilities, --privileged — "}
                    .get(plan.via, "direct — "))
        body.append(plan.privilege or "no elevated flags")
        review = ReviewScreen(
            "Start this scan?", body, "start the scan", blocked=plan.blocked,
            copy_local=plan.copy_local, copy_remote=plan.copy_remote,
            results=f"run elsewhere: copy {plan.out_base.name}.{{xml,nmap,gnmap}} "
                    f"back into {short_path(self.scan_dir)}",
            notify_url=plan.notify_url, notify_progress=plan.notify_progress)
        if not await self.push_screen_wait(review):
            return
        run = plan.run()
        run.notify_url, run.notify_progress = review.notify_url, review.notify_progress
        if run.elevated and not await self._authorise(run):
            return
        self._run_scan(run)

    async def _authorise(self, run: ScanRun) -> bool:
        """Make sure `sudo -n` will run this scan, letting sudo ask if it must.

        sudo asks on the terminal itself, with the interface stepped aside:
        seek never sees the password. The scan then runs in this session, which
        is what lets that authorisation count for it.
        """
        problem = await sudo_ready(run.argv)
        if problem is None:
            return True
        if problem.startswith("sudo is not installed"):
            self.notify(f"{run.preset} needs root and {problem}. "
                        + elevation_help(self.config.nmap_path, terminal=True),
                        severity="error", timeout=20)
            return False
        try:
            with self.suspend():
                _sudo_validate(f"{run.preset} needs root ({' '.join(run.argv[2:4])} …)")
        except SuspendNotSupported:
            self.notify(elevation_help(self.config.nmap_path), severity="error", timeout=20)
            return False
        problem = await sudo_ready(run.argv)
        if problem is None:
            return True
        self.notify(f"{problem}. " + elevation_help(self.config.nmap_path, terminal=True),
                    severity="error", timeout=20)
        return False

    @work(group="scan")
    async def _run_scan(self, run: ScanRun) -> None:
        self._log_frozen = False
        self._report_mode = "raw"
        self.notify(f"started {run.preset}")
        try:
            await self.session.start_scan(run, origin="tui")
        except (SessionBusy, ScanError) as exc:
            self.notify(str(exc), severity="warning")

    # --- captures ----------------------------------------------------------

    def _capture_urls(self, records: list) -> list[str]:
        """The HTTP(S) URLs of a selection, fully qualified.

        `export_urls` is reused rather than reimplemented: it already emits one
        URL per open HTTP service *and* per name the host answers to, carrying
        a scheme and an explicit port. That form is what stops gowitness
        deriving its own candidates, so the list that is written is the list
        that gets probed.
        """
        return exporter.export_urls(records)

    @work(exclusive=True, group="capture")
    async def _start_capture(self, records: list) -> None:
        """Review a capture of the selection, if there is anything to capture,
        and run it on confirmation - or copy it to run elsewhere."""
        try:
            run = self.session.plan_capture(records)
        except ScanError as exc:
            self.notify(str(exc), severity="warning", timeout=12)
            return
        body = Text()
        body.append(" ".join(run.argv[:3]) + " …\n\n", style="bold")
        body.append(f"  {'urls':<11}", style="dim")
        body.append(f"{len(run.urls)}: " + ", ".join(run.urls[:3])
                    + (" …" if len(run.urls) > 3 else "") + "\n")
        body.append(f"  {'writes':<11}", style="dim")
        body.append(f"{short_path(run.paths.root)}\n")
        body.append(f"  {'backend':<11}", style="dim")
        body.append(run.backend or "none here")
        review = ReviewScreen(
            "Start this capture?", body, "start the capture", blocked=run.blocked,
            copy_local=run.copy_local, copy_remote=run.copy_remote,
            results="run elsewhere: copy its gowitness/ directory back into "
                    f"{short_path(self.scan_dir)}",
            notify_url=run.notify_url, notify_progress=run.notify_progress)
        if await self.push_screen_wait(review):
            run.notify_url, run.notify_progress = review.notify_url, review.notify_progress
            await self._run_capture(run)

    async def _run_capture(self, run: gw_capture.CaptureRun) -> None:
        self._log_frozen = False
        self._report_mode = "raw"
        self.notify(f"capturing {run.scope} with gowitness ({run.backend})")
        # Shown as soon as it is listed rather than when it first speaks: a
        # container backend pulls its image before the tool runs at all, and a
        # capture that is nowhere in the Scans tab for the first few minutes
        # looks like a capture that never started.
        try:
            await self.session.start_capture(run, origin="tui")
        except (SessionBusy, ScanError) as exc:
            self.notify(str(exc), severity="warning")


def _sudo_validate(why: str) -> None:
    """Say why, then let sudo ask for the password on the terminal - a module
    function so tests can replace it (and its text) without patching
    `subprocess` or the terminal."""
    print(f"\nseek: {why}.\nsudo asks for your password; seek never sees it.\n", flush=True)
    subprocess.run(["sudo", "-v"], check=False)  # noqa: S603, S607 - fixed argv


def _update_outcome(result) -> str:
    if result.error:
        return f"failed: {result.error}"
    return "unchanged" if result.skipped else f"{result.records} records"
