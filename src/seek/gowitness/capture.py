"""One gowitness capture: where it writes, what it is told, how it reports.

The supervision is `seek.runner`'s, shared with nmap. What is here is what is
true of gowitness and of nothing else.

**Targets are sent fully qualified, and gowitness is told nothing else.**
Measured against v3: `scan file` prepends both `http://` and `https://` to a
target with no scheme and crosses that with `--port` (default 80 and 443), so
two bare names produced seven probes. A URL carrying a scheme *and* an explicit
port is probed exactly once. The viewer already knows which ports are open and
which names a host answers to - `export_urls` emits exactly that form - so
sending complete URLs both avoids guessed probes and makes every result
attributable to one service.

**Both writers are on.** `--write-jsonl` is the parsing contract: one JSON
object per result, documented and stable. `--write-db` is for `gowitness report
server`, and because an externally run capture would have left one. `--skip-html`
and `--skip-network-logs` keep the results file to a readable size - `html`
carries the whole response body per result, and nothing shown needs it.

**A failure is not a result, so `--log-scan-errors` is not optional.** Measured
against v3: a target that cannot be loaded writes **no JSONL record at all**,
and without this flag it produces no output whatsoever - the run simply says
less than it did about the targets that worked, and a host that refused looks
identical to one that was never asked. The `failed` / `failed_reason` fields
exist in the schema but are not what the tool populates for an unreachable
target. Failures are therefore recovered from the log line the flag turns on:

    ERRO failed to witness target target=http://10.0.0.1:81 err="page load error …"

which is also why the progress counter has to count two different lines to
know how many targets are done.

**The screenshot waits for the page, not for a clock.** A fixed `--delay`
photographs a slow page half drawn and makes a fast one wait for nothing.
gowitness has no wait-for-load flag, but `--javascript` runs a function before
the screenshot, and measured against 3.2.2 the `gorod` driver awaits the promise
it returns - the default `chromedp` driver does not (0.7 s for a promise of
8 s), and neither does `--javascript-file` under either driver. So the capture
runs `--driver gorod` with `settle_script` inline. It resolves when
the document is complete, every image has arrived, and nothing has changed in
the page or finished downloading for the quiet window - or at the cap. One
blind spot, and it is the platform's: a page cannot see a request still in
flight, so one that is silent for longer than the quiet window before a single
late response is photographed early; the quiet window is the knob for that.
`gorod` without a script does not wait for navigation at all (it records
`about:blank` as the title), so the driver and the script travel together:
`settle_ms=0` puts back `chromedp` and the fixed delay.

A page that redirects itself as it loads (`location.replace`, as a NAS login
does) destroys the page the script runs in; gowitness logs "Inspected target
navigated or closed" and photographs at once - a blank page. `--delay` runs
before the script, so `settle_delay_s` (default 1 s) lets the redirect finish
first. Measured against a real dashboard: 0 s gives a blank page, 1 s the login.

**One argv, two backends.** The container sees `/data` where the host sees the
capture directory, so the only difference between the two commands is that
prefix and the `docker run` preamble. Keeping that in one function is what stops
the translation leaking into every flag.
"""

from __future__ import annotations

import contextlib
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from seek.gowitness.detect import Probe
from seek.gowitness.results import canonical_url
from seek.runner import Run, State

CAPTURE_DIRNAME = "gowitness"
"""Captures live beside the scans, in their own directory, exactly as an
externally run capture would have been asked to write them."""

URLS_NAME = "urls.txt"
DB_NAME = "gowitness.sqlite3"
JSONL_NAME = "gowitness.jsonl"
SHOTS_NAME = "screenshots"

_MOUNT = "/data"
"""Where the capture directory is mounted inside the container."""

# One of these per finished target - the first when it was reached, the second
# when it was not. Both are needed: they are the only two ways a target ends.
_RESULT = re.compile(r"\bINFO\b.*\bresult\b.*\btarget=(\S+)")
# Trailing "see the help" pointers: always last, never the reason.
_NOISE = re.compile(r"^\s*(run|see) ['\"`]?\S+.*(--help|help\b).*", re.I)

_FAILURE = re.compile(r'failed to witness target\s+target=(\S+)\s+err="?(.*?)"?\s*$')


@dataclass
class Paths:
    """Where a capture's artefacts live, from the host's point of view."""

    root: Path
    # A capture this app runs always writes `gowitness.sqlite3`; one found on
    # disk may have been written under any name (`--write-db-uri`).
    db_name: str = DB_NAME

    @property
    def urls(self) -> Path:
        return self.root / URLS_NAME

    @property
    def db(self) -> Path:
        return self.root / self.db_name

    @property
    def jsonl(self) -> Path:
        return self.root / JSONL_NAME

    @property
    def shots(self) -> Path:
        return self.root / SHOTS_NAME


def from_disk(paths: Paths, urls: list[str], captured: int, where: str = "") -> CaptureRun:
    """A finished capture that this session did not run.

    The Scans tab lists what is on disk whoever produced it - the same
    principle the scan history follows for nmap files. A capture leaves a
    database and screenshots but no log, so this run carries its counts and
    says plainly that its output was not recorded here.
    """
    when = ""
    with contextlib.suppress(OSError):
        when = datetime.fromtimestamp(paths.db.stat().st_mtime).strftime("%m-%d %H:%M")
    run = CaptureRun(argv=[], paths=paths, urls=urls, backend="on disk",
                     captured=captured, recorded=when, where=where)
    run.state = State.DONE
    run.ended = run.started
    run.result = run.summarise()
    return run


def capture_dir(scan_dir: Path) -> Paths:
    """The capture directory under the directory scans are written to.

    **Resolved to an absolute path, always.** The viewer is usually opened on a
    relative directory (`seek nmap test_scans`), and docker reads a relative
    `-v` source as a *named volume* rather than a host directory - it refuses
    the run with "includes invalid characters for a local volume name" and a
    pointer to `docker run --help`, which reads as the app having built a
    broken command. Resolving here rather than at the mount means the database,
    the screenshots and the URL file are absolute for every consumer, including
    the report server and the image viewer.
    """
    return Paths((Path(scan_dir) / CAPTURE_DIRNAME).resolve())


def write_urls(paths: Paths, urls: list[str]) -> Path:
    """Lay the target list down where the capture will read it.

    Written with the port made explicit. A URL properly omits its default port,
    but gowitness crosses a port-less target with its whole port set: two such
    URLs measured as four probes, each recorded under a port the URL never
    carried. Spelling the port out means one probe per open port the scan
    actually found, and a result recorded under the address it was asked for.
    """
    paths.root.mkdir(parents=True, exist_ok=True)
    paths.shots.mkdir(parents=True, exist_ok=True)
    written = list(dict.fromkeys(canonical_url(u) for u in urls))
    paths.urls.write_text("\n".join(written) + "\n", encoding="utf-8")
    return paths.urls


def settle_script(quiet_ms: int, cap_ms: int) -> str:
    """The function gowitness evaluates before a screenshot: a promise that
    resolves once the page has loaded and been still for `quiet_ms`, or after
    `cap_ms` whatever the page is doing. One line - it travels in the argv."""
    return (
        "() => new Promise((done) => {"
        f" const quiet = {int(quiet_ms)}, cap = {int(cap_ms)}, start = performance.now();"
        " let last = start; const seen = () => { last = performance.now(); };"
        " new MutationObserver(seen).observe(document,"
        " { subtree: true, childList: true, attributes: true, characterData: true });"
        ' try { new PerformanceObserver(seen).observe({ type: "resource" }); } catch (_) {}'
        ' const loaded = () => document.readyState === "complete"'
        " && [...document.images].every((i) => i.complete);"
        " const tick = () => { const now = performance.now();"
        " if (now - start >= cap || (loaded() && now - last >= quiet)) done();"
        " else setTimeout(tick, 100); };"
        " tick(); })"
    )


def scan_argv(probe: Probe, paths: Paths, *, chrome_path: str = "",
              collect_all: bool = True,
              threads: int = 6, timeout: int = 30, delay: int = 3,
              settle_ms: int = 2000, settle_cap_ms: int = 20000,
              settle_delay_s: int = 1) -> list[str]:
    """The command that captures `paths.urls`, for whichever backend is in use."""
    seen = _MOUNT if probe.backend == "docker" else str(paths.root)
    if settle_ms > 0:
        # The page's own wait must fit inside gowitness's: a timeout shorter
        # than the delay and the cap would fail the very pages the cap exists for.
        timeout = max(timeout, settle_delay_s + -(-settle_cap_ms // 1000) + 10)
        # gowitness sleeps `--delay` before it runs the script, so a page that
        # redirects itself on load has done so by then; the script would
        # otherwise die with the page it was started in, and gowitness takes
        # the screenshot at once - of a blank page.
        waiting = ["--driver", "gorod", "--delay", str(settle_delay_s),
                   "--javascript", settle_script(settle_ms, settle_cap_ms)]
    else:
        waiting = ["--delay", str(delay)]
    flags = [
        "scan", "file",
        "-f", f"{seen}/{URLS_NAME}",
        "--write-db", "--write-db-uri", f"sqlite://{seen}/{DB_NAME}",
        "--screenshot-path", f"{seen}/{SHOTS_NAME}",
        # Not optional: without it an unreachable target is silent in every
        # output the tool has, and "refused" becomes indistinguishable from
        # "never asked".
        "--log-scan-errors",
        "--threads", str(threads),
        "--timeout", str(timeout),
        *waiting,
    ]
    if not collect_all:
        # `html` carries a whole response body per result and the network log a
        # row per request; gowitness's own help warns this can make storage
        # explode. Collection only - a database recorded either way reads the
        # same.
        flags += ["--skip-html", "--skip-network-logs"]
    if chrome_path:
        flags += ["--chrome-path", chrome_path]
    if probe.backend == "docker":
        return [probe.path or "docker", "run", "--rm",
                "-v", f"{paths.root}:{_MOUNT}", "-w", _MOUNT,
                probe.image or "", *flags]
    return [probe.path or "gowitness", *flags]


def report_argv(probe: Probe, paths: Paths, host: str, port: int) -> list[str]:
    """The command that serves a finished capture's own database."""
    seen = _MOUNT if probe.backend == "docker" else str(paths.root)
    flags = [
        "report", "server",
        "--db-uri", f"sqlite://{seen}/{DB_NAME}",
        "--screenshot-path", f"{seen}/{SHOTS_NAME}",
        "--host", "0.0.0.0" if probe.backend == "docker" else host,  # noqa: S104
        "--port", str(port),
    ]
    if probe.backend == "docker":
        # Published rather than --network=host: the bind stays on the host's
        # loopback, which is what the configuration asked for, without giving
        # the container the host's whole network namespace.
        return [probe.path or "docker", "run", "--rm",
                "-v", f"{paths.root}:{_MOUNT}", "-w", _MOUNT,
                "-p", f"{host}:{port}:{port}",
                probe.image or "", *flags]
    return [probe.path or "gowitness", *flags]


@dataclass
class CaptureRun(Run):
    """One capture: the URLs asked for, what came back, what became of it."""

    paths: Paths = field(default_factory=lambda: Paths(Path()))
    urls: list[str] = field(default_factory=list)
    backend: str = ""
    captured: int = 0
    # Set only for a capture read back from disk rather than run here: the run
    # list shows this instead of an elapsed time, because "00:00" for something
    # that finished last week is a lie, and there is no log to time.
    recorded: str = ""
    # url -> why it could not be captured. Kept here because it is the only
    # place it exists: the results file has no line for a failed target.
    failures: dict[str, str] = field(default_factory=dict)
    # Which directory's capture this is, when the viewer was opened on several
    # and "capture" alone would list two runs under one name.
    where: str = ""
    # Set on a plan only: why it cannot start here, and the two copy forms.
    blocked: str | None = None
    copy_local: str | None = None
    copy_remote: str = ""

    @property
    def failed(self) -> int:
        return len(self.failures)

    @property
    def label(self) -> str:
        return f"capture · {self.where}" if self.where else "capture"

    @property
    def scope(self) -> str:
        count = len(self.urls)
        return f"{count} url{'s' if count != 1 else ''}"

    @property
    def total(self) -> int:
        return len(self.urls)

    def read_progress(self, line: str) -> None:
        failure = _FAILURE.search(line)
        if failure is not None:
            self.failures[failure.group(1)] = failure.group(2).strip() or "failed"
            return
        if _RESULT.search(line):
            self.captured += 1

    @property
    def notify_name(self) -> str:
        # `label` carries the directory name, which may name the engagement.
        return "gowitness capture"

    def fraction(self) -> float | None:
        return self.finished / self.total if self.total else None

    @property
    def finished(self) -> int:
        """Targets that ended, either way."""
        return self.captured + self.failed

    def progress(self) -> str:
        if not self.total:
            return "running"
        return f"{self.finished}/{self.total} captured"

    def summarise(self) -> str:
        text = f"{self.captured} captured"
        if self.failed:
            text += f", {self.failed} failed"
        return text

    def failure(self, code: int, tail: list[str]) -> str:
        if self.finished:
            # A capture that got some way in and then died has more to say than
            # its last line: what it managed is the useful half.
            return f"{self.summarise()}, then failed: {self._why(code, tail)}"
        return self._why(code, tail)

    def _why(self, code: int, tail: list[str]) -> str:
        """The most informative line, not simply the last one.

        A tool that refuses its own command line prints the reason and *then* a
        pointer to its help, so the last line is the least useful thing it
        said - `Run 'docker run --help' for more information` in place of the
        line above it explaining what was actually wrong.
        """
        useful = [line for line in tail if not _NOISE.search(line)]
        return super().failure(code, useful or tail)
