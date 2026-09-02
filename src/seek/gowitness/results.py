"""What a capture found, read back and indexed by URL.

The results file is JSON Lines: one object per captured target. Parsing that
rather than the SQLite database is deliberate - the database schema is
gorm-generated and an implementation detail of gowitness, while the JSONL shape
is its documented output contract.

**A malformed line is skipped, not fatal.** A capture of two hundred URLs that
ends with a half-written line - the process killed, the disk full - still knows
about the hundred and ninety-nine that came before it, and throwing them away
because of the last one would lose exactly the work the operator waited for.

**Failures come from the run, not from here.** gowitness writes no record at all
for a target it could not load, so a failed capture is knowable only while the
run's log is in hand (see `capture.CaptureRun.failures`). Reading a capture
directory left by someone else therefore yields successes only, and the absence
of a URL here is not evidence that it succeeded.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class Capture:
    """One captured URL: what answered, and where the picture of it is."""

    url: str
    final_url: str = ""
    status: int | None = None
    reason: str = ""
    title: str = ""
    protocol: str = ""
    server: str = ""
    technologies: list[str] = field(default_factory=list)
    tls: str = ""
    shot: Path | None = None
    failure: str = ""

    @property
    def failed(self) -> bool:
        return bool(self.failure)

    @property
    def redirected(self) -> bool:
        """Whether the final URL is somewhere other than the one asked for."""
        return bool(self.final_url) and self.final_url.rstrip("/") != self.url.rstrip("/")

    def summary(self) -> str:
        """The one-line description shown under its URL in a record."""
        if self.failed:
            return self.failure
        bits = [f"{self.status} {self.reason}".strip() if self.status else "no status"]
        if self.title:
            bits.append(self.title)
        if self.server:
            bits.append(self.server)
        if self.technologies:
            bits.append(", ".join(self.technologies))
        return " · ".join(bits)


def _server(headers: object) -> str:
    """The `Server` header, matched case-insensitively.

    gowitness lowercases header names on the way out, so looking for `Server`
    as written finds nothing - a trap worth one line of defence.
    """
    if not isinstance(headers, list):
        return ""
    for header in headers:
        if isinstance(header, dict) and str(header.get("key", "")).lower() == "server":
            return str(header.get("value", ""))
    return ""


def _tls(raw: object) -> str:
    """A one-line TLS summary, empty when the probe was not over TLS."""
    if not isinstance(raw, dict):
        return ""
    protocol = str(raw.get("protocol") or "")
    if not protocol:
        return ""
    bits = [protocol]
    if cipher := raw.get("cipher"):
        bits.append(str(cipher))
    if issuer := raw.get("issuer"):
        bits.append(f"issued by {issuer}")
    if until := raw.get("valid_to"):
        bits.append(f"until {str(until)[:10]}")
    return " · ".join(bits)


def _technologies(raw: object) -> list[str]:
    """gowitness writes `null` here, not `[]`, when it detected none."""
    if not isinstance(raw, list):
        return []
    return [str(t.get("value", "")) for t in raw
            if isinstance(t, dict) and t.get("value")]


def from_record(raw: dict, shots: Path | None = None) -> Capture:
    """One JSONL object as a `Capture`."""
    name = str(raw.get("file_name") or "")
    return Capture(
        url=str(raw.get("url") or ""),
        final_url=str(raw.get("final_url") or ""),
        status=raw.get("response_code") if isinstance(
            raw.get("response_code"), int) else None,
        reason=str(raw.get("response_reason") or ""),
        title=str(raw.get("title") or ""),
        protocol=str(raw.get("protocol") or ""),
        server=_server(raw.get("headers")),
        technologies=_technologies(raw.get("technologies")),
        tls=_tls(raw.get("tls")),
        shot=(shots / name) if (name and shots is not None) else None,
        # Present in the schema, and populated for a target that answered
        # badly rather than not at all - kept for that case.
        failure=str(raw.get("failed_reason") or "") if raw.get("failed") else "",
    )


def read_jsonl(path: Path, shots: Path | None = None) -> tuple[list[Capture], list[str]]:
    """Every capture in a results file, and a note for every line that was not.

    Returns `(captures, problems)`; a missing file is simply no captures, since
    a project that has never been captured is the ordinary case, not an error.
    """
    if not path.exists():
        return [], []
    captures: list[Capture] = []
    problems: list[str] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [], [f"{path.name}: {exc.strerror or exc}"]
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except ValueError as exc:
            problems.append(f"{path.name} line {number}: {exc}")
            continue
        if not isinstance(raw, dict) or not raw.get("url"):
            problems.append(f"{path.name} line {number}: not a capture record")
            continue
        captures.append(from_record(raw, shots))
    return captures, problems


class Captures:
    """Every capture known, indexed by the URL it was taken for.

    One URL can have been captured more than once - a second run over the same
    scope - and the newest wins, because that is what the operator just did.
    """

    def __init__(self, captures: Iterable[Capture] = ()) -> None:
        self._by_url: dict[str, Capture] = {}
        self.problems: list[str] = []
        self.add(captures)

    def __len__(self) -> int:
        return len(self._by_url)

    def __bool__(self) -> bool:
        return bool(self._by_url)

    def add(self, captures: Iterable[Capture]) -> None:
        for capture in captures:
            self._by_url[capture.url] = capture

    def add_failures(self, failures: dict[str, str]) -> None:
        """Record what a run could not capture - the only source there is."""
        for url, reason in failures.items():
            self._by_url[url] = Capture(url=url, failure=reason)

    def get(self, url: str) -> Capture | None:
        return self._by_url.get(url)

    def for_urls(self, urls: Iterable[str]) -> list[Capture]:
        """The captures for these URLs, in the order given, skipping unknowns."""
        out = []
        for url in urls:
            found = self._by_url.get(url)
            if found is not None:
                out.append(found)
        return out

    def load(self, path: Path, shots: Path | None = None) -> None:
        captures, problems = read_jsonl(path, shots)
        self.add(captures)
        self.problems.extend(problems)
