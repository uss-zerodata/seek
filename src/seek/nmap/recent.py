"""Commands used before: from this session's scan files, and from a history of
arguments kept in the state directory.

**A target is never kept.** A command is reduced to its arguments before it is
stored or shown: the program, every target, the options seek controls (output
files, the target input), `--exclude`/`--excludefile` and their values all go.
Telling an option's value from a target needs to know which options take one -
`--script vuln` keeps `vuln`, `-sS 10.0.0.5` drops the address - and that
knowledge is `seek.nmap.options`, the catalogue the builder uses, so the two
cannot disagree. An option the catalogue does not know is assumed to take no
value, and the token after it is then dropped if it looks like a target: the
rule errs towards forgetting an argument, never towards storing a target.

The history file is the viewer's one exception to "nothing written but an
explicit export": it records the user's habits, not the engagement.
"""

from __future__ import annotations

import json
import re
import shlex
import time
from dataclasses import dataclass
from pathlib import Path

from seek.nmap import options
from seek.nmap.presets import PORTS_PLACEHOLDER

LIMIT = 200          # commands the history keeps; the least recently used goes
SHOWN = 5            # per list in the chooser
_DROPPED = {"--exclude", "--excludefile"}


def strip(argv: list[str]) -> list[str]:
    """The arguments of a command, with no target, path or output option."""
    tokens = list(argv)
    if tokens[:2] == ["sudo", "-n"]:
        tokens = tokens[2:]
    elif tokens[:1] == ["sudo"]:
        tokens = tokens[1:]
    if tokens and not tokens[0].startswith("-"):
        tokens = tokens[1:]                    # the program
    kept: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        index += 1
        found = options.lookup(token)
        if found is None:
            if len(options.expand(token)) > 1:   # -sUV
                kept.append(token)
            elif token.startswith("-") and token != "-":
                kept.append(token)             # unknown: assumed to take no value
            continue                           # anything else is a target
        option, _value, takes_next = found
        value = None
        if takes_next and index < len(tokens):
            value = tokens[index]
            index += 1
        if option.owner or option.name in _DROPPED:
            continue
        kept.append(token)
        if value is not None:
            kept.append(value)
    return kept


_PLAIN = re.compile(r"[\w@%+=:,./{}-]+")


def text(args: list[str]) -> str:
    """One line, quoted only where a token needs it - `{ports}` stays bare."""
    return " ".join(a if _PLAIN.fullmatch(a) else shlex.quote(a) for a in args)


@dataclass(frozen=True, slots=True)
class Earlier:
    """One command used before, as the chooser lists it."""

    args: str
    where: str                 # "this engagement" or "history"
    last: float | None         # when it was last used, epoch seconds
    count: int


class CommandHistory:
    """`{args: {"count": n, "last": epoch}}` in a JSON file, capped at `LIMIT`."""

    def __init__(self, path: Path | None) -> None:
        self.path = path
        self.entries: dict[str, dict] = {}
        if path is not None:
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
                self.entries = {k: v for k, v in raw.get("commands", {}).items()
                                if isinstance(v, dict)}
            except (OSError, ValueError, AttributeError):
                self.entries = {}

    @classmethod
    def default(cls) -> CommandHistory:
        from seek.paths import state_dir
        return cls(state_dir() / "nmap-commands.json")

    def record(self, argv: list[str], when: float | None = None) -> str | None:
        """Remember a command's arguments - never its targets."""
        args = strip(argv)
        if not args:
            return None
        key = text(args)
        entry = self.entries.setdefault(key, {"count": 0, "last": 0.0})
        entry["count"] = int(entry.get("count", 0)) + 1
        entry["last"] = when if when is not None else time.time()
        if len(self.entries) > LIMIT:
            oldest = sorted(self.entries, key=lambda k: self.entries[k].get("last", 0))
            for gone in oldest[:len(self.entries) - LIMIT]:
                del self.entries[gone]
        self._write()
        return key

    def _write(self) -> None:
        if self.path is None:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps({"commands": self.entries}, indent=1),
                                 encoding="utf-8")
        except OSError:
            pass


def _restore_ports(args: str, known_ports: str) -> str:
    """`-p 22,80,443` back to `-p{ports}` when it is exactly the known open
    ports, so a version scan reused later scans what is open *then*."""
    if not known_ports:
        return args
    tokens = shlex.split(args)
    out: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "-p" and index + 1 < len(tokens) and tokens[index + 1] == known_ports:
            out.append(f"-p{PORTS_PLACEHOLDER}")
            index += 2
            continue
        out.append(f"-p{PORTS_PLACEHOLDER}" if token == f"-p{known_ports}" else token)
        index += 1
    return text(out)


def _collect(files, history: CommandHistory | None) -> dict[str, Earlier]:
    seen: dict[str, Earlier] = {}
    for scan in files or []:
        if not getattr(scan, "args", ""):
            continue
        try:
            argv = shlex.split(scan.args)
        except ValueError:
            continue
        args = text(strip(argv))
        if not args:
            continue
        before = seen.get(args)
        when = float(scan.start) if scan.start else None
        if before is None:
            seen[args] = Earlier(args, "this engagement", when, 1)
        else:
            last = max(filter(None, (before.last, when)), default=None)
            seen[args] = Earlier(args, before.where, last, before.count + 1)
    for args, entry in (history.entries if history else {}).items():
        before = seen.get(args)
        last, count = float(entry.get("last") or 0) or None, int(entry.get("count", 0))
        if before is None:
            seen[args] = Earlier(args, "history", last, count)
        else:
            seen[args] = Earlier(args, before.where,
                                 max(filter(None, (before.last, last)), default=None),
                                 before.count + count)
    return seen


def recent(files, history: CommandHistory | None, known_ports: str = "",
           limit: int = SHOWN) -> list[Earlier]:
    """Newest first: this session's scans and the history together."""
    found = sorted(_collect(files, history).values(), key=lambda e: e.last or 0, reverse=True)
    return [_with_ports(e, known_ports) for e in found[:limit]]


def frequent(files, history: CommandHistory | None, known_ports: str = "",
             limit: int = SHOWN) -> list[Earlier]:
    """Most used first; a tie goes to the more recent."""
    found = sorted(_collect(files, history).values(),
                   key=lambda e: (e.count, e.last or 0), reverse=True)
    return [_with_ports(e, known_ports) for e in found[:limit]]


def _with_ports(earlier: Earlier, known_ports: str) -> Earlier:
    restored = _restore_ports(earlier.args, known_ports)
    if restored == earlier.args:
        return earlier
    return Earlier(restored, earlier.where, earlier.last, earlier.count)
