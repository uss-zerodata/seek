"""Owner of the tag files: finding them, reading them in order of precedence, and
writing seek's own.

Two kinds of file, in any folder below the opened ones and once in the config
directory:

- `seek-rules.yaml` (`rules.yaml` globally) is written by a person. seek reads
  it and never writes it - rewriting YAML loses its comments.
- `seek-tags.yaml` (`tags.yaml` globally) is written by seek: manual tags
  (`entries:`) and the definitions made in the viewer. A person may edit it;
  seek keeps every value it does not understand, but not comments.

Everything else - what a rule means, what a tag file says - is `tagrules`'s.
This module is the one place a tag file is opened (design D8, D9).
"""

from __future__ import annotations

import contextlib
import ipaddress
import os
import socket
import tempfile
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path

import yaml

from seek.gowitness.locate import files_below
from seek.nmap import tagrules as tr

RULES_NAMES = ("seek-rules.yaml", "seek-rules.yml")
TAGS_NAME = "seek-tags.yaml"
GLOBAL_RULES = "rules.yaml"
GLOBAL_TAGS = "tags.yaml"
HEADER = "# Written by seek. Edits to values are kept; comments are not.\n"
# How long a writer waits for another writer's lock, and when a lock is taken
# to be left behind by a writer that died. A write takes milliseconds.
LOCK_WAIT = 2.0
LOCK_STALE = 30.0
LOCK_POLL = 0.05
FILE_MODE = 0o644


class Kind(StrEnum):
    RULES = "rules"      # a person's file; read only
    TAGS = "tags"        # seek's file; read and written


@dataclass(frozen=True, slots=True)
class TagFile:
    path: Path
    kind: Kind
    # The folder whose scans the file belongs to; None for the global files,
    # which rank below every project file.
    scope: Path | None


@dataclass(frozen=True, slots=True)
class Entry:
    """One manual tag: on a host, or on one service of it."""
    tag: str
    host: str
    protocol: str | None = None
    port: int | None = None
    added: str = ""

    @property
    def key(self) -> tuple[str, str, str | None, int | None]:
        return (self.tag, self.host, self.protocol, self.port)

    @property
    def subject(self) -> tuple:
        """What it tags: `(address,)` or `(address, protocol, port)` - the
        identity a record has (`export.Record.identity`)."""
        return (self.host,) if self.port is None else (self.host, self.protocol, self.port)


@dataclass(frozen=True, slots=True)
class Loaded:
    """Every tag file as read, merged by precedence. Immutable: a reload makes a
    new one, so a reader never sees half of each."""
    files: tuple[TagFile, ...] = ()
    tags: dict[str, tr.TagDef] = field(default_factory=dict)
    order: tuple[str, ...] = ()
    disabled: dict[str, tr.Problem] = field(default_factory=dict)
    entries: dict[Path, tuple[Entry, ...]] = field(default_factory=dict)
    problems: tuple[tr.Problem, ...] = ()
    stamps: dict[Path, tuple[int, int]] = field(default_factory=dict)

    @property
    def all_entries(self) -> tuple[Entry, ...]:
        return tuple(e for es in self.entries.values() for e in es)


class TagWriteError(Exception):
    """A tag could not be saved. The message is for the user, and says why."""


# --- finding -------------------------------------------------------------------------


def _kind(name: str, global_dir: bool) -> Kind | None:
    if global_dir:
        return {GLOBAL_RULES: Kind.RULES, GLOBAL_TAGS: Kind.TAGS}.get(name)
    return Kind.RULES if name in RULES_NAMES else Kind.TAGS if name == TAGS_NAME else None


def find(sources: Iterable[Path], config_dir: Path | None) -> tuple[TagFile, ...]:
    """Every tag file for these sources, each once, in a stable order.

    A folder is searched all the way down by the scan search's rules (dot and
    symlinked folders skipped); a file named directly makes its own folder be
    looked in, without descending. The global files come last.
    """
    seen: dict[Path, TagFile] = {}

    def take(path: Path, scope: Path | None) -> None:
        kind = _kind(path.name, scope is None)
        if kind is None:
            return
        with contextlib.suppress(OSError):
            key = path.resolve()
            if key not in seen and path.is_file():
                seen[key] = TagFile(path, kind, scope)

    for source in sources:
        source = Path(source)
        if source.is_dir():
            for path in files_below(source):
                take(path, _resolved(path.parent))
        else:
            folder = source.parent
            for name in (*RULES_NAMES, TAGS_NAME):
                take(folder / name, _resolved(folder))
    if config_dir is not None:
        for name in (GLOBAL_RULES, GLOBAL_TAGS):
            take(config_dir / name, None)
    return tuple(sorted(seen.values(), key=lambda f: (f.scope is None, str(f.path))))


def _resolved(path: Path) -> Path:
    try:
        return path.resolve()
    except OSError:
        return path.absolute()


def home(sources: list[Path]) -> Path | None:
    """Where manual tags are written: the first opened folder, or the folder of
    the first opened file."""
    for source in sources:
        source = Path(source)
        return source if source.is_dir() else source.parent
    return None


# --- reading ---------------------------------------------------------------------


def _stamp(path: Path) -> tuple[int, int]:
    try:
        st = path.stat()
        return (st.st_mtime_ns, st.st_size)
    except OSError:
        return (0, -1)


def changed(loaded: Loaded, files: tuple[TagFile, ...]) -> bool:
    """Whether a file appeared, went away or changed since `loaded` was read."""
    if {f.path for f in files} != {f.path for f in loaded.files}:
        return True
    return any(_stamp(f.path) != loaded.stamps.get(f.path) for f in files)


def read_text(path: Path) -> str:
    """The text of a tag file. Raises OSError, which the caller turns into a problem."""
    return path.read_text(encoding="utf-8")


def canonical_address(text: str) -> str:
    try:
        return ipaddress.ip_address(text.strip()).compressed
    except ValueError:
        return text.strip()


def parse_entries(doc: dict, path: str) -> tuple[tuple[Entry, ...], list[tr.Problem]]:
    raw = doc.get("entries", [])
    if raw is None:
        return (), []
    if not isinstance(raw, list):
        return (), [tr.Problem("`entries:` must be a list", tr.Source(path, tr._line(doc)))]
    out: list[Entry] = []
    problems: list[tr.Problem] = []
    for item in raw:
        line = tr._line(item, tr._line(raw))
        try:
            out.append(entry_from(item, line))
        except tr.RuleError as exc:
            problems.append(tr.Problem(f"manual tag left out: {exc}", tr.Source(path, exc.line)))
    return tuple(dict.fromkeys(out)), problems


def entry_from(item, line: int | None = None) -> Entry:
    if not isinstance(item, dict):
        raise tr.RuleError("a manual tag is `{tag: name, host: address}`", line)
    tr._only(item, {"tag", "host", "port", "added"}, "manual tag", line)
    if "tag" not in item or "host" not in item:
        raise tr.RuleError("a manual tag needs `tag:` and `host:`", line)
    tag = tr.tag_name(item["tag"], line)
    host = canonical_address(tr._text(item["host"], "a host", line))
    protocol, port = None, None
    if "port" in item:
        ports, protocol = tr._port(item["port"], line)
        if len(ports) != 1 or ports[0][0] != ports[0][1]:
            raise tr.RuleError("a manual tag names one port, such as 443/tcp", line)
        port = ports[0][0]
        if protocol is None:
            raise tr.RuleError("a manual tag's port needs its protocol, such as 443/tcp", line)
    added = item.get("added", "")
    return Entry(tag, host, protocol, port, str(added) if added else "")


def load(files: tuple[TagFile, ...]) -> Loaded:
    """Read every file; merge definitions by precedence; never raise."""
    problems: list[tr.Problem] = []
    per_file: list[tuple[TagFile, dict[str, tr.TagDef]]] = []
    entries: dict[Path, tuple[Entry, ...]] = {}
    stamps: dict[Path, tuple[int, int]] = {}
    for f in files:
        stamps[f.path] = _stamp(f.path)
        try:
            text = read_text(f.path)
        except (OSError, UnicodeDecodeError) as exc:
            problems.append(tr.Problem(f"could not be read: {exc}", tr.Source(str(f.path))))
            continue
        doc, defs = tr.load(text, str(f.path))
        problems.extend(defs.problems)
        if doc is None:
            continue
        per_file.append((f, defs.tags))
        if f.kind is Kind.TAGS:
            found, bad = parse_entries(doc, str(f.path))
            problems.extend(bad)
            if found:
                entries[f.path] = found
    tags, merge_problems = merge(per_file)
    problems.extend(merge_problems)
    order, disabled = tr.order(tags)
    problems.extend(dict.fromkeys(disabled.values()))
    return Loaded(files, tags, order, disabled, entries, tuple(problems), stamps)


# --- precedence --------------------------------------------------------------------


def _below(a: TagFile, b: TagFile) -> bool:
    """Is `a` more specific than `b`: in a folder below b's, or a project file
    where `b` is global?"""
    if b.scope is None:
        return a.scope is not None
    if a.scope is None:
        return False
    return a.scope != b.scope and a.scope.is_relative_to(b.scope)


def merge(per_file: list[tuple[TagFile, dict[str, tr.TagDef]]]
          ) -> tuple[dict[str, tr.TagDef], list[tr.Problem]]:
    """One definition per tag, by the precedence of design D8.

    A file below another replaces its definition; a project file replaces the
    global one; unrelated files and files in the same folder are merged. Every
    real difference warns, naming the files; identical copies do not.
    """
    by_tag: dict[str, list[tuple[TagFile, tr.TagDef]]] = {}
    for f, tags in per_file:
        for name, d in tags.items():
            by_tag.setdefault(name, []).append((f, d))
    out: dict[str, tr.TagDef] = {}
    problems: list[tr.Problem] = []
    for name, defs in sorted(by_tag.items()):
        # Identical definitions are one definition, wherever they were written.
        distinct: dict[tuple, list[tuple[TagFile, tr.TagDef]]] = {}
        for f, d in defs:
            distinct.setdefault(d.canonical(), []).append((f, d))
        kept = []
        for group in distinct.values():
            f, d = group[0]
            replaced_by = [g for other in distinct.values() if other is not group
                           for g in other if any(_below(g[0], h[0]) for h in group)]
            beaten = all(any(_below(g[0], h[0]) for g in replaced_by) for h in group)
            if replaced_by and beaten:
                winner = replaced_by[0][0]
                problems.append(tr.Problem(
                    f"tag {name!r} is defined differently in {f.path} and in {winner.path}; "
                    f"the definition in {winner.path} applies", tr.Source(str(winner.path)),
                    tr.Level.WARNING, name))
                continue
            sources = tuple(dict.fromkeys(s for _, dd in group for s in dd.sources))
            kept.append(replace(d, sources=sources))
        if len(kept) > 1:
            files = ", ".join(sorted({str(s.path) for d in kept for s in d.sources}))
            problems.append(tr.Problem(f"tag {name!r} is defined differently in {files}; "
                                       "their rules and issues are combined",
                                       kept[0].sources[0] if kept[0].sources else None,
                                       tr.Level.WARNING, name))
        merged, notes = _combine(name, kept)
        problems.extend(notes)
        out[name] = merged
    return out, problems


def _combine(name: str, defs: list[tr.TagDef]) -> tuple[tr.TagDef, list[tr.Problem]]:
    if len(defs) == 1:
        return defs[0], []
    notes: list[tr.Problem] = []
    ordered = sorted(defs, key=lambda d: str(d.sources[0]) if d.sources else "")
    descriptions = [d.description for d in ordered if d.description]
    if len(set(descriptions)) > 1:
        notes.append(tr.Problem(f"tag {name!r} has different descriptions; the first, from "
                                f"{ordered[0].sources[0].path}, is shown",
                                ordered[0].sources[0], tr.Level.WARNING, name))
    rules = list({r.canonical: r for d in ordered for r in d.rules}.values())
    issues: dict[str, tr.Issue] = {}
    for d in ordered:
        for issue in d.issues:
            key = issue.title.casefold()
            had = issues.get(key)
            if had is None:
                issues[key] = issue
            elif had.severity != issue.severity:
                higher = max(had, issue, key=lambda i: i.severity.rank)
                issues[key] = higher
                notes.append(tr.Problem(f"issue {issue.title!r} of tag {name!r} has the "
                                        f"severities {had.severity} and {issue.severity}; "
                                        f"{higher.severity} applies", issue.source,
                                        tr.Level.WARNING, name))
    sources = tuple(dict.fromkeys(s for d in ordered for s in d.sources))
    return tr.TagDef(name, descriptions[0] if descriptions else "", tuple(issues.values()),
                     tuple(rules), sources), notes


# --- writing ---------------------------------------------------------------------


Op = Callable[[dict], dict]


def add_entries(entries: Iterable[Entry]) -> Op:
    def op(doc: dict) -> dict:
        raw = list(doc.get("entries") or [])
        have = set()
        for item in raw:
            with contextlib.suppress(tr.RuleError):
                have.add(entry_from(item).key)
        before = len(raw)
        for e in entries:
            if e.key not in have:
                raw.append(_entry_raw(e))
                have.add(e.key)
        return doc if len(raw) == before else {**doc, "entries": raw}
    return op


def remove_entries(keys: Iterable[tuple]) -> Op:
    gone = set(keys)

    def op(doc: dict) -> dict:
        kept = []
        raw = doc.get("entries") or []
        for item in raw:
            try:
                if entry_from(item).key in gone:
                    continue
            except tr.RuleError:
                pass            # not ours to understand, so not ours to drop
            kept.append(item)
        return doc if len(kept) == len(raw) else {**doc, "entries": kept}
    return op


def set_definition(name: str, body: dict) -> Op:
    def op(doc: dict) -> dict:
        tags = dict(doc.get("tags") or {})
        tags[name] = body
        return {**doc, "tags": tags}
    return op


def update_definition(name: str, description: str, issues: list[tr.Issue]) -> Op:
    """Set a tag's description and issues in seek's file, keeping its rules and
    anything else written there."""
    def op(doc: dict) -> dict:
        tags = dict(doc.get("tags") or {})
        body = dict(tags.get(name) or {})
        body.pop("description", None)
        body.pop("issues", None)
        if description:
            body["description"] = description
        if issues:
            body["issues"] = [_issue_raw(i) for i in issues]
        tags[name] = body
        return {**doc, "tags": tags}
    return op


def add_rule(name: str, raw: dict) -> Op:
    """Append a rule, in seek's own form, to a tag in seek's file."""
    def op(doc: dict) -> dict:
        tags = dict(doc.get("tags") or {})
        body = dict(tags.get(name) or {})
        rules = list(body.get("rules") or [])
        if tr.plain(raw) in rules:
            return doc
        body["rules"] = rules + [tr.plain(raw)]
        tags[name] = body
        return {**doc, "tags": tags}
    return op


def _same_rule(entry, old: dict) -> bool:
    """The rule a builder opened, as it is in the file: the same tests and grant.
    A name the loader made up (`rule 2`) is not in the file, so it is not compared."""
    return (isinstance(entry, dict)
            and tr.plain(entry.get("when")) == old.get("when")
            and str(entry.get("grant", tr.Grant.HOST.value)).lower()
            == old.get("grant", tr.Grant.HOST.value))


def replace_rule(name: str, old: dict, new: dict) -> Op:
    """Replace a rule of a tag in place. Raises TagWriteError, and writes nothing,
    when the rule is no longer in the file as it was read."""
    def op(doc: dict) -> dict:
        tags = dict(doc.get("tags") or {})
        body = dict(tags.get(name) or {})
        rules = list(body.get("rules") or [])
        for n, entry in enumerate(rules):
            if _same_rule(entry, old):
                rules[n] = tr.plain(new)
                break
        else:
            raise TagWriteError("the rule changed on disk - press R and open it again")
        body["rules"] = rules
        tags[name] = body
        return {**doc, "tags": tags}
    return op


def delete_definition(name: str) -> Op:
    def op(doc: dict) -> dict:
        tags = doc.get("tags") or {}
        if name not in tags:
            return doc
        return {**doc, "tags": {k: v for k, v in tags.items() if k != name}}
    return op


def body_of(d: tr.TagDef) -> dict:
    """A definition in seek's own form, ready to be written."""
    body: dict = {}
    if d.description:
        body["description"] = d.description
    if d.issues:
        body["issues"] = [_issue_raw(i) for i in d.issues]
    if d.rules:
        body["rules"] = [dict(r.raw) for r in d.rules]
    return body


def _issue_raw(i: tr.Issue) -> dict:
    out: dict = {"title": i.title, "severity": i.severity.value}
    if i.description:
        out["description"] = i.description
    if i.references:
        out["references"] = list(i.references)
    return out


def _entry_raw(e: Entry) -> dict:
    out: dict = {"tag": e.tag, "host": e.host}
    if e.port is not None:
        out["port"] = f"{e.port}/{e.protocol}"
    if e.added:
        out["added"] = e.added
    return out


def _address_key(text: str) -> tuple:
    try:
        a = ipaddress.ip_address(text)
        return (0, a.version, int(a))
    except ValueError:
        return (1, 0, text)


def _entry_sort(item) -> tuple:
    try:
        e = entry_from(item)
        return (0, e.tag, _address_key(e.host), e.protocol or "", e.port or 0)
    except tr.RuleError:
        return (1, str(item))


def dump(doc: dict) -> str:
    """seek's file in a fixed order: the version, tags by name, entries by tag and
    address, then anything else it found there, untouched."""
    out: dict = {"seek": tr.FORMAT_VERSION}
    tags = doc.get("tags") or {}
    if tags:
        out["tags"] = {k: tr.plain(tags[k]) for k in sorted(tags, key=str)}
    entries = doc.get("entries") or []
    if entries:
        out["entries"] = [tr.plain(e) for e in sorted(entries, key=_entry_sort)]
    for key, value in doc.items():
        if key not in ("seek", "tags", "entries"):
            out[key] = tr.plain(value)
    return HEADER + yaml.safe_dump(out, sort_keys=False, allow_unicode=True,
                                   default_flow_style=None, width=100)


@contextlib.contextmanager
def _lock(path: Path):
    """An exclusive lock beside the file. Waits `LOCK_WAIT`; breaks a lock older
    than `LOCK_STALE` - its writer died - and says so through `broken`."""
    lock = path.with_name(path.name + ".lock")
    mine = f"{os.getpid()}@{socket.gethostname()}"
    deadline = time.monotonic() + LOCK_WAIT
    broken = False
    while True:
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            with os.fdopen(fd, "w") as fh:
                fh.write(mine)
            break
        except FileExistsError:
            try:
                age = time.time() - lock.stat().st_mtime
            except OSError:
                continue                     # released between the two calls
            if age > LOCK_STALE:
                with contextlib.suppress(OSError):
                    lock.unlink()
                broken = True
                continue
            if time.monotonic() > deadline:
                raise TagWriteError(f"{path} is being written by another seek "
                                    f"({_read_owner(lock)}); try again") from None
            time.sleep(LOCK_POLL)
    try:
        yield broken
    finally:
        with contextlib.suppress(OSError):
            if lock.read_text() == mine:
                lock.unlink()


def _read_owner(lock: Path) -> str:
    try:
        return lock.read_text().strip() or "unknown"
    except OSError:
        return "unknown"


def _write_atomic(path: Path, text: str, mode: int) -> None:
    """Whole or not at all, and on disk before it replaces the old file.

    By hand rather than `stdkit.files.write_atomic`: seek does not depend on
    stdkit (AGENTS.md, LIB-1), and the tag file wants the fsync it skips.
    """
    handle, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
    with contextlib.suppress(OSError):          # the rename itself, durably
        fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def apply(path: Path, op: Op) -> bool:
    """Apply `op` to the file as it is on disk now, under the lock. Returns whether
    the file changed. Never writes a file it could not parse; raises TagWriteError
    with the reason when anything stops the write."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise TagWriteError(f"cannot create {path.parent}: {exc.strerror}") from None
    try:
        with _lock(path):
            mode = FILE_MODE
            doc: dict = {}
            if path.exists():
                try:
                    mode = path.stat().st_mode & 0o777
                    text = read_text(path)
                except (OSError, UnicodeDecodeError) as exc:
                    raise TagWriteError(f"{path} could not be read: {exc}") from None
                parsed, problems = tr.parse_document(text, str(path))
                if parsed is None:
                    raise TagWriteError(f"{path} was not changed, because it could not be "
                                        f"read: {problems[0].message}. Fix the file first")
                doc = tr.plain(parsed)
            new = op(doc)
            if new == doc:              # nothing to do - and no empty file created
                return False
            _write_atomic(path, dump(new), mode)
            return True
    except PermissionError as exc:
        raise TagWriteError(f"tags cannot be saved in {path.parent}: {exc.strerror}") from None
    except OSError as exc:
        raise TagWriteError(f"{path} could not be written: {exc.strerror or exc}") from None
