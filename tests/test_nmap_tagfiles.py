"""The tag files: finding them, precedence, broken files, reload, and seek's writer."""

from __future__ import annotations

import multiprocessing
import os
import time
from pathlib import Path

import pytest

from seek.nmap import tagfiles as tf
from seek.nmap import tagrules as tr

ROOT_USER = hasattr(os, "geteuid") and os.geteuid() == 0


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def _tag(name: str, extra: str = "") -> str:
    return f"tags:\n  {name}:\n    description: from here\n{extra}"


def _warnings(loaded: tf.Loaded) -> list[str]:
    return [str(p) for p in loaded.problems if p.level is tr.Level.WARNING]


def _errors(loaded: tf.Loaded) -> list[str]:
    return [str(p) for p in loaded.problems if p.level is tr.Level.ERROR]


# --- 3.1 finding ---------------------------------------------------------------------


def test_files_in_nested_folders_are_all_found(tmp_path):
    a = _write(tmp_path / "eng" / "alice" / "seek-rules.yaml", "")
    b = _write(tmp_path / "eng" / "bob" / "deep" / "seek-rules.yml", "")
    t = _write(tmp_path / "eng" / "seek-tags.yaml", "")
    _write(tmp_path / "eng" / "alice" / "notes.yaml", "")
    found = tf.find([tmp_path / "eng"], None)
    assert {f.path for f in found} == {a, b, t}
    kinds = {f.path.name: f.kind for f in found}
    assert kinds["seek-tags.yaml"] is tf.Kind.TAGS and kinds["seek-rules.yml"] is tf.Kind.RULES


def test_a_named_file_looks_in_its_own_folder_only(tmp_path):
    scan = _write(tmp_path / "alice" / "scan.xml", "")
    own = _write(tmp_path / "alice" / "seek-rules.yaml", "")
    _write(tmp_path / "alice" / "sub" / "seek-rules.yaml", "")
    assert [f.path for f in tf.find([scan], None)] == [own]


def test_dot_folders_are_not_searched(tmp_path):
    _write(tmp_path / ".seek" / "seek-rules.yaml", "")
    assert tf.find([tmp_path], None) == ()


def test_no_files_is_nothing_and_no_problem(tmp_path):
    loaded = tf.load(tf.find([tmp_path], tmp_path / "config"))
    assert loaded.tags == {} and loaded.problems == ()


def test_the_global_files_come_last_and_rank_lowest(tmp_path):
    config = tmp_path / "config"
    g = _write(config / "rules.yaml", "")
    _write(config / "seek-rules.yaml", "")          # not a global name
    p = _write(tmp_path / "eng" / "seek-rules.yaml", "")
    found = tf.find([tmp_path / "eng"], config)
    assert [f.path for f in found] == [p, g] and found[-1].scope is None


def test_where_manual_tags_are_written(tmp_path):
    scan = _write(tmp_path / "a" / "scan.xml", "")
    (tmp_path / "b").mkdir()
    assert tf.home([tmp_path / "b", scan]) == tmp_path / "b"
    assert tf.home([scan]) == tmp_path / "a"
    assert tf.home([]) is None


# --- 3.2 precedence ---------------------------------------------------------------


def _issue(sev: str) -> str:
    return f"    issues: [{{title: PIN only, severity: {sev}}}]\n"


def test_a_project_file_replaces_the_global_one_with_a_warning(tmp_path):
    config = tmp_path / "config"
    _write(config / "rules.yaml", _tag("zebra-zd420", _issue("low")))
    _write(tmp_path / "eng" / "seek-rules.yaml", _tag("zebra-zd420", _issue("medium")))
    loaded = tf.load(tf.find([tmp_path / "eng"], config))
    assert loaded.tags["zebra-zd420"].issues[0].severity is tr.Severity.MEDIUM
    (w,) = _warnings(loaded)
    assert "rules.yaml" in w and "eng/seek-rules.yaml" in w and "applies" in w


def test_a_subfolder_replaces_its_parent(tmp_path):
    _write(tmp_path / "eng" / "seek-rules.yaml", _tag("printer", _issue("low")))
    _write(tmp_path / "eng" / "alice" / "seek-rules.yaml", _tag("printer", _issue("high")))
    loaded = tf.load(tf.find([tmp_path / "eng"], None))
    assert loaded.tags["printer"].issues[0].severity is tr.Severity.HIGH
    assert len(_warnings(loaded)) == 1


def test_siblings_are_merged_with_a_warning(tmp_path):
    _write(tmp_path / "eng" / "alice" / "seek-rules.yaml",
           "tags:\n  printer:\n    rules: [{when: [{port: 515}]}]\n"
           "    issues: [{title: Raw printing, severity: low}]\n")
    _write(tmp_path / "eng" / "bob" / "seek-rules.yaml",
           "tags:\n  printer:\n    rules: [{when: [{port: 9100}]}]\n"
           "    issues: [{title: raw printing, severity: high},\n"
           "             {title: Telnet, severity: medium}]\n")
    loaded = tf.load(tf.find([tmp_path / "eng"], None))
    tag = loaded.tags["printer"]
    assert len(tag.rules) == 2
    assert {(i.title.casefold(), i.severity) for i in tag.issues} == {
        ("raw printing", tr.Severity.HIGH), ("telnet", tr.Severity.MEDIUM)}
    w = _warnings(loaded)
    assert any("combined" in x and "alice" in x and "bob" in x for x in w)
    assert any("severities low and high" in x for x in w)


def test_a_copy_is_not_a_collision(tmp_path):
    body = _tag("zebra-zd420", _issue("medium"))
    _write(tmp_path / "config" / "tags.yaml", body)
    _write(tmp_path / "eng" / "seek-tags.yaml", "\n\n" + body)
    loaded = tf.load(tf.find([tmp_path / "eng"], tmp_path / "config"))
    assert not loaded.problems
    assert len(loaded.tags["zebra-zd420"].sources) == 2


def test_rules_and_tags_files_in_one_folder_merge(tmp_path):
    _write(tmp_path / "seek-rules.yaml", "tags:\n  x:\n    rules: [{when: [{port: 1}]}]\n")
    _write(tmp_path / "seek-tags.yaml", "tags:\n  x:\n    rules: [{when: [{port: 2}]}]\n")
    loaded = tf.load(tf.find([tmp_path], None))
    assert len(loaded.tags["x"].rules) == 2 and _warnings(loaded)


# --- 3.3 broken files -------------------------------------------------------------


def test_invalid_yaml_skips_that_file_only(tmp_path):
    _write(tmp_path / "eng" / "alice" / "seek-rules.yaml", _tag("printer"))
    _write(tmp_path / "eng" / "bob" / "seek-rules.yaml", "tags:\n  a: [unclosed\n")
    loaded = tf.load(tf.find([tmp_path / "eng"], None))
    assert "printer" in loaded.tags
    (e,) = _errors(loaded)
    assert "bob/seek-rules.yaml:" in e and "not valid YAML" in e


def test_a_list_and_a_newer_format_are_skipped(tmp_path):
    _write(tmp_path / "a" / "seek-rules.yaml", "- one\n- two\n")
    _write(tmp_path / "b" / "seek-rules.yaml", "seek: 9\n" + _tag("x"))
    loaded = tf.load(tf.find([tmp_path], None))
    assert loaded.tags == {}
    assert len(_errors(loaded)) == 2


@pytest.mark.skipif(ROOT_USER, reason="root reads any file")
def test_an_unreadable_file_is_a_problem_not_a_crash(tmp_path):
    path = _write(tmp_path / "seek-rules.yaml", _tag("x"))
    path.chmod(0)
    try:
        loaded = tf.load(tf.find([tmp_path], None))
    finally:
        path.chmod(0o644)
    assert "could not be read" in _errors(loaded)[0]


# --- 3.4 reload --------------------------------------------------------------------


def test_an_edit_is_noticed_and_read_again(tmp_path):
    path = _write(tmp_path / "seek-rules.yaml", _tag("x"))
    files = tf.find([tmp_path], None)
    loaded = tf.load(files)
    assert not tf.changed(loaded, files)
    time.sleep(0.01)
    path.write_text(_tag("x") + "  y: {description: new}\n")
    assert tf.changed(loaded, files)
    assert set(tf.load(files).tags) == {"x", "y"}


def test_a_new_file_is_a_change(tmp_path):
    files = tf.find([tmp_path], None)
    loaded = tf.load(files)
    _write(tmp_path / "sub" / "seek-rules.yaml", _tag("x"))
    assert tf.changed(loaded, tf.find([tmp_path], None))


# --- 3.5 the writer --------------------------------------------------------------


def _entry(host="10.0.0.5", tag="explored", port=None, proto=None) -> tf.Entry:
    return tf.Entry(tag, host, proto, port, "2026-11-11T09:00:00Z")


def test_adding_creates_the_file_in_a_fixed_order(tmp_path):
    path = tmp_path / "seek-tags.yaml"
    assert tf.apply(path, tf.add_entries([_entry("10.0.0.9"), _entry("10.0.0.10"),
                                          _entry("10.0.0.5", "high-value", 443, "tcp")]))
    text = path.read_text()
    assert text.startswith(tf.HEADER) and "seek: 1" in text
    loaded = tf.load(tf.find([tmp_path], None))
    hosts = [(e.tag, e.host) for e in loaded.all_entries]
    assert hosts == [("explored", "10.0.0.9"), ("explored", "10.0.0.10"),
                     ("high-value", "10.0.0.5")], "by tag, then numerically by address"


def test_adding_twice_and_removing_nothing_write_nothing(tmp_path):
    path = tmp_path / "seek-tags.yaml"
    tf.apply(path, tf.add_entries([_entry()]))
    stamp = path.stat().st_mtime_ns
    assert not tf.apply(path, tf.add_entries([_entry()]))
    assert not tf.apply(path, tf.remove_entries([("x", "1.2.3.4", None, None)]))
    assert path.stat().st_mtime_ns == stamp
    assert not tf.apply(tmp_path / "other" / "seek-tags.yaml", tf.remove_entries([]))
    assert not (tmp_path / "other" / "seek-tags.yaml").exists(), "no empty file"


def test_a_file_that_does_not_parse_is_never_rewritten(tmp_path):
    path = _write(tmp_path / "seek-tags.yaml", "entries: [unclosed\n")
    with pytest.raises(tf.TagWriteError, match="could not be read.*Fix the file first"):
        tf.apply(path, tf.add_entries([_entry()]))
    assert path.read_text() == "entries: [unclosed\n"


def test_what_seek_does_not_understand_is_kept(tmp_path):
    path = _write(tmp_path / "seek-tags.yaml",
                  "custom: {keep: me}\nentries:\n  - {tag: 'bad name', host: 1.2.3.4}\n")
    tf.apply(path, tf.add_entries([_entry()]))
    text = path.read_text()
    assert "keep: me" in text and "bad name" in text and "explored" in text


def test_the_file_mode_is_kept_and_no_temporary_is_left(tmp_path):
    path = _write(tmp_path / "seek-tags.yaml", "")
    path.chmod(0o600)
    tf.apply(path, tf.add_entries([_entry()]))
    assert path.stat().st_mode & 0o777 == 0o600
    assert sorted(p.name for p in tmp_path.iterdir()) == ["seek-tags.yaml"]


def test_a_held_lock_makes_the_write_wait_then_fail(tmp_path, monkeypatch):
    monkeypatch.setattr(tf, "LOCK_WAIT", 0.2)
    path = tmp_path / "seek-tags.yaml"
    _write(tmp_path / "seek-tags.yaml.lock", "4242@elsewhere")
    with pytest.raises(tf.TagWriteError, match="being written by another seek.*4242@elsewhere"):
        tf.apply(path, tf.add_entries([_entry()]))


def test_a_stale_lock_is_broken(tmp_path):
    lock = _write(tmp_path / "seek-tags.yaml.lock", "1@gone")
    old = time.time() - tf.LOCK_STALE - 5
    os.utime(lock, (old, old))
    assert tf.apply(tmp_path / "seek-tags.yaml", tf.add_entries([_entry()]))
    assert not lock.exists()


# --- 3.6 robustness ----------------------------------------------------------------


def _add_many(path: str, tag: str, count: int) -> None:
    for n in range(count):
        tf.apply(Path(path), tf.add_entries([tf.Entry(tag, f"10.0.{n}.1")]))


def test_two_processes_writing_at_once_keep_both(tmp_path):
    path = tmp_path / "seek-tags.yaml"
    ctx = multiprocessing.get_context("spawn")
    procs = [ctx.Process(target=_add_many, args=(str(path), tag, 15)) for tag in ("a", "b")]
    for p in procs:
        p.start()
    for p in procs:
        p.join(60)
        assert p.exitcode == 0
    entries = tf.load(tf.find([tmp_path], None)).all_entries
    assert len(entries) == 30, "no write lost the other's"


def test_a_write_cut_short_leaves_the_old_file_whole(tmp_path, monkeypatch):
    path = tmp_path / "seek-tags.yaml"
    tf.apply(path, tf.add_entries([_entry()]))
    before = path.read_text()

    def killed(*_a, **_k):
        raise KeyboardInterrupt
    monkeypatch.setattr(tf.os, "replace", killed)
    with pytest.raises(KeyboardInterrupt):
        tf.apply(path, tf.add_entries([_entry("10.9.9.9")]))
    assert path.read_text() == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["seek-tags.yaml"], "temp cleaned up"


@pytest.mark.skipif(ROOT_USER, reason="root writes anywhere")
def test_a_read_only_folder_says_so_and_changes_nothing(tmp_path):
    folder = tmp_path / "ro"
    folder.mkdir()
    folder.chmod(0o555)
    try:
        with pytest.raises(tf.TagWriteError, match="cannot be saved|could not be written"):
            tf.apply(folder / "seek-tags.yaml", tf.add_entries([_entry()]))
    finally:
        folder.chmod(0o755)
    assert list(folder.iterdir()) == []


# --- 3.7 manual entries -----------------------------------------------------------


def test_addresses_are_canonical(tmp_path):
    _write(tmp_path / "seek-tags.yaml", "entries:\n  - {tag: x, host: '2001:db8:0:0::1'}\n")
    (entry,) = tf.load(tf.find([tmp_path], None)).all_entries
    assert entry.host == "2001:db8::1" and entry.subject == ("2001:db8::1",)


def test_a_service_entry_is_keyed_by_address_protocol_and_port(tmp_path):
    _write(tmp_path / "seek-tags.yaml",
           "entries:\n  - {tag: high-value, host: 10.0.0.5, port: 443/tcp, added: '2026-11-11'}\n"
           "  - {tag: x, host: 10.0.0.5, port: 443}\n")
    loaded = tf.load(tf.find([tmp_path], None))
    (entry,) = loaded.all_entries
    assert entry.subject == ("10.0.0.5", "tcp", 443) and entry.added == "2026-11-11"
    assert "needs its protocol" in _errors(loaded)[0]


def test_entries_for_hosts_not_loaded_are_kept_on_write(tmp_path):
    path = _write(tmp_path / "seek-tags.yaml", "entries:\n  - {tag: x, host: 203.0.113.99}\n")
    tf.apply(path, tf.add_entries([_entry()]))
    assert "203.0.113.99" in path.read_text()


def test_removal_drops_only_the_named_entries(tmp_path):
    path = tmp_path / "seek-tags.yaml"
    tf.apply(path, tf.add_entries([_entry("10.0.0.1"), _entry("10.0.0.2")]))
    tf.apply(path, tf.remove_entries([_entry("10.0.0.1").key]))
    assert [e.host for e in tf.load(tf.find([tmp_path], None)).all_entries] == ["10.0.0.2"]


def test_a_copy_to_the_global_file_has_the_definition_and_no_address(tmp_path):
    _write(tmp_path / "eng" / "seek-tags.yaml",
           _tag("zebra-zd420", _issue("medium") +
                "    rules: [{when: [{port: 9100}, {not: {port: 22/tcp}}]}]\n") +
           "entries:\n  - {tag: zebra-zd420, host: 10.0.0.7}\n")
    loaded = tf.load(tf.find([tmp_path / "eng"], None))
    target = tmp_path / "config" / "tags.yaml"
    tf.apply(target, tf.set_definition("zebra-zd420", tf.body_of(loaded.tags["zebra-zd420"])))
    text = target.read_text()
    assert "10.0.0.7" not in text and "entries" not in text
    copied = tf.load(tf.find([tmp_path / "eng"], tmp_path / "config"))
    assert not copied.problems, "the copy equals the original"


def test_a_colleague_rule_copies_into_seek_s_own_form(tmp_path):
    _write(tmp_path / "seek-rules.yaml",
           "rules:\n  - {name: p, pattern: {nmap_port: {port: 9100}}, host_tags: [printer]}\n")
    d = tf.load(tf.find([tmp_path], None)).tags["printer"]
    target = tmp_path / "out" / "tags.yaml"
    tf.apply(target, tf.set_definition("printer", tf.body_of(d)))
    again = tf.load((tf.TagFile(target, tf.Kind.TAGS, None),)).tags["printer"]
    assert again.canonical() == d.canonical()
