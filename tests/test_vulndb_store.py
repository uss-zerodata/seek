"""The database file: missing is a state, reads are read-only."""

from __future__ import annotations

import sqlite3

from seek.vulndb import store


def test_a_missing_database_is_a_state(tmp_path):
    s = store.Store(tmp_path / "none.sqlite3")
    assert s.missing
    assert s.criteria("f5", "nginx") == [] and s.age_days() is None
    assert not (tmp_path / "none.sqlite3").exists(), "reading never creates it"


def test_a_file_that_is_not_a_database_is_missing(tmp_path):
    bad = tmp_path / "bad.sqlite3"
    bad.write_text("not sqlite")
    assert store.Store(bad).missing


def test_reads_what_was_written_and_cannot_write(tmp_path):
    path = tmp_path / "db.sqlite3"
    con = store.open_write(path)
    con.execute("insert into meta values ('updated_at', ?)", ("1000.0",))
    con.execute("insert into cve values ('CVE-1', 'p', 'm', 'sum', 'HIGH', 7.5, 'v', 'CWE-1')")
    con.execute("insert into crit values ('CVE-1','a','f5','nginx','*','','0.6.18','','',"
                "'1.20.1')")
    con.close()
    s = store.Store(path)
    assert not s.missing
    [c] = s.criteria("f5", "nginx")
    assert (c.start_incl, c.end_excl) == ("0.6.18", "1.20.1")
    assert s.cves(["CVE-1"])["CVE-1"].score == 7.5
    assert s.product_cve_count("f5", "nginx") == 1
    assert round(s.age_days(now=1000.0 + 86400), 3) == 1.0
    assert s.generation == "1000.0"
    try:
        s._con.execute("insert into meta values ('x', 'y')")
        raise AssertionError("a session's connection must be read-only")
    except sqlite3.OperationalError:
        pass


def test_the_default_path_is_in_the_state_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    assert store.resolve("") == tmp_path / "seek" / "vulndb.sqlite3"
    assert store.resolve("~/x.db").name == "x.db"
