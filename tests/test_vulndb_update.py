"""Updating the database from (a local copy of) the public feeds."""

from __future__ import annotations

import io
import threading
from datetime import date

import pytest
import vulndb_fixtures as fx

from seek.vulndb import eol, sources, store, update

TODAY = date(2026, 10, 1)
NOW = 1_790_000_000.0


@pytest.fixture
def feeds(tmp_path):
    return fx.build(tmp_path / "www")


def _run(db, urls, **kw):
    kw.setdefault("today", TODAY)
    kw.setdefault("now", NOW)
    return update.run(db, urls=urls, **kw)


def test_first_update_fills_every_source(tmp_path, feeds):
    db = tmp_path / "vulndb.sqlite3"
    with fx.serve(feeds) as urls:
        results = {r.source: r for r in _run(db, urls)}
    assert not any(r.error for r in results.values()), results
    assert results["nvd"].records == 11
    assert results["osv"].records == 2, "left-pad is not a tracked package"
    assert results["cpe"].records == 34, "deprecated names and hardware are skipped"
    assert results["eol"].notes == [f"endoflife.date does not know '{fx.UNKNOWN_SLUG}'"]
    s = store.Store(db)
    counts = s.counts()
    assert counts["cve"] == 10, "the rejected CVE is not stored"
    assert counts["osv"] == 2
    assert s.updated_at() == NOW


def test_only_vulnerable_criteria_are_stored(tmp_path, feeds):
    db = tmp_path / "db.sqlite3"
    with fx.serve(feeds) as urls:
        _run(db, urls, which=["nvd"])
    s = store.Store(db)
    assert s.criteria("linux", "linux_kernel") == [], "a running-on platform is not a match"
    [ssh] = s.criteria("openbsd", "openssh")
    assert (ssh.version, ssh.update) == ("8.9", "p1")
    cve = s.cves(["CVE-2099-0004"])["CVE-2099-0004"]
    assert (cve.severity, cve.score) == ("MEDIUM", 5.0), "v2-only metrics are read"


def test_an_incremental_update_reads_only_the_modified_feed(tmp_path, feeds):
    db = tmp_path / "db.sqlite3"
    with fx.serve(feeds) as urls:
        _run(db, urls, which=["nvd"])
        changed = fx.nvd_items(2021)[0]
        changed["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"] = 8.1
        fx.set_modified(feeds, [changed])
        fetch = update.Fetcher()
        [r] = _run(db, urls, which=["nvd"], fetcher=fetch, now=NOW + 3 * 86400)
    assert r.records == 1
    assert all("modified" in u for u in fetch.requested), fetch.requested
    assert store.Store(db).cves(["CVE-2099-0001"])["CVE-2099-0001"].score == 8.1


def test_an_old_database_rechecks_the_yearly_feeds_by_hash(tmp_path, feeds):
    db = tmp_path / "db.sqlite3"
    with fx.serve(feeds) as urls:
        _run(db, urls, which=["nvd"])
        fetch = update.Fetcher()
        [r] = _run(db, urls, which=["nvd"], fetcher=fetch, now=NOW + 30 * 86400)
    assert r.skipped, "no yearly feed changed"
    assert not any(u.endswith(".json.gz") for u in fetch.requested), "only .meta files"


def test_osv_is_not_downloaded_again_when_unchanged(tmp_path, feeds):
    db = tmp_path / "db.sqlite3"
    with fx.serve(feeds) as urls:
        _run(db, urls, which=["osv"])
        [r] = _run(db, urls, which=["osv"])
    assert r.skipped and not r.error
    assert store.Store(db).counts()["osv"] == 2


def test_a_failed_update_changes_nothing(tmp_path, feeds):
    db = tmp_path / "db.sqlite3"
    with fx.serve(feeds) as urls:
        _run(db, urls, which=["nvd"])
        before = store.Store(db).counts()
        (feeds / "nvd" / "nvdcve-2.0-2021.json.gz").unlink()
        (feeds / "nvd" / "nvdcve-2.0-2021.meta").write_text("sha256:CHANGED\r\n")
        [r] = _run(db, urls, which=["nvd"], full=True)
    assert r.error and "404" in r.error
    assert store.Store(db).counts() == before
    assert store.Store(db).cves(["CVE-2099-0001"]), "the old records are still there"


def test_cancel_rolls_back(tmp_path, feeds):
    db = tmp_path / "db.sqlite3"
    cancel = threading.Event()

    def progress(source, done, total, unit):
        if source == "nvd" and done >= 3:
            cancel.set()

    with fx.serve(feeds) as urls:
        results = _run(db, urls, progress=progress, cancel=cancel)
    assert results[-1].error == "cancelled"
    assert [r.source for r in results] == ["eol", "cpe", "osv", "nvd"], "small ones first"
    assert store.Store(db).counts()["eol"] > 0, "and are kept when NVD is cancelled"
    assert store.Store(db).counts()["cve"] == 0


def test_requests_are_exactly_the_fixed_url_set(tmp_path, feeds):
    """Nothing from a session can reach a request: the URLs are the fixed set."""
    db = tmp_path / "db.sqlite3"
    fetch = update.Fetcher()
    with fx.serve(feeds) as urls:
        _run(db, urls, fetcher=fetch)
        allowed = {urls.nvd_meta(y) for y in range(2002, 2027)} | \
                  {urls.nvd_year(y) for y in range(2002, 2027)} | \
                  {urls.osv_npm(), urls.eol_full(), urls.cpe_meta(), urls.cpe_dictionary()}
    assert set(fetch.requested) <= allowed, set(fetch.requested) - allowed


def test_a_json_array_streams_across_chunk_boundaries():
    items = [{"n": i, "pad": "x" * (i * 7)} for i in range(200)]
    import json
    text = json.dumps({"format": "x", "vulnerabilities": items})
    got = list(sources.iter_json_array(io.StringIO(text), "vulnerabilities", chunk=97))
    assert got == items


def test_osv_ranges_are_intervals():
    row = sources.parse_osv(fx.OSV[1], ["jquery"])
    assert row.ranges == [("jquery", "", "3.4.0", "", "")]
    assert sources.parse_osv(fx.OSV[2], ["jquery"]) is None
    assert sources.parse_osv(fx.OSV[0], ["jquery"]).severity == "MEDIUM"


# --- the commands ------------------------------------------------------------------


def test_status_says_when_there_is_no_database(tmp_path):
    from seek.config import Config
    from seek.vulndb import commands

    out = io.StringIO()
    assert commands.status(Config(vulndb_path=str(tmp_path / "x.db")), out) == 1
    assert "seek vulndb update" in out.getvalue()


def test_update_then_status(tmp_path, feeds):
    from seek.config import Config
    from seek.vulndb import commands

    config = Config(vulndb_path=str(tmp_path / "v.db"))
    out = io.StringIO()
    with fx.serve(feeds) as urls:
        assert commands.run_update(config, out, urls=urls) == 0
    assert "nvd: 11 records" in out.getvalue()
    assert f"endoflife.date does not know '{fx.UNKNOWN_SLUG}'" in out.getvalue()
    out = io.StringIO()
    assert commands.status(config, out) == 0
    assert "cve" not in out.getvalue() and "nvd" in out.getvalue()


def test_the_cli_group_is_wired():
    from typer.testing import CliRunner

    from seek.cli import app

    result = CliRunner().invoke(app, ["vulndb", "update", "--source", "bogus"])
    assert result.exit_code != 0 and "bogus" in result.output
    result = CliRunner().invoke(app, ["vulndb", "--help"])
    assert result.exit_code == 0 and "update" in result.output and "status" in result.output


def test_every_slug_is_one_endoflife_date_knows():
    """Checked against a recorded copy of endoflife.date's product list - a
    renamed product (Varnish became `vinyl-cache`) is caught here, not by a
    user wondering why a product is never tracked."""
    import json
    from pathlib import Path

    recorded = Path(__file__).parent / "fixtures" / "eol-all.json"
    known = set(json.loads(recorded.read_text()))
    assert set(eol.SLUGS.values()) <= known, set(eol.SLUGS.values()) - known


def test_the_dictionary_lists_releases_with_the_update_joined(tmp_path, feeds):
    db = tmp_path / "db.sqlite3"
    with fx.serve(feeds) as urls:
        _run(db, urls, which=["cpe"])
        [again] = _run(db, urls, which=["cpe"])
    assert again.skipped, "an unchanged dictionary is not downloaded twice"
    releases = store.Store(db).releases("python", "python")
    assert "3.8.20" in releases and "3.8.99" not in releases
