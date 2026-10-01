"""The update's progress: a bar per step that moves while it downloads and
while it indexes, and a time left."""

from __future__ import annotations

import io
from datetime import date

import vulndb_fixtures as fx

from seek.config import Config
from seek.vulndb import commands, update
from seek.vulndb.progress import Tracker, bar, duration


def test_bar_and_duration():
    assert bar(0.0, 10) == "░" * 10 and bar(1.0, 10) == "█" * 10
    assert bar(0.5, 10) == "█" * 5 + "░" * 5
    assert duration(42) == "42 s" and duration(185) == "3 min 05 s"
    assert duration(7200) == "2 h 00 min"


def test_the_line_says_step_bar_activity_and_time_left():
    now = [0.0]
    t = Tracker(["eol", "cpe", "osv", "nvd"], clock=lambda: now[0])
    t("cpe", 0, 100, "downloading")
    now[0] = 10.0
    t("cpe", 25, 100, "downloading · 21.0 of 84.1 MB")
    line = t.line()
    assert line.startswith("2/4 cpe █████░░░░░░░░░░░░░░░  25%")
    assert "downloading · 21.0 of 84.1 MB" in line
    assert line.endswith("~30 s left"), "25% in 10 s: 30 s for the rest"


def test_no_estimate_before_there_is_something_to_project():
    t = Tracker(["nvd"], clock=lambda: 0.0)
    t("nvd", 0, 100, "checking")
    assert "left" not in t.line()


def _reports(tmp_path):
    feeds = fx.build(tmp_path / "www")
    seen: list[tuple[str, int, int, str]] = []
    with fx.serve(feeds) as urls:
        results = update.run(tmp_path / "db.sqlite3", lambda *r: seen.append(r), urls=urls,
                             today=date(2026, 10, 1))
    assert not any(r.error for r in results)
    return seen


def test_every_download_reports_its_bytes_and_finishes_full(tmp_path):
    seen = _reports(tmp_path)
    for source in ("cpe", "osv", "nvd"):
        mine = [(d, t, a) for s, d, t, a in seen if s == source]
        downloads = [d for d, _t, a in mine if a.startswith("downloading")]
        assert downloads and max(downloads) > 0, f"{source} reported no bytes"
        final = mine[-1]
        assert final[0] >= final[1] > 0, f"{source} did not finish at its total: {final}"


def test_within_a_step_progress_never_goes_backwards(tmp_path):
    seen = _reports(tmp_path)
    for source in ("cpe", "osv"):
        done = [d for s, d, t, _a in seen if s == source]
        assert done == sorted(done), source
    nvd = [(d, t) for s, d, t, a in seen if s == "nvd" and not a.startswith("checking")]
    assert [d for d, _t in nvd] == sorted(d for d, _t in nvd)
    assert len({t for _d, t in nvd}) == 1, "one total for the whole NVD step"


def test_the_command_prints_progress_and_the_time_taken(tmp_path):
    feeds = fx.build(tmp_path / "www")
    out = io.StringIO()                      # not a terminal: one line per change
    with fx.serve(feeds) as urls:
        assert commands.run_update(Config(vulndb_path=str(tmp_path / "v.db")), out,
                                   urls=urls) == 0
    text = out.getvalue()
    assert "first update: about" in text
    assert "2/4 cpe" in text and "█" in text
    assert "0.0 MB of 0.0 MB" not in text, "small sizes read in kB"
    assert "done in" in text


def test_the_short_form_fits_a_status_line():
    now = [0.0]
    t = Tracker(["eol", "cpe", "osv", "nvd"], clock=lambda: now[0])
    t("nvd", 0, 200, "downloading 2024")
    now[0] = 30.0
    t("nvd", 100, 200, "indexing 2024")
    assert t.short() == "4/4 nvd █████░░░░░ 50% ~30 s"


def test_the_viewer_label_shows_the_bar_while_updating(tmp_path):
    from seek.nmap.session import Session

    sess = Session(Config(nmap_path="/x", vulndb_path=str(tmp_path / "v.db")), [], tmp_path,
                   databases=[])
    assert sess.vulndb_label() == "◈ no vulndb"
    assert sess._vulndb_lock.acquire()
    try:
        sess.vulndb_progress_short = "2/4 cpe ████░░░░░░ 40% ~1 min"
        assert sess.vulndb_label() == "◈ vulndb 2/4 cpe ████░░░░░░ 40% ~1 min"
    finally:
        sess._vulndb_lock.release()


def test_the_session_forwards_throttled_progress_and_ends_clean(tmp_path, monkeypatch):
    from seek.nmap.session import Session

    feeds = fx.build(tmp_path / "www")
    sess = Session(Config(nmap_path="/x", vulndb_path=str(tmp_path / "v.db")), [], tmp_path,
                   databases=[])
    heard: list[tuple] = []
    with fx.serve(feeds) as urls:
        real = update.run
        monkeypatch.setattr(update, "run", lambda path, progress, cancel: real(
            path, progress, cancel, urls=urls, today=date(2026, 10, 1)))
        results = sess.update_vulndb(lambda *r: heard.append(r))
    assert not any(r.error for r in results)
    assert heard and heard[-1][1] >= heard[-1][2] > 0, "the last report is a finished step"
    assert sess.vulndb_progress == "" and not sess.vulndb_updating


def test_a_finished_step_has_no_time_left():
    now = [0.0]
    t = Tracker(["cpe"], clock=lambda: now[0])
    t("cpe", 0, 10, "x")
    now[0] = 30.0
    t("cpe", 10, 10, "done")
    assert "left" not in t.line() and t.line().endswith("100% · done")


def test_the_estimate_counts_only_the_sources_asked_for(tmp_path):
    feeds = fx.build(tmp_path / "www")
    out = io.StringIO()
    with fx.serve(feeds) as urls:
        commands.run_update(Config(vulndb_path=str(tmp_path / "v.db")), out, ["cpe"],
                            urls=urls)
    assert "about 85 MB" in out.getvalue()
