"""Reading a capture back from its database.

The fixture is a real gowitness v3 database (see `make_fixture.py`), so the
schema under test is the one the tool writes rather than one invented here. It
carries the traps that matter: the screenshot column is `filename`, header keys
are cased differently per protocol, and `response_reason` is empty over HTTP/2.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from seek.gowitness import results as res

FIX = Path(__file__).parent / "fixtures" / "gowitness" / "capture.sqlite3"


def _read(shots: Path | None = None):
    return res.read_database(FIX, shots)


# --- the real database --------------------------------------------------


def test_every_result_in_the_capture_is_read():
    captures, problems = _read()
    assert len(captures) == 7
    assert problems == []


def test_the_row_id_is_carried_because_the_report_server_needs_it():
    """The JSON Lines writer set every id to 0; only the database has real
    ones, and `/results/detail/:id` is addressed by them."""
    captures, _ = _read()
    ids = [c.row_id for c in captures]
    assert all(isinstance(i, int) for i in ids)
    assert len(set(ids)) == len(ids), "ids are distinct"
    assert 0 not in ids


def test_the_screenshot_comes_from_the_filename_column():
    """The column is `filename`; the JSON field was `file_name`. A
    field-for-field port of the old reader loses every screenshot silently."""
    captures, _ = _read(Path("/shots"))
    shots = [c.shot for c in captures if c.shot is not None]
    assert shots, "no screenshot path was read"
    assert all(str(s).startswith("/shots/") for s in shots)
    assert all(s.suffix in (".jpeg", ".png") for s in shots)


def test_headers_are_read_for_every_result():
    captures, _ = _read()
    assert sum(len(c.headers) for c in captures) == 70


def test_a_header_is_found_whatever_its_case():
    """HTTP/1.1 keeps the server's casing, HTTP/2 lowercases it - a
    case-sensitive lookup works on some rows and fails on others."""
    captures, _ = _read()
    by_proto = {}
    for c in captures:
        by_proto.setdefault(c.protocol, []).append(c)
    assert {"http/1.1", "h2"} <= set(by_proto), "the fixture has both protocols"
    for protocol, group in by_proto.items():
        found = [c for c in group if c.header("content-type")]
        assert found, f"no content-type found over {protocol}"


def test_technologies_are_read_and_absent_ones_are_empty():
    captures, _ = _read()
    assert any(c.technologies for c in captures)
    assert any(c.technologies == [] for c in captures)
    assert all(isinstance(c.technologies, list) for c in captures)


def test_console_messages_are_read():
    """They carry version strings the headers do not."""
    captures, _ = _read()
    assert sum(len(c.console) for c in captures) == 6


def test_tls_detail_and_its_san_list_are_read():
    captures, _ = _read()
    with_tls = [c for c in captures if c.tls]
    assert with_tls
    assert any("TLS" in c.tls for c in with_tls)
    assert any(c.sans for c in captures), "no certificate SAN names were read"


def test_an_empty_reason_over_http2_is_not_an_error():
    captures, _ = _read()
    h2 = [c for c in captures if c.protocol == "h2"]
    assert h2 and all(c.reason == "" for c in h2)
    assert all(str(c.status) in c.summary() for c in h2 if c.status)


def test_the_probe_time_and_size_are_carried():
    captures, _ = _read()
    assert any(c.probed_at for c in captures)
    assert any(isinstance(c.content_length, int) for c in captures)


# --- a database-only capture: the defect this change fixes ---------------


def test_a_capture_directory_with_only_a_database_is_read(tmp_path):
    """The documented workflow is `scan file --write-db` - no JSON Lines file
    at all. That capture used to return nothing."""
    from seek.gowitness.capture import capture_dir

    paths = capture_dir(tmp_path)
    paths.root.mkdir(parents=True)
    paths.db.write_bytes(FIX.read_bytes())
    assert not paths.jsonl.exists()

    index = res.Captures()
    index.load(paths.db, paths.shots)
    assert len(index) == 7, "a database-only capture was not read"
    assert index.problems == []


# --- damage -------------------------------------------------------------


def test_a_missing_database_is_no_captures_not_an_error(tmp_path):
    assert res.read_database(tmp_path / "absent.sqlite3") == ([], [])


def test_a_file_that_is_not_a_database_is_reported_not_raised(tmp_path):
    path = tmp_path / "gowitness.sqlite3"
    path.write_text("this is not a database")
    captures, problems = res.read_database(path)
    assert captures == []
    assert len(problems) == 1


def test_a_database_without_a_results_table_says_so(tmp_path):
    path = tmp_path / "gowitness.sqlite3"
    con = sqlite3.connect(path)
    con.execute("create table something_else (id integer)")
    con.commit()
    con.close()
    captures, problems = res.read_database(path)
    assert captures == []
    assert "not a gowitness database" in problems[0]


def test_a_database_missing_optional_tables_still_reads(tmp_path):
    """A different gowitness version need not have every table we expect."""
    path = tmp_path / "gowitness.sqlite3"
    path.write_bytes(FIX.read_bytes())
    con = sqlite3.connect(path)
    for table in ("cookies", "network_logs", "console_logs", "tls_san_lists"):
        con.execute(f"drop table if exists {table}")
    con.commit()
    con.close()
    captures, problems = res.read_database(path)
    assert len(captures) == 7, "dropped optional tables lost the results"
    assert problems == []
    assert all(c.console == [] and c.sans == [] for c in captures)


def test_a_results_table_missing_columns_still_reads(tmp_path):
    """Only columns that exist are selected, never a fixed list."""
    path = tmp_path / "gowitness.sqlite3"
    con = sqlite3.connect(path)
    con.execute("create table results (id integer, url text)")
    con.execute("insert into results values (1, 'http://a:80')")
    con.commit()
    con.close()
    captures, problems = res.read_database(path)
    assert len(captures) == 1
    assert captures[0].url == "http://a:80" and captures[0].row_id == 1
    assert problems == []


def test_the_database_is_opened_read_only(tmp_path):
    """A capture may be writing to it, and the viewer never should."""
    path = tmp_path / "gowitness.sqlite3"
    path.write_bytes(FIX.read_bytes())
    before = path.read_bytes()
    res.read_database(path)
    assert path.read_bytes() == before


# --- the index ----------------------------------------------------------


def test_captures_are_looked_up_by_url():
    captures, _ = _read()
    index = res.Captures(captures)
    assert index.get(captures[0].url) is not None
    assert index.get("https://not.captured:443") is None


def test_the_newest_capture_of_a_url_wins():
    index = res.Captures([res.Capture(url="http://x:80", title="old"),
                          res.Capture(url="http://x:80", title="new")])
    assert index.get("http://x:80").title == "new"
    assert len(index) == 1


def test_failures_come_from_the_run_because_nothing_writes_them():
    index = res.Captures()
    index.add_failures({"http://10.255.255.1:81": "page load error"})
    assert index.get("http://10.255.255.1:81").failed


# --- what identifies a system -------------------------------------------


def test_the_security_headers_looked_for_are_reported_both_ways():
    captures, _ = _read()
    for c in captures:
        labels = {label for _n, label in res.SECURITY_HEADERS}
        assert set(c.missing_security_headers()) <= labels


def test_a_missing_security_header_is_knowable():
    c = res.Capture(url="u", headers=[("X-Frame-Options", "DENY")])
    assert "x-frame-options" not in c.missing_security_headers(), "present is not missing"
    assert "hsts" in c.missing_security_headers()


def test_a_system_is_derived_from_a_header_when_nothing_was_detected():
    captures, _ = _read()
    derived = [(c.derived_system(), c.url) for c in captures]
    named = [d for d, _u in derived if d[0]]
    assert named, "nothing was derived from the real capture"
    assert all(source for _name, source in named), "a derivation must say its source"


def test_a_detected_technology_is_never_overridden_by_a_guess():
    c = res.Capture(url="u", technologies=["Cloudflare"],
                    headers=[("server", "nginx")])
    assert c.derived_system() == ("", "")


def test_a_title_that_only_repeats_the_host_names_nothing():
    assert res.Capture(url="http://fritz.box:80", title="fritz.box").derived_system() == ("", "")
    assert res.Capture(url="http://fritz.box:80",
                       title="FRITZ!Box 7590").derived_system() == ("FRITZ!Box 7590", "page title")


@pytest.mark.parametrize("header", ["server", "x-powered-by"])
def test_a_naming_header_is_used_and_labelled(header):
    name, source = res.Capture(url="u", headers=[(header, "authentik")]).derived_system()
    assert (name, source) == ("authentik", header)


def test_a_versioned_server_header_keeps_only_the_product():
    name, _ = res.Capture(url="u", headers=[("server", "nginx/1.24.0")]).derived_system()
    assert name == "nginx"


def test_an_error_pages_title_names_no_system():
    """An error page's title is usually its own status line back again, and
    "403 Forbidden" is not a product."""
    for status, title in ((403, "403 Forbidden"), (404, "404 Not Found"),
                          (400, "400 The plain HTTP request was sent to HTTPS port")):
        assert res.Capture(url="http://x:80", status=status,
                           title=title).derived_system() == ("", "")


# --- the join: two sides spelling the same address differently ----------


def test_a_default_port_is_made_explicit():
    """`export_urls` omits a default port, as a URL should. gowitness records
    what it probed, and it probes the port set - so the same page comes back
    as `http://host:80`. Measured: two port-less URLs produced four recorded
    results, none matching the URL they came from, and nothing linked."""
    assert res.canonical_url("http://fritz.box") == "http://fritz.box:80"
    assert res.canonical_url("https://sso.example") == "https://sso.example:443"
    assert res.canonical_url("http://fritz.box:80") == "http://fritz.box:80"
    assert res.canonical_url("https://x:8443") == "https://x:8443"
    assert res.canonical_url("http://fritz.box/") == "http://fritz.box:80"


def test_a_capture_recorded_with_a_port_is_found_without_one():
    """The real failure: the tool records `:80`, the record looks up neither."""
    index = res.Captures([res.Capture(url="http://fritz.box:80", status=200)])
    assert index.get("http://fritz.box") is not None
    assert index.get("http://fritz.box:80") is not None


def test_a_capture_recorded_without_a_port_is_found_with_one():
    index = res.Captures([res.Capture(url="https://sso.example", status=200)])
    assert index.get("https://sso.example:443") is not None


def test_for_urls_matches_across_the_two_spellings():
    index = res.Captures([res.Capture(url="http://a:80", status=200),
                          res.Capture(url="https://b:443", status=200)])
    found = index.for_urls(["http://a", "https://b"])
    assert len(found) == 2


def test_a_capture_is_yielded_once_however_many_ways_it_is_asked_for():
    index = res.Captures([res.Capture(url="http://a:80", status=200)])
    assert len(index.for_urls(["http://a", "http://a:80", "http://a/"])) == 1


def test_a_failure_is_indexed_canonically_too():
    index = res.Captures()
    index.add_failures({"http://a": "refused"})
    assert index.get("http://a:80") is not None


def test_something_that_is_not_a_url_survives_canonicalisation():
    for odd in ("", "not a url", "mailto:x@y"):
        assert isinstance(res.canonical_url(odd), str)


def test_network_logs_are_read_when_the_capture_recorded_them():
    captures, _ = _read()
    assert any(c.network for c in captures), "no network log rows were read"
    url, label = next(c.network[0] for c in captures if c.network)
    assert isinstance(url, str) and isinstance(label, str)


# --- every capture, and where it came from -------------------------------------


def test_a_capture_knows_its_database():
    captures, _ = _read()
    assert {c.database for c in captures} == {FIX}


def test_two_databases_with_the_same_url_are_both_kept(tmp_path):
    import shutil

    second = tmp_path / "other.sqlite3"
    shutil.copy(FIX, second)
    con = sqlite3.connect(second)
    con.execute("update results set probed_at = '2026-09-03 10:00:00+00:00'")
    con.commit()
    con.close()

    shots = res.Captures()
    shots.add(res.read_database(FIX)[0])
    shots.add(res.read_database(second)[0])
    assert len(shots.all()) == 14, "both pictures of every URL"
    assert {c.database for c in shots.all()} == {FIX, second}
    url = shots.all()[0].url
    assert shots.get(url).database == second, "the newest still wins for a lookup"
    assert len(shots) == 7


def test_reading_a_database_again_does_not_double_it():
    shots = res.Captures()
    before = shots.generation
    shots.add(_read()[0])
    shots.add(_read()[0])
    assert len(shots.all()) == 7
    assert shots.generation > before


def test_a_failure_from_a_log_is_listed_too():
    shots = res.Captures()
    shots.add_failures({"http://192.0.2.9": "timeout"})
    (only,) = shots.all()
    assert only.failed and only.database is None


@pytest.mark.parametrize("url", [
    "http://fritz.box", "http://fritz.box:80", "https://Fritz.Box", "https://a.b:8443",
    "HTTP://X.Y", "http://192.0.2.1", "https://192.0.2.1:443", "ftp://h", "ftp://h:21",
    "http://h:0080", "http://h:99999", "http://h:", "http://:80", "http://h/", "http://h/p",
    "http://u@h", "http://[::1]:80", "http://h?q", "http://h#f", "http://h:x", "gopher://h",
    "http://h:65535", "https://sso.hektor.cc:80", "",
])
def test_the_fast_canonical_form_agrees_with_the_parser(url):
    """The string fast path must give exactly what `urlsplit` would."""
    from urllib.parse import urlsplit

    def slow(u):
        if not u:
            return u
        split = urlsplit(u)
        if not split.scheme or not split.hostname:
            return u.rstrip("/")
        port = split.port or res._DEFAULT_PORT.get(split.scheme.lower())
        if port is None:
            return f"{split.scheme}://{split.hostname}".rstrip("/")
        return f"{split.scheme}://{split.hostname}:{port}"

    try:
        expected = slow(url)
    except ValueError:
        expected = None
    fast = res._canonical_plain(url)
    if fast is not None:
        assert fast == expected, url
