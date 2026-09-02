"""Reading a capture back.

The fixture is real gowitness v3 output, trimmed to the fields the reader uses
but with its shapes left exactly as the tool wrote them - `technologies` as
`null` rather than `[]`, header keys lowercased. Hand-written JSON would have
had neither trap in it, and both are the kind that only shows up in production.
"""

from __future__ import annotations

import json
from pathlib import Path

from seek.gowitness import results as res

FIX = Path(__file__).parent / "fixtures" / "gowitness" / "capture.jsonl"


def _load(shots: Path | None = None):
    return res.read_jsonl(FIX, shots)


# --- the real shapes ----------------------------------------------------


def test_every_record_in_the_sample_is_read():
    captures, problems = _load()
    assert len(captures) == 7
    assert problems == []


def test_a_successful_capture_carries_what_the_record_needs():
    captures, _ = _load()
    found = next(c for c in captures if c.url == "https://sso.hektor.cc:443")
    assert found.status == 200
    assert found.title == "sso.hektor.cc"
    assert found.protocol
    assert not found.failed


def test_technologies_are_read_when_present():
    captures, _ = _load()
    with_tech = [c for c in captures if c.technologies]
    assert with_tech, "the sample has records with technologies"
    assert all(isinstance(t, str) and t for c in with_tech for t in c.technologies)


def test_null_technologies_do_not_crash_the_reader():
    """gowitness writes `null` here, not `[]`, when it detected none."""
    raws = [json.loads(line) for line in FIX.read_text().splitlines() if line.strip()]
    assert any(r["technologies"] is None for r in raws), \
        "fixture premise: the real tool writes null here"
    captures, _ = _load()
    assert all(isinstance(c.technologies, list) for c in captures)
    assert any(c.technologies == [] for c in captures)


def test_the_server_header_is_matched_case_insensitively():
    """gowitness lowercases header names, so looking for `Server` finds nothing."""
    raw = {"url": "http://x:80", "headers": [{"key": "server", "value": "nginx"}]}
    assert res.from_record(raw).server == "nginx"


def test_a_tls_summary_is_built_only_for_a_tls_probe():
    captures, _ = _load()
    tls = [c for c in captures if c.tls]
    assert tls, "the sample has TLS probes"
    assert any("TLS" in c.tls for c in tls)
    plain = res.from_record({"url": "http://x:80", "tls": {"protocol": ""}})
    assert plain.tls == ""


def test_the_screenshot_path_is_resolved_against_the_shots_directory():
    captures, _ = _load(Path("/shots"))
    shot = next(c.shot for c in captures if c.shot is not None)
    assert str(shot).startswith("/shots/")
    assert shot.suffix in (".jpeg", ".png")


def test_no_shots_directory_leaves_the_path_unset():
    captures, _ = _load()
    assert all(c.shot is None for c in captures)


# --- damage -------------------------------------------------------------


def test_a_malformed_line_is_skipped_and_reported(tmp_path):
    good = FIX.read_text().splitlines()[0]
    path = tmp_path / "gowitness.jsonl"
    path.write_text(f"{good}\n{{not json\n{good}\n")
    captures, problems = res.read_jsonl(path)
    assert len(captures) == 2, "the readable records survived"
    assert len(problems) == 1 and "line 2" in problems[0]


def test_a_truncated_last_line_does_not_lose_the_rest(tmp_path):
    """The process was killed mid-write - the work before it still counts."""
    lines = FIX.read_text().splitlines()
    path = tmp_path / "gowitness.jsonl"
    path.write_text("\n".join(lines) + "\n" + lines[0][:40])
    captures, problems = res.read_jsonl(path)
    assert len(captures) == 7
    assert len(problems) == 1


def test_a_record_without_a_url_is_not_a_capture(tmp_path):
    path = tmp_path / "gowitness.jsonl"
    path.write_text('{"response_code": 200}\n')
    captures, problems = res.read_jsonl(path)
    assert captures == []
    assert "not a capture record" in problems[0]


def test_a_missing_results_file_is_no_captures_not_an_error(tmp_path):
    captures, problems = res.read_jsonl(tmp_path / "absent.jsonl")
    assert (captures, problems) == ([], [])


# --- the index ----------------------------------------------------------


def test_captures_are_looked_up_by_url():
    captures, _ = _load()
    index = res.Captures(captures)
    assert index.get("https://sso.hektor.cc:443") is not None
    assert index.get("https://not.captured:443") is None


def test_the_newest_capture_of_a_url_wins():
    index = res.Captures([res.Capture(url="http://x:80", title="old"),
                          res.Capture(url="http://x:80", title="new")])
    assert index.get("http://x:80").title == "new"
    assert len(index) == 1


def test_for_urls_keeps_the_order_given_and_skips_unknowns():
    index = res.Captures([res.Capture(url="b"), res.Capture(url="a")])
    assert [c.url for c in index.for_urls(["a", "missing", "b"])] == ["a", "b"]


def test_failures_are_added_from_the_run_since_nothing_writes_them():
    """gowitness records a failed target nowhere on disk - the run's log is
    the only place it exists."""
    index = res.Captures()
    index.add_failures({"http://10.255.255.1:81": "page load error"})
    found = index.get("http://10.255.255.1:81")
    assert found.failed
    assert found.summary() == "page load error"


def test_loading_a_directory_collects_problems():
    index = res.Captures()
    index.load(FIX)
    assert len(index) == 7
    assert index.problems == []


# --- the one-line summary shown in a record ------------------------------


def test_the_summary_leads_with_the_status():
    capture = res.Capture(url="u", status=200, reason="OK", title="Home",
                          server="nginx", technologies=["Cloudflare"])
    assert capture.summary() == "200 OK · Home · nginx · Cloudflare"


def test_a_failed_summary_is_its_reason():
    assert res.Capture(url="u", failure="i/o timeout").summary() == "i/o timeout"


def test_a_redirect_is_visible():
    assert res.Capture(url="http://x:80", final_url="https://x/login").redirected
    assert not res.Capture(url="http://x:80", final_url="http://x:80/").redirected
