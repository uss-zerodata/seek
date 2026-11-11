"""Building the capture command, and reading what it says.

The argv assertions are pinned against the interface that was measured, not the
one the reference workflow documents - the extra `gowitness` word the reference
passes is rejected by the current image, whose entrypoint is already gowitness.
The log lines parsed here are verbatim from a real v3 run.
"""

from __future__ import annotations

from pathlib import Path

from seek.gowitness.capture import (
    CaptureRun,
    Paths,
    capture_dir,
    report_argv,
    scan_argv,
    settle_script,
    write_urls,
)
from seek.gowitness.detect import Probe

DOCKER = Probe(backend="docker", path="/usr/bin/docker",
               image="ghcr.io/sensepost/gowitness")
NATIVE = Probe(backend="native", path="/usr/bin/gowitness")

# Verbatim from a real run.
RESULT_LINE = ("2026/09/02 17:05:47 INFO result 🤖 target=https://sso.hektor.cc:443 "
               "status-code=200 title=sso.hektor.cc have-screenshot=true")
FAILURE_LINE = ('2026/09/02 17:08:00 ERRO failed to witness target '
                'target=http://10.255.255.1:81 err="page load error '
                'net::ERR_ADDRESS_UNREACHABLE"')


def _paths(tmp_path) -> Paths:
    return capture_dir(tmp_path)


# --- where things go -----------------------------------------------------


def test_the_capture_directory_sits_beside_the_scans(tmp_path):
    paths = capture_dir(tmp_path)
    assert paths.root == tmp_path / "gowitness"
    assert paths.jsonl.name == "gowitness.jsonl"
    assert paths.db.name == "gowitness.sqlite3"
    assert paths.shots.name == "screenshots"


def test_the_url_file_is_written_with_the_directories_it_needs(tmp_path):
    paths = _paths(tmp_path)
    write_urls(paths, ["https://a:443", "http://b:80"])
    assert paths.urls.read_text().splitlines() == ["https://a:443", "http://b:80"]
    assert paths.shots.is_dir()


def test_every_written_url_carries_a_scheme_and_a_port(tmp_path):
    """The whole reason gowitness does not expand them into guessed variants."""
    paths = _paths(tmp_path)
    urls = ["https://a.example:443", "http://b.example:8080"]
    write_urls(paths, urls)
    for line in paths.urls.read_text().splitlines():
        assert line.startswith(("http://", "https://"))
        assert line.rsplit(":", 1)[-1].isdigit(), f"{line} has no explicit port"


# --- the command ---------------------------------------------------------


def test_the_docker_command_mounts_the_capture_directory(tmp_path):
    paths = _paths(tmp_path)
    argv = scan_argv(DOCKER, paths)
    assert argv[0] == "/usr/bin/docker"
    assert argv[1:3] == ["run", "--rm"]
    assert f"{paths.root}:/data" in argv
    assert "ghcr.io/sensepost/gowitness" in argv


def test_the_docker_command_does_not_repeat_the_entrypoint(tmp_path):
    """The image's entrypoint is already gowitness; the reference workflow's
    extra `gowitness` word makes the current image reject the command."""
    argv = scan_argv(DOCKER, _paths(tmp_path))
    image_at = argv.index("ghcr.io/sensepost/gowitness")
    assert argv[image_at + 1] == "scan", f"expected `scan`, got {argv[image_at + 1]!r}"


def test_the_native_command_is_the_same_flags_with_real_paths(tmp_path):
    paths = _paths(tmp_path)
    native = scan_argv(NATIVE, paths)
    assert native[0] == "/usr/bin/gowitness"
    assert native[1:3] == ["scan", "file"]
    assert "run" not in native[:3]
    assert str(paths.urls) in native


def test_both_backends_ask_for_the_same_writers(tmp_path):
    paths = _paths(tmp_path)
    for argv in (scan_argv(DOCKER, paths), scan_argv(NATIVE, paths)):
        assert "--write-db" in argv
        assert "--log-scan-errors" in argv


def test_scan_errors_are_always_logged(tmp_path):
    """Without this an unreachable target is silent in every output the tool
    has, and "refused" cannot be told from "never asked"."""
    for probe in (DOCKER, NATIVE):
        assert "--log-scan-errors" in scan_argv(probe, _paths(tmp_path))


def test_a_chrome_path_is_passed_only_when_configured(tmp_path):
    paths = _paths(tmp_path)
    assert "--chrome-path" not in scan_argv(DOCKER, paths)
    argv = scan_argv(DOCKER, paths, chrome_path="/usr/bin/chromium")
    assert argv[argv.index("--chrome-path") + 1] == "/usr/bin/chromium"


def test_the_report_server_publishes_to_the_configured_loopback(tmp_path):
    argv = report_argv(DOCKER, _paths(tmp_path), "127.0.0.1", 7171)
    assert "-p" in argv
    assert "127.0.0.1:7171:7171" in argv
    assert argv[argv.index("--port") + 1] == "7171"


def test_the_native_report_server_binds_where_it_was_told(tmp_path):
    argv = report_argv(NATIVE, _paths(tmp_path), "127.0.0.1", 7171)
    assert argv[argv.index("--host") + 1] == "127.0.0.1"
    assert "-p" not in argv


# --- reading the run -----------------------------------------------------


def _run(tmp_path, n: int = 3) -> CaptureRun:
    return CaptureRun(argv=["true"], paths=_paths(tmp_path),
                      urls=[f"http://h{i}:80" for i in range(n)])


def test_a_result_line_advances_the_count(tmp_path):
    run = _run(tmp_path)
    run.append(RESULT_LINE)
    assert (run.captured, run.failed) == (1, 0)
    assert run.progress() == "1/3 captured"


def test_a_failure_line_is_counted_and_its_reason_kept(tmp_path):
    run = _run(tmp_path)
    run.append(FAILURE_LINE)
    assert (run.captured, run.failed) == (0, 1)
    assert run.failures["http://10.255.255.1:81"] == (
        "page load error net::ERR_ADDRESS_UNREACHABLE")


def test_progress_counts_both_ways_a_target_can_end(tmp_path):
    run = _run(tmp_path)
    run.append(RESULT_LINE)
    run.append(FAILURE_LINE)
    assert run.finished == 2
    assert run.progress() == "2/3 captured"


def test_the_summary_reports_both_halves(tmp_path):
    run = _run(tmp_path)
    run.append(RESULT_LINE)
    run.append(FAILURE_LINE)
    assert run.summarise() == "1 captured, 1 failed"


def test_a_clean_summary_says_nothing_about_failures(tmp_path):
    run = _run(tmp_path)
    run.append(RESULT_LINE)
    assert run.summarise() == "1 captured"


def test_a_run_that_died_part_way_still_reports_what_it_managed(tmp_path):
    run = _run(tmp_path)
    run.append(RESULT_LINE)
    assert "1 captured" in run.failure(1, ["some fatal line"])


def test_ordinary_output_is_not_mistaken_for_progress(tmp_path):
    run = _run(tmp_path)
    run.append("2026/09/02 17:05:40 INFO starting scan")
    run.append("chrome: downloading browser")
    assert (run.captured, run.failed) == (0, 0)


def test_the_run_describes_itself_for_the_list(tmp_path):
    run = _run(tmp_path, n=12)
    assert run.label == "capture"
    assert run.scope == "12 urls"
    assert _run(tmp_path, n=1).scope == "1 url"


# --- how much a capture collects ----------------------------------------


def test_trimmed_collection_skips_the_heavy_writers(tmp_path):
    """Still available for when the size of a capture directory matters more
    than its completeness."""
    for probe in (DOCKER, NATIVE):
        argv = scan_argv(probe, _paths(tmp_path), collect_all=False)
        assert "--skip-html" in argv and "--skip-network-logs" in argv


def test_collecting_everything_drops_the_skips(tmp_path):
    for probe in (DOCKER, NATIVE):
        argv = scan_argv(probe, _paths(tmp_path), collect_all=True)
        assert "--skip-html" not in argv and "--skip-network-logs" not in argv


def test_the_setting_changes_collection_only(tmp_path):
    """Everything else about the command is identical, so a database recorded
    either way is read the same."""
    trimmed = [a for a in scan_argv(DOCKER, _paths(tmp_path), collect_all=False)
               if not a.startswith("--skip")]
    full = scan_argv(DOCKER, _paths(tmp_path), collect_all=True)
    assert trimmed == full


def test_the_results_file_is_no_longer_written(tmp_path):
    """The JSON Lines reader is gone; a writer nothing reads is dead weight."""
    argv = scan_argv(DOCKER, _paths(tmp_path))
    assert "--write-jsonl" not in argv
    assert not any(a.startswith("--write-jsonl") for a in argv)
    assert "--write-db" in argv, "the database is still written"


# --- the mount must be an absolute path ---------------------------------


def test_the_capture_directory_is_absolute_even_from_a_relative_scan_dir():
    """docker reads a relative `-v` source as a *named volume*, not a host
    directory: it refuses the run with "includes invalid characters for a local
    volume name" and points at `docker run --help`, which reads as the app
    having built a broken command. The viewer is normally opened on a relative
    directory (`seek nmap test_scans`), so this is the common case, not an edge.
    """
    paths = capture_dir(Path("test_scans"))
    assert paths.root.is_absolute()
    for path in (paths.urls, paths.db, paths.jsonl, paths.shots):
        assert path.is_absolute()


def test_the_docker_mount_source_is_absolute():
    argv = scan_argv(DOCKER, capture_dir(Path("relative/dir")))
    source = argv[argv.index("-v") + 1].rsplit(":", 1)[0]
    assert Path(source).is_absolute(), f"docker would treat {source!r} as a volume name"


def test_the_native_command_also_gets_absolute_paths():
    argv = scan_argv(NATIVE, capture_dir(Path("relative/dir")))
    assert Path(argv[argv.index("-f") + 1]).is_absolute()


def test_the_report_server_mount_is_absolute():
    argv = report_argv(DOCKER, capture_dir(Path("relative/dir")), "127.0.0.1", 7171)
    source = argv[argv.index("-v") + 1].rsplit(":", 1)[0]
    assert Path(source).is_absolute()


def test_a_help_pointer_is_not_what_the_run_list_reports(tmp_path):
    """A tool that refuses its command line prints the reason and *then* points
    at its help, so the last line is the least useful thing it said."""
    run = _run(tmp_path, n=1)
    tail = [
        'docker: Error response from daemon: create x: "x" includes invalid '
        "characters for a local volume name",
        "Run 'docker run --help' for more information",
    ]
    reported = run.failure(125, tail)
    assert "invalid characters" in reported
    assert "--help" not in reported


def test_the_last_line_is_still_used_when_it_is_all_there_is(tmp_path):
    run = _run(tmp_path, n=1)
    assert "boom" in run.failure(1, ["boom"])
    # even a lone help pointer beats saying nothing
    assert run.failure(1, ["Run 'docker run --help' for more information"])


def test_the_url_list_is_written_with_explicit_ports(tmp_path):
    """A port-less target is crossed with gowitness's whole port set, so it is
    probed twice and recorded under a port it never carried."""
    paths = _paths(tmp_path)
    write_urls(paths, ["http://fritz.box", "https://sso.example", "https://x:8443"])
    written = paths.urls.read_text().split()
    assert written == ["http://fritz.box:80", "https://sso.example:443",
                       "https://x:8443"]


def test_urls_that_canonicalise_together_are_written_once(tmp_path):
    paths = _paths(tmp_path)
    write_urls(paths, ["http://a", "http://a:80", "http://a/"])
    assert paths.urls.read_text().split() == ["http://a:80"]


def test_everything_is_recorded_by_default(tmp_path):
    """A capture that quietly drops its network log recorded less than it saw,
    and the operator has no way to tell."""
    argv = scan_argv(DOCKER, _paths(tmp_path))
    assert "--skip-network-logs" not in argv
    assert "--skip-html" not in argv


def test_collection_can_still_be_trimmed(tmp_path):
    argv = scan_argv(DOCKER, _paths(tmp_path), collect_all=False)
    assert "--skip-network-logs" in argv and "--skip-html" in argv


# --- waiting for the page ---------------------------------------------------------


def test_a_capture_waits_for_the_page_not_for_a_clock(tmp_path):
    """Measured against gowitness 3.2.2: only the gorod driver awaits the promise
    the script returns, and only when the script is inline."""
    for probe in (DOCKER, NATIVE):
        argv = scan_argv(probe, _paths(tmp_path))
        assert argv[argv.index("--driver") + 1] == "gorod"
        assert argv[argv.index("--delay") + 1] == "1", "a redirect on load, then the script"
        assert argv[argv.index("--javascript") + 1] == settle_script(2000, 20000)
        assert "--javascript-file" not in argv, "not awaited"


def test_the_wait_is_one_function_on_one_line():
    script = settle_script(1500, 9000)
    assert script.startswith("() => new Promise(") and "\n" not in script
    assert "quiet = 1500, cap = 9000" in script
    # Loaded, every image in, and still - or the cap.
    for part in ('readyState === "complete"', "document.images", "MutationObserver",
                 "now - start >= cap"):
        assert part in script, part


def test_the_page_s_wait_fits_inside_the_tool_s_timeout(tmp_path):
    argv = scan_argv(DOCKER, _paths(tmp_path), timeout=30, settle_cap_ms=45_000)
    assert int(argv[argv.index("--timeout") + 1]) >= 55
    quick = scan_argv(DOCKER, _paths(tmp_path), timeout=30, settle_cap_ms=5_000)
    assert quick[quick.index("--timeout") + 1] == "30", "never shortened"


def test_a_page_that_redirects_on_load_is_followed_first(tmp_path):
    """gowitness sleeps `--delay` before it runs the script; a script started
    before a page's own `location.replace` dies with that page, and gowitness
    then photographs a blank one at once."""
    argv = scan_argv(DOCKER, _paths(tmp_path), settle_delay_s=3)
    assert argv[argv.index("--delay") + 1] == "3"
    assert "--javascript" in argv
    none = scan_argv(DOCKER, _paths(tmp_path), settle_delay_s=0)
    assert none[none.index("--delay") + 1] == "0", "0 turns the pause off"


def test_the_timeout_covers_the_delay_and_the_cap(tmp_path):
    argv = scan_argv(DOCKER, _paths(tmp_path), timeout=30, settle_cap_ms=45_000,
                     settle_delay_s=5)
    assert int(argv[argv.index("--timeout") + 1]) >= 5 + 45 + 10


def test_the_wait_can_be_switched_off(tmp_path):
    """gorod without a script does not wait for navigation at all, so the
    driver and the script go together."""
    argv = scan_argv(DOCKER, _paths(tmp_path), settle_ms=0)
    assert "--driver" not in argv and "--javascript" not in argv
    assert argv[argv.index("--delay") + 1] == "3"


def test_the_session_passes_the_configured_wait(tmp_path, monkeypatch):
    from seek.config import Config
    from seek.nmap.session import Session

    config = Config(nmap_path="/nonexistent/nmap", gowitness_settle_ms=4000,
                    gowitness_settle_cap_ms=30_000, gowitness_settle_delay_s=2)
    session = Session(config, [], tmp_path, databases=[], scans=None)
    session.gowitness = DOCKER
    monkeypatch.setattr("seek.nmap.session.export_urls", lambda records: list(records))
    run = session.plan_capture(["https://192.0.2.1:443"])
    assert settle_script(4000, 30_000) in run.argv
    assert run.argv[run.argv.index("--delay") + 1] == "2"
    remote_argv = run.copy_remote.splitlines()[-1]
    assert "--delay 2" in remote_argv, "the snippet for another machine waits the same"


def _planning_session(tmp_path, monkeypatch, probe):
    from seek.config import Config
    from seek.nmap.session import Session

    session = Session(Config(nmap_path="/nonexistent/nmap"), [], tmp_path,
                      databases=[], scans=None)
    session.gowitness = probe
    monkeypatch.setattr("seek.nmap.session.export_urls", lambda records: list(records))
    return session


def test_a_plan_writes_nothing(tmp_path, monkeypatch):
    """A review that is cancelled or only copied leaves the disk as it was."""
    session = _planning_session(tmp_path, monkeypatch, NATIVE)
    run = session.plan_capture(["https://192.0.2.1:443"])
    assert run.blocked is None and run.copy_local and run.copy_remote
    assert not run.paths.root.exists()


def test_without_gowitness_a_plan_can_still_be_copied(tmp_path, monkeypatch):
    import pytest

    from seek.nmap.session import ScanError

    session = _planning_session(tmp_path, monkeypatch, Probe(reason="not on PATH"))
    run = session.plan_capture(["https://192.0.2.1:443"])
    assert run.blocked == "gowitness unavailable: not on PATH"
    assert run.copy_local is None
    assert "https://192.0.2.1:443" in run.copy_remote and str(tmp_path) not in run.copy_remote
    with pytest.raises(ScanError, match="unavailable"):
        session.start_capture(run)
    assert not run.paths.root.exists()


def test_a_busy_capture_blocks_the_start_and_keeps_its_list(tmp_path, monkeypatch):
    session = _planning_session(tmp_path, monkeypatch, NATIVE)
    running = CaptureRun(argv=["sleep"], paths=_paths(tmp_path), urls=["http://a:80"])
    write_urls(running.paths, running.urls)
    session.captures.claim(running)
    run = session.plan_capture(["https://192.0.2.1:443"])
    assert run.blocked and "already running" in run.blocked
    assert running.paths.urls.read_text() == "http://a:80\n"
