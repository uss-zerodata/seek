"""Building the capture command, and reading what it says.

The argv assertions are pinned against the interface that was measured, not the
one the reference workflow documents - the extra `gowitness` word the reference
passes is rejected by the current image, whose entrypoint is already gowitness.
The log lines parsed here are verbatim from a real v3 run.
"""

from __future__ import annotations

from seek.gowitness.capture import (
    CaptureRun,
    Paths,
    capture_dir,
    report_argv,
    scan_argv,
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
        assert "--write-jsonl" in argv
        assert "--skip-html" in argv and "--skip-network-logs" in argv


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
