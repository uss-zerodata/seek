"""Looking for gowitness: two backends, three modes, and absence as an answer.

`subprocess.run` and `shutil.which` are patched rather than a real docker being
required - the point of these tests is the decision table, not the daemon.
"""

from __future__ import annotations

import subprocess

import pytest

from seek.config import Config, ConfigError
from seek.gowitness import detect


class _Done:
    def __init__(self, returncode: int = 0, stdout: str = "27.0.3", stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _patch(monkeypatch, *, docker: bool, daemon: bool | str, native: bool):
    """Wire up a machine: is docker installed, does its daemon answer, is
    gowitness on PATH. `daemon` may be a string, standing for its error."""

    def which(name):
        if name == "docker":
            return "/usr/bin/docker" if docker else None
        return "/usr/bin/gowitness" if native else None

    def run(argv, **_kwargs):
        if daemon is True:
            return _Done()
        if isinstance(daemon, str):
            return _Done(returncode=1, stderr=daemon)
        return _Done(returncode=1, stderr="Cannot connect to the Docker daemon")

    monkeypatch.setattr(detect.shutil, "which", which)
    monkeypatch.setattr(detect.subprocess, "run", run)


# --- auto ---------------------------------------------------------------


def test_auto_prefers_docker_when_the_daemon_answers(monkeypatch):
    _patch(monkeypatch, docker=True, daemon=True, native=True)
    probe = detect.probe("auto")
    assert probe.available
    assert probe.backend == "docker"
    assert probe.image == detect.DEFAULT_IMAGE


def test_auto_falls_back_to_native_when_docker_is_absent(monkeypatch):
    _patch(monkeypatch, docker=False, daemon=False, native=True)
    probe = detect.probe("auto")
    assert (probe.available, probe.backend) == (True, "native")


def test_a_dead_daemon_is_not_a_usable_docker(monkeypatch):
    """A docker binary with no daemon behind it is the common broken case -
    finding the client on PATH is not the question worth asking."""
    _patch(monkeypatch, docker=True, daemon=False, native=True)
    probe = detect.probe("auto")
    assert probe.backend == "native", "fell back rather than choosing a dead docker"


def test_neither_backend_available(monkeypatch):
    _patch(monkeypatch, docker=False, daemon=False, native=False)
    probe = detect.probe("auto")
    assert not probe.available
    assert "docker is not on PATH" in probe.reason
    assert "gowitness is not on PATH" in probe.reason


def test_auto_reports_both_reasons_when_the_daemon_is_dead(monkeypatch):
    _patch(monkeypatch, docker=True, daemon="Cannot connect to the Docker daemon",
           native=False)
    probe = detect.probe("auto")
    assert not probe.available
    assert "Docker daemon" in probe.reason


# --- pinned -------------------------------------------------------------


def test_pinned_docker_never_falls_back(monkeypatch):
    """Silently using the other backend would hide the very thing the setting
    was used to express."""
    _patch(monkeypatch, docker=False, daemon=False, native=True)
    probe = detect.probe("docker")
    assert not probe.available, "fell back to native despite being pinned"
    assert "docker was pinned" in probe.reason


def test_pinned_native_never_falls_back(monkeypatch):
    _patch(monkeypatch, docker=True, daemon=True, native=False)
    probe = detect.probe("native")
    assert not probe.available
    assert "native was pinned" in probe.reason


def test_pinned_backend_that_is_present(monkeypatch):
    _patch(monkeypatch, docker=True, daemon=True, native=True)
    assert detect.probe("docker").backend == "docker"
    assert detect.probe("native").backend == "native"


# --- errors are answers, not exceptions ---------------------------------


@pytest.mark.parametrize("boom", [OSError(1, "boom"), subprocess.TimeoutExpired("d", 5)])
def test_a_docker_that_cannot_be_run_is_a_reason_not_a_crash(monkeypatch, boom):
    def which(name):
        return "/usr/bin/docker" if name == "docker" else None

    def run(argv, **_kwargs):
        raise boom

    monkeypatch.setattr(detect.shutil, "which", which)
    monkeypatch.setattr(detect.subprocess, "run", run)
    probe = detect.probe("docker")
    assert not probe.available and probe.reason


# --- the status-bar label ------------------------------------------------


def test_the_label_names_the_backend_in_words():
    """Symbol and words, never colour alone - and which backend, because a
    containerised run behaves differently from a native one."""
    assert detect.Probe(backend="docker", path="/usr/bin/docker").label() == (
        "◉ gowitness docker")
    assert detect.Probe(backend="native", path="/usr/bin/gowitness").label() == (
        "◉ gowitness native")
    assert detect.Probe(reason="nothing found").label() == "◉ gowitness not found"


# --- configuration -------------------------------------------------------


def test_config_defaults_are_docker_first():
    cfg = Config()
    assert cfg.gowitness_mode == "auto"
    assert cfg.gowitness_image == detect.DEFAULT_IMAGE
    assert cfg.gowitness_report_port == 7171


def test_an_unknown_mode_is_refused(tmp_path):
    from seek.config import load_config

    path = tmp_path / "seek.toml"
    path.write_text('gowitness_mode = "podman"\n')
    with pytest.raises(ConfigError, match="must be one of"):
        load_config(path)


def test_a_valid_mode_is_accepted(tmp_path):
    from seek.config import load_config

    path = tmp_path / "seek.toml"
    path.write_text('gowitness_mode = "native"\n')
    assert load_config(path).gowitness_mode == "native"


def test_an_out_of_range_report_port_is_refused(tmp_path):
    from seek.config import load_config

    path = tmp_path / "seek.toml"
    path.write_text("gowitness_report_port = 99999\n")
    with pytest.raises(ConfigError, match="between 1 and 65535"):
        load_config(path)


def test_the_example_config_documents_every_gowitness_key():
    from seek.config import example_toml

    text = example_toml()
    for key in ("gowitness_mode", "gowitness_path", "gowitness_image",
                "gowitness_report_host", "gowitness_report_port",
                "gowitness_chrome_path"):
        assert f"{key} = " in text, f"{key} is not in the shipped example"
