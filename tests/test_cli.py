from typer.testing import CliRunner

from seek.cli import app

runner = CliRunner()


def test_init_zsh():
    r = runner.invoke(app, ["init", "zsh"])
    assert r.exit_code == 0
    assert "seek()" in r.stdout


def test_init_unsupported_shell():
    r = runner.invoke(app, ["init", "powershell"])
    assert r.exit_code == 2
    assert "bash" in r.output and "zsh" in r.output


def test_config_path():
    r = runner.invoke(app, ["search", "--config-path"])
    assert r.exit_code == 0
    assert r.stdout.strip().endswith("config.toml")


def test_invalid_regex_exits_before_ui():
    r = runner.invoke(app, ["search", "-r", "["])
    assert r.exit_code == 2
    assert "invalid regex" in r.output


def test_non_interactive_stdout(monkeypatch):
    monkeypatch.setattr("seek.cli._stdout_is_usable", lambda: False)
    r = runner.invoke(app, ["search"])
    assert r.exit_code == 1
    assert "interactive terminal" in r.output


def test_mode_resolution_via_session(monkeypatch):
    captured = {}

    def fake_run(session):
        captured["modes"] = session.modes
        captured["patterns"] = session.patterns
        return 0

    monkeypatch.setattr("seek.cli._stdout_is_usable", lambda: True)
    monkeypatch.setattr("seek.tui.app.run_session", fake_run)
    r = runner.invoke(app, ["search", "-f", "-d", "x*.py"])
    assert r.exit_code == 0
    assert captured["modes"].file and captured["modes"].dir
    assert not captured["modes"].content
    assert captured["patterns"] == ["x*.py"]
