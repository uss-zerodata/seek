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


def test_help_shows_the_search_options_not_just_the_command_list(monkeypatch):
    """`seek --help` used to show only the command list, hiding every flag.

    They lived on the default `search` command, one `seek search --help` away,
    so a user reading `seek --help` concluded they did not exist.
    """
    import seek.cli as cli

    captured = {}

    def fake_app(argv):
        captured["argv"] = argv

    monkeypatch.setattr(cli, "app", fake_app)
    monkeypatch.setattr(cli.sys, "argv", ["seek", "--help"])
    cli.main()
    assert captured["argv"] == ["search", "--help"], "routed to the default command"

    # and the search help itself carries the options and points at the rest
    out = runner.invoke(app, ["search", "--help"]).output
    for flag in ("--file", "--content", "--config-path", "--init-config"):
        assert flag in out
    assert "seek nmap" in out and "seek init" in out, "other commands are discoverable"


def test_a_bare_pattern_still_reaches_search(monkeypatch):
    import seek.cli as cli

    captured = {}
    monkeypatch.setattr(cli, "app", lambda argv: captured.update(argv=argv))
    monkeypatch.setattr(cli.sys, "argv", ["seek", "foo*.py"])
    cli.main()
    assert captured["argv"] == ["search", "foo*.py"]


def test_a_subcommand_is_not_rewritten(monkeypatch):
    import seek.cli as cli

    captured = {}
    monkeypatch.setattr(cli, "app", lambda argv: captured.update(argv=argv))
    monkeypatch.setattr(cli.sys, "argv", ["seek", "nmap", "scan.xml"])
    cli.main()
    assert captured["argv"] == ["nmap", "scan.xml"], "nmap dispatches, not swallowed"


def test_init_config_writes_a_starter_and_will_not_clobber(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    dest = tmp_path / "seek" / "config.toml"

    first = runner.invoke(app, ["search", "--init-config"])
    assert first.exit_code == 0
    assert dest.exists() and "[nmap_presets]" in dest.read_text()
    assert str(dest) in first.output

    dest.write_text("# my edits\n")
    second = runner.invoke(app, ["search", "--init-config"])
    assert second.exit_code == 1, "an existing config is never overwritten"
    assert dest.read_text() == "# my edits\n", "the user's file is untouched"
    assert "already exists" in second.output


def test_the_installed_config_is_what_the_app_reads(tmp_path, monkeypatch):
    """Closes the loop the user hit: editing the template changed nothing."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    runner.invoke(app, ["search", "--init-config"])
    dest = tmp_path / "seek" / "config.toml"
    text = dest.read_text().replace('default_editor = "nvim"', 'default_editor = "hx"')
    dest.write_text(text)
    from seek.config import load_config
    assert load_config().default_editor == "hx", "the edit is picked up"


def test_a_broken_config_is_reported_not_silently_ignored(tmp_path, monkeypatch):
    """A typo in the config must not fall back to defaults behind the user's back.

    Both the search and the nmap paths must say what is wrong and stop, rather
    than the nmap viewer quietly using defaults — which reads as "my edits are
    ignored".
    """
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    cfg = tmp_path / "seek" / "config.toml"
    cfg.parent.mkdir(parents=True)
    cfg.write_text('default_editor = "does-not-exist"\n')

    for argv in (["search"], ["nmap", "scan.xml"]):
        result = runner.invoke(app, argv)
        assert result.exit_code == 2, argv
        assert "does-not-exist" in result.output, argv
