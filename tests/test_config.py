import pytest

from seek import paths
from seek.config import Config, ConfigError, example_toml, load_config


def test_missing_file_uses_defaults(tmp_path):
    cfg = load_config(tmp_path / "nope.toml")
    assert cfg == Config()


def test_example_toml_roundtrips(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text(example_toml())
    cfg = load_config(p)
    assert cfg.debounce_ms == 150
    assert cfg.editors["hx"] == "hx {file}:{line}"
    assert cfg.keys["copy"] == "ctrl+y"


def test_invalid_toml(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text("this is = = not toml")
    with pytest.raises(ConfigError) as exc:
        load_config(p)
    assert str(p) in str(exc.value)


def test_unknown_key(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text("wat = 1\n")
    with pytest.raises(ConfigError) as exc:
        load_config(p)
    assert "wat" in str(exc.value)


def test_wrong_type(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text('debounce_ms = "fast"\n')
    with pytest.raises(ConfigError):
        load_config(p)


def test_bool_not_accepted_as_int(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text("debounce_ms = true\n")
    with pytest.raises(ConfigError):
        load_config(p)


def test_default_editor_must_exist(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text('default_editor = "nano"\n')
    with pytest.raises(ConfigError):
        load_config(p)


def test_unknown_key_action(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text("[keys]\nfrobnicate = \"ctrl+z\"\n")
    with pytest.raises(ConfigError):
        load_config(p)


def test_precedence_flag_over_config():
    cfg = Config(honor_gitignore=True)
    assert cfg.with_overrides(honor_gitignore=False).honor_gitignore is False
    assert cfg.with_overrides(honor_gitignore=None).honor_gitignore is True


def test_config_path_platform(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setattr("sys.platform", "linux")
    assert paths.config_dir() == tmp_path / "cfg" / "seek"


# --- value ranges -----------------------------------------------------------


def _write(tmp_path, text):
    p = tmp_path / "config.toml"
    p.write_text(text)
    return p


def test_max_results_of_zero_is_rejected(tmp_path):
    """`max_results = 0` silently removed the result cap.

    `engine._admits` short-circuits on `cap <= 0`, so every match was built and
    pushed and the heap grew with the corpus - losing exactly the bounded-memory
    property the cap exists to provide, with no error anywhere.
    """
    with pytest.raises(ConfigError, match="max_results.*at least 1"):
        load_config(_write(tmp_path, "max_results = 0"))


@pytest.mark.parametrize(
    "line",
    [
        "debounce_ms = -500",
        "content_size_cap = -1",
        "preview_size_cap = 0",
        "detail_size_cap = 0",
        "preview_window_lines = 0",
        "format_min_line = 0",
        "content_cache_budget = -9",
        "min_content_query = -1",
        "publish_interval_ms = -1",
        "gowitness_settle_delay_s = -1",
        "gowitness_settle_delay_s = 31",
    ],
)
def test_out_of_range_numbers_are_rejected(tmp_path, line):
    with pytest.raises(ConfigError):
        load_config(_write(tmp_path, line))


@pytest.mark.parametrize(
    "line",
    ["debounce_ms = 0", "publish_interval_ms = 0", "content_cache_budget = 0",
     "max_results = 1", "min_content_query = 0", "gowitness_settle_delay_s = 0",
     "gowitness_settle_delay_s = 30"],
)
def test_meaningful_edge_values_are_accepted(tmp_path, line):
    load_config(_write(tmp_path, line))


def test_defaults_satisfy_their_own_ranges(tmp_path):
    load_config(_write(tmp_path, example_toml()))


# --- key specs --------------------------------------------------------------


@pytest.mark.parametrize("spec", ["not a real key", "ctrl+zzz", "", "nonsense", "ctrl+"])
def test_unbindable_key_is_rejected(tmp_path, spec):
    """An unrecognised key name is otherwise completely silent.

    It binds against something no keypress ever produces, so the action just
    stops working - with nothing reported at load, at bind time, or on the press.
    """
    with pytest.raises(ConfigError, match="not a key Textual recognises"):
        load_config(_write(tmp_path, f'[keys]\ncopy = "{spec}"'))


@pytest.mark.parametrize("spec", ["ctrl+w", "f2", "home", "end", "alt+right", "delete"])
def test_real_key_specs_are_accepted(tmp_path, spec):
    cfg = load_config(_write(tmp_path, f'[keys]\ncopy = "{spec}"'))
    assert cfg.keys["copy"] == spec


@pytest.mark.parametrize(
    "spec", ["ctrl+y", "alt+up", "alt+left", "question_mark", "shift+tab",
             "ctrl+underscore", "tab", "f1", "pageup"],
)
def test_every_shape_seek_itself_uses_is_recognised(spec):
    """The shapes in `DEFAULT_KEYS` must all pass the validator.

    Checked directly rather than through a config file: binding any of these to
    a *different* action would trip the duplicate check first, since seek
    already uses them.
    """
    from seek.config import _known_key_names, _valid_key

    assert _valid_key(spec, _known_key_names())


def test_two_actions_on_one_key_is_rejected(tmp_path):
    """Whichever action lost would simply never run, with no way to notice."""
    with pytest.raises(ConfigError, match="would never run"):
        load_config(_write(tmp_path, '[keys]\ncopy = "ctrl+x"'))


# --- nmap scan presets ------------------------------------------------------


def _write(tmp_path, body: str):
    path = tmp_path / "config.toml"
    path.write_text(body)
    return path


def test_presets_replace_the_default_rather_than_merging(tmp_path):
    path = _write(tmp_path, '[nmap_presets]\n"My scan" = "-sV -T4"\n')
    cfg = load_config(path)
    assert cfg.nmap_presets == {"My scan": "-sV -T4"}, "a curated list is the whole list"


def test_presets_keep_the_order_they_were_written_in(tmp_path):
    path = _write(tmp_path, '[nmap_presets]\n"c" = "-sn"\n"a" = "-sV"\n"b" = "-p-"\n')
    assert list(load_config(path).nmap_presets) == ["c", "a", "b"]


def test_a_preset_that_cannot_be_run_is_dropped_and_reported(tmp_path):
    path = _write(tmp_path, '[nmap_presets]\n"good" = "-sV"\n"bad" = "-sV | tee x"\n')
    cfg = load_config(path)
    assert list(cfg.nmap_presets) == ["good"], "the rest of the config still loads"
    assert cfg.preset_errors and "bad" in cfg.preset_errors[0]


def test_a_preset_carrying_its_own_output_flag_is_dropped(tmp_path):
    path = _write(tmp_path, '[nmap_presets]\n"bad" = "-sV -oX out.xml"\n')
    cfg = load_config(path)
    assert cfg.nmap_presets == {}
    assert "handled for you" in cfg.preset_errors[0]


def test_presets_must_be_a_table_of_strings(tmp_path):
    path = _write(tmp_path, "[nmap_presets]\nquick = 42\n")
    with pytest.raises(ConfigError):
        load_config(path)


def test_the_scan_settings_are_configurable(tmp_path):
    path = _write(tmp_path, 'nmap_path = "/opt/nmap"\nscan_output_dir = "/tmp/scans"\n')
    cfg = load_config(path)
    assert cfg.nmap_path == "/opt/nmap" and cfg.scan_output_dir == "/tmp/scans"


def test_the_example_config_documents_the_presets():
    text = example_toml()
    assert "[nmap_presets]" in text
    assert "01 · Discovery" in text and "02 · Services" in text
    assert "worked out from" in text, "and says privilege is derived, not declared"
