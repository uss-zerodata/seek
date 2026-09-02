"""Configuration: built-in defaults, TOML loading + validation, and precedence.

Precedence for any setting: explicit CLI flag > config file > built-in default.
The CLI layer is responsible for applying flag overrides on top of
:func:`load_config`.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path

from seek.nmap.presets import DEFAULT_PRESETS, CommandError, parse_args
from seek.paths import config_file

# Directories pruned before descending, unless ``apply_noise_excludes`` is off.
# ``.git`` is always pruned regardless of that setting.
DEFAULT_NOISE_DIRS: tuple[str, ...] = (
    "node_modules",
    ".venv",
    "__pycache__",
    "target",
    "dist",
)

# Extensions whose files are candidates for re-indenting before indexing.
DEFAULT_FORMAT_EXTENSIONS: tuple[str, ...] = (
    "json", "jsonl", "yaml", "yml", "xml", "html", "htm", "svg", "css", "js",
)

DEFAULT_EDITORS: dict[str, str] = {
    "nvim": "nvim +{line} {file}",
    "vim": "vim +{line} {file}",
    "code": "code --goto {file}:{line}",
    "emacs": "emacs +{line} {file}",
    "hx": "hx {file}:{line}",
}

DEFAULT_KEYS: dict[str, str] = {
    "open_default": "ctrl+o",
    "open_editor": "ctrl+e",
    "open_code": "ctrl+b",
    "copy": "ctrl+y",
    "export": "ctrl+x",
    "goto_dir": "alt+c",
    "action_menu": "ctrl+k",
    "toggle_file": "ctrl+f",
    "toggle_dir": "ctrl+underscore",
    "toggle_content": "ctrl+t",
    "toggle_format": "ctrl+n",
    "reroot": "ctrl+r",
    "breadcrumb_pop": "alt+left",
    "refresh": "ctrl+g",
    "history_prev": "alt+up",
    "history_next": "alt+down",
    "mark": "tab",
    "clear_marks": "shift+tab",
    "help": "question_mark",
}

# Rich style names (these style Rich Text in the result rows), not Textual CSS.
DEFAULT_THEME: dict[str, str] = {
    "match": "bold bright_yellow",
    "marker_filename": "blue",
    "marker_dirname": "cyan",
    "marker_content": "green",
    "selected": "bright_magenta",
    "matched_line": "bright_black",
    "path": "cyan",  # directory portion of a name row / path prefix of a content row
    "basename": "default",  # the file's own name
    "content": "default",  # the matching source line text
    "tree_dir": "bold blue",  # directory names in the tree view
    "tree_branch": "bright_black",  # the ├── │ └── branch glyphs
}


class ConfigError(Exception):
    """Raised for a missing key, wrong type, or unparseable config file."""


@dataclass(slots=True)
class Config:
    debounce_ms: int = 150
    min_content_query: int = 2
    preview_size_cap: int = 5 * 1024 * 1024
    detail_size_cap: int = 5 * 1024 * 1024
    content_size_cap: int = 5 * 1024 * 1024
    preview_window_lines: int = 200
    max_results: int = 500
    publish_interval_ms: int = 500
    format_content: bool = True
    format_min_line: int = 500
    content_cache_budget: int = 512 * 1024 * 1024
    honor_gitignore: bool = False
    apply_noise_excludes: bool = True
    absolute_output: bool = False
    wrap_results: bool = False
    exclude_globs: list[str] = field(default_factory=list)
    noise_dirs: list[str] = field(default_factory=lambda: list(DEFAULT_NOISE_DIRS))
    format_extensions: list[str] = field(
        default_factory=lambda: list(DEFAULT_FORMAT_EXTENSIONS)
    )
    default_editor: str = "nvim"
    editors: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_EDITORS))
    keys: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_KEYS))
    theme: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_THEME))
    nmap_path: str = "nmap"
    scan_output_dir: str = ""      # empty: the directory the viewer was opened on
    # How to run gowitness. "auto" prefers the container and falls back to a
    # native binary; naming one pins it, and a pinned backend never falls back.
    gowitness_mode: str = "auto"
    gowitness_path: str = "gowitness"
    gowitness_image: str = "ghcr.io/sensepost/gowitness"
    gowitness_report_host: str = "127.0.0.1"
    gowitness_report_port: int = 7171
    # Empty: let gowitness fetch its own browser. Set when Chrome is already
    # installed and the download is unwanted.
    gowitness_chrome_path: str = ""
    # Off by default: gowitness warns that recording response content can
    # make a capture directory grow without a useful bound, and nothing
    # shown by default needs it. Affects collection only, never reading.
    gowitness_collect_all: bool = False
    # name -> nmap arguments. Unlike the other tables this one *replaces* the
    # default when the user defines any: a curated list of the commands you
    # actually run should be exactly what the app offers.
    nmap_presets: dict[str, str] = field(
        default_factory=lambda: dict(DEFAULT_PRESETS))
    # Presets that could not be read, kept rather than raised: one bad line
    # should not stop the whole configuration from loading.
    preset_errors: list[str] = field(default_factory=list)

    def with_overrides(self, **overrides: object) -> Config:
        """Return a copy with the given non-None overrides applied (CLI layer)."""
        clean = {k: v for k, v in overrides.items() if v is not None}
        return replace(self, **clean) if clean else self


# Mapping of TOML key -> (dataclass field, expected python type)
_SCALAR_KEYS: dict[str, type | tuple[type, ...]] = {
    "debounce_ms": int,
    "min_content_query": int,
    "preview_size_cap": int,
    "detail_size_cap": int,
    "content_size_cap": int,
    "preview_window_lines": int,
    "max_results": int,
    "publish_interval_ms": int,
    "format_content": bool,
    "format_min_line": int,
    "content_cache_budget": int,
    "honor_gitignore": bool,
    "apply_noise_excludes": bool,
    "absolute_output": bool,
    "wrap_results": bool,
    "default_editor": str,
    "nmap_path": str,
    "scan_output_dir": str,
    "gowitness_mode": str,
    "gowitness_path": str,
    "gowitness_image": str,
    "gowitness_report_host": str,
    "gowitness_report_port": int,
    "gowitness_chrome_path": str,
    "gowitness_collect_all": bool,
}
# Minimum (and where one is meaningful, maximum) for each numeric key.
# Types alone were checked before, which let values through that quietly break
# the engine: `max_results = 0` makes `engine._admits` accept everything, so the
# result heap grows without bound and the cap that makes peak memory
# predictable is gone. A caps of 0 or a negative budget are the same kind of
# mistake, just less dramatic.
_RANGES: dict[str, tuple[int, int | None]] = {
    "debounce_ms": (0, 60_000),
    "min_content_query": (0, None),
    "preview_size_cap": (1, None),
    "detail_size_cap": (1, None),
    "content_size_cap": (1, None),
    "preview_window_lines": (1, None),
    "max_results": (1, None),
    "publish_interval_ms": (0, 60_000),
    "format_min_line": (1, None),
    "content_cache_budget": (0, None),
    "gowitness_report_port": (1, 65_535),
}

# Keys whose value must be one of a fixed set. A typo in one of these is not a
# preference, it is a setting that will not do what it says.
_CHOICES: dict[str, tuple[str, ...]] = {
    "gowitness_mode": ("auto", "docker", "native"),
}

_LIST_KEYS = {"exclude_globs", "noise_dirs", "format_extensions"}
_TABLE_KEYS = {"editors", "keys", "theme"}
# Tables the user's version replaces wholesale rather than merging into ours.
_REPLACE_TABLE_KEYS = {"nmap_presets"}
_ALL_KEYS = set(_SCALAR_KEYS) | _LIST_KEYS | _TABLE_KEYS | _REPLACE_TABLE_KEYS


def _validate(raw: dict, source: Path) -> Config:
    unknown = set(raw) - _ALL_KEYS
    if unknown:
        raise ConfigError(
            f"{source}: unknown config key(s): {', '.join(sorted(unknown))}"
        )
    cfg = Config()
    for key, expected in _SCALAR_KEYS.items():
        if key not in raw:
            continue
        value = raw[key]
        # bool is a subclass of int; guard against silent coercion
        if expected is int and isinstance(value, bool):
            raise ConfigError(f"{source}: '{key}' must be an integer, got a boolean")
        if not isinstance(value, expected):
            raise ConfigError(
                f"{source}: '{key}' must be {expected.__name__}, got "
                f"{type(value).__name__}"
            )
        bounds = _RANGES.get(key)
        if bounds is not None:
            low, high = bounds
            if value < low or (high is not None and value > high):
                allowed = f"at least {low}" if high is None else f"between {low} and {high}"
                raise ConfigError(f"{source}: '{key}' must be {allowed}, got {value}")
        choices = _CHOICES.get(key)
        if choices is not None and value not in choices:
            raise ConfigError(f"{source}: '{key}' must be one of "
                              f"{', '.join(choices)}, got {value!r}")
        setattr(cfg, key, value)
    for key in _LIST_KEYS:
        if key not in raw:
            continue
        value = raw[key]
        if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
            raise ConfigError(f"{source}: '{key}' must be a list of strings")
        setattr(cfg, key, list(value))
    for key in _TABLE_KEYS:
        if key not in raw:
            continue
        value = raw[key]
        if not isinstance(value, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in value.items()
        ):
            raise ConfigError(f"{source}: '{key}' must be a table of string values")
        merged = getattr(cfg, key)
        merged.update(value)
        setattr(cfg, key, merged)
    for key in _REPLACE_TABLE_KEYS:
        if key not in raw:
            continue
        value = raw[key]
        if not isinstance(value, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in value.items()
        ):
            raise ConfigError(f"{source}: '{key}' must be a table of string values")
        setattr(cfg, key, dict(value))
    _check_presets(cfg, source)
    if cfg.default_editor not in cfg.editors:
        raise ConfigError(
            f"{source}: default_editor '{cfg.default_editor}' is not in [editors]"
        )
    _known_actions = set(DEFAULT_KEYS)
    bad_actions = set(cfg.keys) - _known_actions
    if bad_actions:
        raise ConfigError(
            f"{source}: [keys] has unknown action(s): {', '.join(sorted(bad_actions))}"
        )
    if "keys" in raw:
        _validate_keys(cfg.keys, source)
    return cfg


def _check_presets(cfg: Config, source: Path) -> None:
    """Drop a preset that cannot be run, and record why.

    A mistyped preset is one line of a config file; refusing to start over it
    would be out of proportion, and silently offering a command that cannot run
    is worse. So the bad one goes and the app reports it.
    """
    kept: dict[str, str] = {}
    for name, args in cfg.nmap_presets.items():
        try:
            parse_args(args)
        except CommandError as exc:
            cfg.preset_errors.append(f"{source}: preset {name!r}: {exc}")
        else:
            kept[name] = args
    cfg.nmap_presets = kept


_KEY_MODIFIERS = frozenset({"ctrl", "control", "shift", "alt", "option", "meta",
                            "super", "hyper", "cmd"})
_key_names: frozenset[str] | None = None


def _known_key_names() -> frozenset[str]:
    """Every key name Textual will ever report, resolved once and cached.

    Imported lazily: `seek --config-path` and a run with no ``[keys]`` table
    should not pay for importing the whole TUI toolkit.
    """
    global _key_names
    if _key_names is None:
        from textual.keys import Keys, _character_to_key

        names = {k.value for k in Keys}
        # Printable characters are reported under a name (`?` -> `question_mark`),
        # which is how `DEFAULT_KEYS` spells them.
        names |= {_character_to_key(chr(code)) for code in range(0x20, 0x7F)}
        _key_names = frozenset(names)
    return _key_names


def _validate_keys(keys: dict[str, str], source: Path) -> None:
    """Reject key specs Textual cannot bind, and two actions on one key.

    Both failures are otherwise completely silent: a misspelled key name binds
    against something no keypress produces, and a duplicate leaves whichever
    action lost the race simply unreachable. Neither reports anything at any
    point - the action just does nothing for ever.
    """
    known = _known_key_names()
    for action, spec in sorted(keys.items()):
        if not _valid_key(spec, known):
            raise ConfigError(
                f"{source}: [keys] {action} = {spec!r} is not a key Textual "
                f"recognises (e.g. 'ctrl+y', 'alt+up', 'question_mark', 'f2')"
            )
    seen: dict[str, str] = {}
    for action, spec in sorted(keys.items()):
        if spec in seen:
            raise ConfigError(
                f"{source}: [keys] binds {spec!r} to both {seen[spec]!r} and "
                f"{action!r}; one of them would never run"
            )
        seen[spec] = action


def _valid_key(spec: str, known: frozenset[str]) -> bool:
    if not spec or any(c.isspace() for c in spec):
        return False
    if spec in known:
        return True
    *mods, base = spec.split("+")
    if not base or any(m.lower() not in _KEY_MODIFIERS for m in mods):
        return False
    return base in known or len(base) == 1


def load_config(path: Path | None = None) -> Config:
    """Load configuration. Missing file -> defaults. Bad file -> ConfigError."""
    source = path or config_file()
    if not source.exists():
        return Config()
    try:
        raw = tomllib.loads(source.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{source}: invalid TOML: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"{source}: could not read config file: {exc}") from exc
    return _validate(raw, source)


_EXAMPLE_COMMENTS = {
    "debounce_ms": "idle ms after the last keystroke before re-searching",
    "min_content_query": "min positive-term length before content search runs",
    "preview_size_cap": "bytes; larger files are truncated in the side preview",
    "detail_size_cap": "bytes; larger files are truncated in the detail view",
    "content_size_cap": "bytes; at most this much of any one file is content-searched",
    "preview_window_lines": "lines shown in the side preview window",
    "max_results": "max rows kept in the result list (rest shown as '+N more')",
    "publish_interval_ms": "min ms between streamed partial-result updates (0 = every batch)",
    "format_content": "re-indent over-long structured files before indexing them",
    "format_min_line": "chars; a file is only reformatted if some line exceeds this",
    "content_cache_budget": "bytes of decoded file content kept in memory",
    "honor_gitignore": "apply .gitignore / .ignore rules while walking",
    "apply_noise_excludes": "prune noise_dirs (.git is always pruned)",
    "absolute_output": "emit absolute paths instead of root-relative ones",
    "wrap_results": "wrap long result rows instead of shortening them to one line",
    "exclude_globs": "extra globs pruned from the walk",
    "noise_dirs": "directory names pruned unless apply_noise_excludes is false",
    "format_extensions": "file extensions considered for re-indenting",
    "default_editor": "which [editors] entry the editor action uses",
    "nmap_path": "the nmap program to run (looked up on PATH when not a path)",
    "scan_output_dir": "where scans write; empty means the directory the viewer was opened on",
    "gowitness_mode": "how to run gowitness: auto (docker, then native), docker, or native",
    "gowitness_path": "the gowitness program to run, for the native backend",
    "gowitness_image": "the container image to run, for the docker backend",
    "gowitness_report_host": "address the gowitness report server binds to",
    "gowitness_report_port": "port the gowitness report server listens on",
    "gowitness_chrome_path": "a Chrome binary for gowitness to use; empty lets it fetch its own",
    "gowitness_collect_all": "record network logs, cookies and response bodies too (large)",
}


def _toml_value(value: object) -> str:
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, str):
        return f'"{value}"'
    if isinstance(value, list):
        return "[" + ", ".join(f'"{v}"' for v in value) + "]"
    return str(value)


def example_toml() -> str:
    """A commented example config with every key at its default value."""
    d = Config()
    out = [
        "# seek configuration - every key shown at its default value.",
        "# Install a copy at the right path with `seek --init-config`, then edit",
        "# that file (its path is `seek --config-path`). Editing THIS example does",
        "# nothing - the app reads the installed copy, not this template.",
        "",
    ]
    for key in _SCALAR_KEYS:
        out.append(f"{key} = {_toml_value(getattr(d, key))}  # {_EXAMPLE_COMMENTS[key]}")
    for key in ("exclude_globs", "noise_dirs", "format_extensions"):
        out.append(f"{key} = {_toml_value(getattr(d, key))}  # {_EXAMPLE_COMMENTS[key]}")
    out += ["", "[editors]  # name = command template, with {file} and {line}"]
    out += [f'{k} = {_toml_value(v)}' for k, v in DEFAULT_EDITORS.items()]
    out += ["", "[keys]  # action = key (Textual key names)"]
    out += [f'{k} = {_toml_value(v)}' for k, v in DEFAULT_KEYS.items()]
    out += [
        "",
        "# Scan presets: a name you pick from, and the nmap arguments it stands",
        "# for. Defining any replaces this whole table, so your list is exactly",
        "# what the app offers. Whether a preset needs root is worked out from",
        "# its flags - do not declare it. The output flags, the targets and any",
        "# elevation are added for you, so leave out -iL, -oA/-oX and sudo.",
        "# `{ports}` expands to the open ports already in the model - the step",
        "# you would otherwise grep out of the previous scan's .gnmap.",
        "[nmap_presets]",
    ]
    out += [f'"{k}" = {_toml_value(v)}' for k, v in DEFAULT_PRESETS.items()]
    out += ["", "[theme]  # style name = Rich/Textual color"]
    out += [f'{k} = {_toml_value(v)}' for k, v in DEFAULT_THEME.items()]
    out.append("")
    return "\n".join(out)

