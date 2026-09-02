"""Per-platform resolution of the config and state directories.

Hand-rolled (no ``platformdirs`` dependency): the rules are short and stable.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

APP = "seek"


def _home() -> Path:
    return Path(os.path.expanduser("~"))


def config_dir() -> Path:
    if sys.platform == "win32":
        base = os.environ.get("APPDATA")
        root = Path(base) if base else _home() / "AppData" / "Roaming"
        return root / APP
    if sys.platform == "darwin":
        return _home() / "Library" / "Application Support" / APP
    base = os.environ.get("XDG_CONFIG_HOME")
    root = Path(base) if base else _home() / ".config"
    return root / APP


def state_dir() -> Path:
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA")
        root = Path(base) if base else _home() / "AppData" / "Local"
        return root / APP
    if sys.platform == "darwin":
        return _home() / "Library" / "Application Support" / APP
    base = os.environ.get("XDG_STATE_HOME")
    root = Path(base) if base else _home() / ".local" / "state"
    return root / APP


def config_file() -> Path:
    return config_dir() / "config.toml"


def history_file() -> Path:
    return state_dir() / "history"
