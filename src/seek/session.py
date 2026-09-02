"""The resolved configuration handed from the CLI to the interactive session."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from seek.config import Config
from seek.engine.engine import Modes
from seek.scope import Scope


@dataclass(slots=True)
class SessionConfig:
    root: Path
    modes: Modes
    scope: Scope
    config: Config
    regex: bool = False
    patterns: tuple[str, ...] | list[str] = ()
