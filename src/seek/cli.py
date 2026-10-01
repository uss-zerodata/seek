"""Command-line entry point.

``seek [options] [patterns...]`` launches the interactive session.
``seek init <bash|zsh>`` prints shell-integration code.
"""

from __future__ import annotations

import shutil
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated

import typer

from seek.config import Config, ConfigError, load_config
from seek.engine.engine import Modes
from seek.paths import config_file
from seek.scope import ScopeError, build_scope
from seek.session import SessionConfig
from seek.shell import SUPPORTED_SHELLS, render_init

app = typer.Typer(
    add_completion=False,
    context_settings={"help_option_names": ["-h", "--help"]},
    help="Interactive terminal search for files, directories, and file contents.",
)

_KNOWN_SUBCOMMANDS = {"search", "init", "nmap", "vulndb"}


@contextmanager
def _search_progress():
    """A one-line report of the scan search, rewritten in place on a terminal.

    An engagement directory can hold thousands of directories, and a search
    that says nothing for several seconds reads as a hang. Nothing is printed
    when stderr is not a terminal - a redirect or a pipe would collect a
    thousand half-lines - so scripts and CI see the output they saw before.

    Written with `\r` and spaces rather than escape codes, so it behaves the
    same wherever the tests run.
    """
    if not sys.stderr.isatty():
        yield None
        return

    width = max(20, min(shutil.get_terminal_size((80, 24)).columns - 1, 100))
    # Seeded with the start time, so a search that finishes inside the interval
    # prints nothing at all: a line that appears and vanishes says less than
    # the scans that follow it.
    last = [time.monotonic()]
    drawn = [False]

    def report(done: int, total: int, unit: str) -> None:
        now = time.monotonic()
        if now - last[0] < 0.1:                     # ~10 redraws a second
            return
        last[0] = now
        if total:
            line = f"seek: reading scans {done}/{total} {unit}"
        else:
            # A total of zero is the walk saying it cannot count itself yet;
            # all it can honestly report is what it has turned up so far.
            line = f"seek: searching for scans - {done} found"
        sys.stderr.write("\r" + line[:width].ljust(width))
        sys.stderr.flush()
        drawn[0] = True

    try:
        yield report
    finally:
        if drawn[0]:
            sys.stderr.write("\r" + " " * width + "\r")
            sys.stderr.flush()


@app.command()
def init(
    shell: Annotated[str, typer.Argument(help="Target shell: bash or zsh")],
) -> None:
    """Print shell-integration code for ``eval "$(seek init <shell>)"``."""
    key = shell.strip().lower()
    if key not in SUPPORTED_SHELLS:
        supported = ", ".join(sorted(SUPPORTED_SHELLS))
        typer.echo(f"seek: unsupported shell {shell!r}; supported: {supported}", err=True)
        raise typer.Exit(code=2)
    typer.echo(render_init(key))


def _typed_serve() -> bool:
    """Whether the first path was typed as the bare word `serve`.

    Asked of the command line itself: a `Path` prints `./serve` as `serve`,
    and `./serve` is exactly how to name a directory of that name.
    """
    args = sys.argv[1:]
    if "nmap" in args:
        args = args[args.index("nmap") + 1:]
    first = next((a for a in args if not a.startswith("-")), None)
    return first == "serve"


@app.command()
def nmap(
    paths: Annotated[
        list[Path] | None,
        typer.Argument(
            help="nmap XML files and directories to search, as many as you "
                 "like, merged into one view (default: the working directory).",
        ),
    ] = None,
    serve: Annotated[
        bool, typer.Option("--serve", help="Run the web interface without the terminal "
                                           "viewer (also: `seek nmap serve PATHS…`).")
    ] = False,
    open_browser: Annotated[
        bool, typer.Option("--open", help="With serve: open the browser once it listens.")
    ] = False,
) -> None:
    """Browse one or more nmap XML scans, consolidated.

    A directory is searched all the way down, so an engagement directory can be
    named instead of its files; with nothing named at all the working directory
    is searched, which is where a scan was run from. Several directories are
    read as one engagement; their scans are then named by directory
    (`dir1/scan.xml`), and scans started in the viewer write into the first.

    Stateless: the files found are read straight into memory for this run, with
    no import step and nothing written.
    """
    from seek.gowitness.locate import find_databases
    from seek.nmap.merge import Pending, discover, naming

    # `seek nmap serve …` is the headless form - unless `serve` is also a file or
    # directory right here, which is not guessed at: said, and left to the user.
    if paths and str(paths[0]) == "serve" and _typed_serve():
        if Path("serve").exists():
            typer.echo("seek: `serve` is ambiguous - a file or directory of that name is "
                       "here. Use `./serve` for the directory, or `seek nmap --serve` "
                       "for the web interface.", err=True)
            raise typer.Exit(code=2)
        serve = True
        paths = paths[1:]

    # The working directory is the engagement directory often enough that
    # naming it adds nothing, and it is the directory a scan started here would
    # write into anyway.
    paths = list(paths) if paths else [Path.cwd()]

    try:
        config = load_config()
    except ConfigError as exc:
        # Surface it, exactly as `search` does: a typo in the config must not be
        # swallowed into a silent fall-back to defaults, which reads to the user
        # as "my edits are being ignored".
        typer.echo(f"seek: {exc}", err=True)
        raise typer.Exit(code=2) from None

    # Discovery only. Reading a hundred and twenty scans is seconds of work and
    # it now happens with the viewer already open, so what the command has to
    # decide - is there anything here worth opening - is decided from what can
    # be established cheaply: whether a candidate file was found, and whether a
    # scan could be started. Whether those candidates actually parse is not
    # knowable without reading them, and the viewer says so if none of them do.
    with _search_progress() as report:
        candidates = discover(paths, report)
        # gowitness captures, found the same way and read alongside. A results
        # database named directly is a capture, not a scan that failed to parse.
        databases = find_databases(paths)
        taken = {d.resolve() for d in databases}
        candidates = [c for c in candidates if c.resolve() not in taken]

    # A directory with nothing in it yet is the case for *starting* a scan, so
    # it is only an error when no scan can be started.
    from seek.nmap.presets import probe

    nmap = probe(config.nmap_path)
    if not candidates and not nmap.available:
        where = ", ".join(str(p) for p in paths)
        typer.echo(f"seek: no readable nmap output in {where}", err=True)
        typer.echo(f"seek: and no scan can be started here ({nmap.reason})", err=True)
        raise typer.Exit(code=1)

    first = paths[0]
    scan_dir = first if first.is_dir() else Path.cwd()

    if serve:
        import asyncio

        from seek.web import serve as serve_mod

        session = serve_mod.build([Path(p) for p in paths], candidates, naming(paths),
                                  databases, config, scan_dir)
        raise typer.Exit(code=asyncio.run(serve_mod.serve(session, open_browser)))

    if not _stdout_is_usable():
        typer.echo("seek: requires an interactive terminal", err=True)
        raise typer.Exit(code=1)

    from seek.tui.nmap.app import run_viewer

    # The paths given are the sources: a directory keeps covering whatever a
    # scan writes into it, so a finished run needs no special case.
    raise typer.Exit(code=run_viewer(Pending(candidates, naming(paths), databases), config,
                                     sources=[Path(p) for p in paths],
                                     scan_dir=scan_dir))


_OTHER_COMMANDS = (
    "Other commands (run `seek <command> --help`):\n"
    "  seek nmap [files|dirs]  browse or run nmap scans, several merged into one\n"
    "  seek init <bash|zsh>    print shell-integration code\n"
    "  seek vulndb update      download public vulnerability and end-of-life data\n"
    "  seek vulndb status      where the vulnerability database is, and how old"
)


def _load_config() -> Config:
    """The config, or exit 2 naming what is wrong with it - as `nmap` does."""
    try:
        return load_config()
    except ConfigError as exc:
        typer.echo(f"seek: {exc}", err=True)
        raise typer.Exit(code=2) from None


vulndb_app = typer.Typer(
    help="The local vulnerability database: public NVD, OSV and endoflife.date data. "
         "Only `update` uses the network; the viewer only ever reads the file.",
    no_args_is_help=True,
)
app.add_typer(vulndb_app, name="vulndb")


@vulndb_app.command("update")
def vulndb_update(
    source: Annotated[
        list[str] | None,
        typer.Option("--source", help="Only this source: eol, cpe, osv or nvd (repeatable)."),
    ] = None,
    full: Annotated[
        bool, typer.Option("--full", help="Download everything again, not just what changed.")
    ] = False,
) -> None:
    """Download or refresh the database. The first run fetches several hundred MB."""
    from seek.vulndb import commands, update

    which = source or list(update.SOURCES)
    unknown = [s for s in which if s not in update.SOURCES]
    if unknown:
        raise typer.BadParameter(f"unknown source(s): {', '.join(unknown)}")
    raise typer.Exit(code=commands.run_update(_load_config(), sys.stderr, which, full))


@vulndb_app.command("status")
def vulndb_status() -> None:
    """Where the database is, how old it is, and what it holds."""
    from seek.vulndb import commands

    raise typer.Exit(code=commands.status(_load_config(), sys.stdout))


@app.command(epilog=_OTHER_COMMANDS)
def search(
    patterns: Annotated[
        list[str] | None,
        typer.Argument(help="Glob (or regex with -r) patterns scoping the walk."),
    ] = None,
    file: Annotated[bool, typer.Option("-f", "--file", help="Search filenames.")] = False,
    directory: Annotated[
        bool, typer.Option("-d", "--directory", help="Search directory names.")
    ] = False,
    content: Annotated[
        bool, typer.Option("-c", "--content", help="Search file contents.")
    ] = False,
    regex: Annotated[
        bool, typer.Option("-r", "--regex", help="Treat patterns as regexes.")
    ] = False,
    gitignore: Annotated[
        bool | None,
        typer.Option("--gitignore/--no-gitignore", help="Honor .gitignore/.ignore."),
    ] = None,
    config_path: Annotated[
        bool, typer.Option("--config-path", help="Print the config file path and exit.")
    ] = False,
    init_config: Annotated[
        bool,
        typer.Option(
            "--init-config",
            help="Write a starter config to the config path (won't overwrite an "
            "existing one) and exit.",
        ),
    ] = False,
) -> None:
    """Launch the interactive search session (default command)."""
    if config_path:
        typer.echo(str(config_file()))
        raise typer.Exit()
    if init_config:
        raise typer.Exit(code=_write_starter_config())

    try:
        cfg = load_config()
    except ConfigError as exc:
        typer.echo(f"seek: {exc}", err=True)
        raise typer.Exit(code=2) from None
    cfg = cfg.with_overrides(honor_gitignore=gitignore)

    try:
        scope = build_scope(patterns or [], regex=regex)
    except ScopeError as exc:
        typer.echo(f"seek: {exc}", err=True)
        raise typer.Exit(code=2) from None

    modes = Modes.resolve((file, directory, content))

    if not _stdout_is_usable():
        typer.echo("seek: requires an interactive terminal", err=True)
        raise typer.Exit(code=1)

    session = SessionConfig(
        root=Path.cwd(),
        modes=modes,
        scope=scope,
        config=cfg,
        regex=regex,
        patterns=list(patterns or []),
    )
    from seek.tui.app import run_session

    raise typer.Exit(code=run_session(session))


def _write_starter_config() -> int:
    """Install a starter config at the standard path, without clobbering one.

    The shipped `config.example.toml` is only a template inside the package -
    editing it changes nothing, because the app reads the per-user path below.
    This writes that template where the app will actually read it.
    """
    from seek.config import example_toml

    dest = config_file()
    if dest.exists():
        typer.echo(f"seek: a config already exists at {dest}", err=True)
        typer.echo("seek: edit it, or delete it and run --init-config again", err=True)
        return 1
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(example_toml(), encoding="utf-8")
    except OSError as exc:
        typer.echo(f"seek: could not write {dest}: {exc.strerror or exc}", err=True)
        return 1
    typer.echo(f"seek: wrote a starter config to {dest}")
    typer.echo("seek: edit it and run seek again to pick up the changes")
    return 0


def _stdout_is_usable() -> bool:
    """The interactive UI needs a real terminal on stdout (and stdin)."""
    return sys.stdout.isatty() and sys.stdin.isatty()


def main() -> None:
    # `search` is the default command; anything that is not another subcommand is
    # handed to it - including a bare `-h`/`--help`, so the main help screen is
    # the search command's own (every option visible) rather than a bare list of
    # subcommands that hides them. The other commands are named in search's
    # epilog, so nothing is lost.
    argv = sys.argv[1:]
    if not argv or argv[0] not in _KNOWN_SUBCOMMANDS:
        argv = ["search", *argv]
    app(argv)
