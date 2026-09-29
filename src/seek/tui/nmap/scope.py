"""Defining a scope, choosing a command, and reviewing it before it runs.

Three screens, in the order they are met:

- `ScopeScreen` — what to scan, when the viewer was opened on nothing to read.
- `CommandScreen` — the preset expanded into a command, editable.
- `ReviewScreen` — the exact argv and what it will do, which is the second of
  the two confirmations. Nothing starts a process until this returns.

The review is deliberately not a yes/no on a one-line question: a scan is an
action against someone else's network, and the argv, the scope, the file it
writes and the privilege level are all things worth reading first.
"""

from __future__ import annotations

from dataclasses import dataclass

from rich.console import Group
from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Label, OptionList, Static, TextArea
from textual.widgets.option_list import Option

from seek.nmap.presets import Scope, needs_root, parse_args


@dataclass(slots=True)
class ScanRequest:
    """What the three screens between them produce."""

    targets: list[str]
    preset: str = ""
    command: str = ""


class ScopeScreen(ModalScreen[list[str] | None]):
    """One target per line: addresses, ranges, hostnames or URLs.

    Lines are checked as they are typed and the bad ones are named individually
    with their line number - a scope rejected as a whole tells you nothing about
    which line was wrong.
    """

    BINDINGS = [
        ("escape", "cancel", "Cancel"),
        ("ctrl+s", "accept", "Continue"),
    ]
    DEFAULT_CSS = """
    ScopeScreen { align: center middle; }
    ScopeScreen > Vertical {
        width: 84; height: auto; max-height: 90%; background: $panel;
        border: round $primary; padding: 1 2;
    }
    ScopeScreen TextArea { height: 12; border: none; }
    ScopeScreen #summary { height: auto; max-height: 6; }
    ScopeScreen .muted { color: $text-muted; }
    """

    def __init__(self, initial: str = "") -> None:
        super().__init__()
        self._initial = initial

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("Scope — one target per line")
            yield Label("addresses, 10.0.0.0/24, 10.0.0.1-20, hostnames, URLs · "
                        "# comments ignored", classes="muted")
            yield TextArea(self._initial, id="scope")
            yield Static(id="summary")
            yield Label("^S continue · Esc cancel", classes="muted")

    def on_mount(self) -> None:
        self.query_one(TextArea).focus()
        self._refresh()

    @on(TextArea.Changed)
    def _changed(self, _event: TextArea.Changed) -> None:
        self._refresh()

    def scope(self) -> Scope:
        return Scope.parse(self.query_one(TextArea).text)

    def _refresh(self) -> None:
        scope = self.scope()
        text = Text()
        text.append(scope.summary(), style="bold" if scope.valid else "dim")
        for number, line in enumerate(self.query_one(TextArea).text.splitlines(), 1):
            target = next((t for t in scope.invalid if t.raw == line.strip()), None)
            if target is not None:
                text.append(f"\n  line {number}: ", style="dim")
                text.append(f"{target.raw} — {target.error}", style="bright_red")
        self.query_one("#summary", Static).update(text)

    def action_accept(self) -> None:
        scope = self.scope()
        if not scope.valid:
            self.notify("no valid target to scan", severity="warning")
            return
        if scope.invalid:
            self.notify(f"{len(scope.invalid)} line(s) will be skipped",
                        severity="warning")
        self.dismiss(scope.values())

    def action_cancel(self) -> None:
        self.dismiss(None)


class PresetScreen(ModalScreen[str | None]):
    """Choose a scan preset. Returns the preset name, or None if cancelled.

    Each preset is two lines - its name, and a dim preview of the flags it
    stands for - so the list can be told apart at a glance without every long
    name wrapping into its neighbour. The privilege badge sits at the right of
    the name line, where it cannot be torn onto a line of its own.
    """

    BINDINGS = [("escape,q", "cancel", "Cancel")]
    DEFAULT_CSS = """
    PresetScreen { align: center middle; }
    PresetScreen > Vertical {
        width: 84; height: auto; max-height: 90%; background: $panel;
        border: round $primary; padding: 1 2;
    }
    PresetScreen OptionList {
        height: auto; max-height: 22; background: transparent; padding: 0;
    }
    PresetScreen OptionList > .option-list--option { padding: 0 0 1 0; }
    PresetScreen #scope, PresetScreen #keys { color: $text-muted; }
    """
    # Text budget for one line inside the box: width, less the border, the
    # padding and the option list's own gutter. Kept as a constant so the name
    # and the flag preview are trimmed to the same edge.
    _WIDTH = 74

    def __init__(self, title: str, scope_line: str,
                 presets: dict[str, str]) -> None:
        super().__init__()
        self._title = title
        self._scope_line = scope_line
        self._presets = presets

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(self._title)
            yield Label(self._scope_line, id="scope")
            yield OptionList(*[self._option(name, args)
                               for name, args in self._presets.items()])
            yield Label("↑↓ move · ↵ choose · Esc cancel", id="keys")

    def _option(self, name: str, args: str) -> Option:
        try:
            root = "needs root" if needs_root(parse_args(args)) else ""
        except Exception:                       # noqa: BLE001 - a bad preset still lists
            root = ""
        # Both lines are no-wrap and clip with an ellipsis, so neither the name
        # nor the flag preview can spill onto a line of its own - the bug that
        # made the old chooser unreadable. The badge is right-aligned by padding
        # the name to the same edge the clip uses.
        head = Text(no_wrap=True, overflow="ellipsis")
        head.append(name, style="bold")
        if root:
            head.append(" " * max(2, self._WIDTH - len(name) - len(root)))
            head.append(root, style="yellow")
        body = Text("  ", no_wrap=True, overflow="ellipsis")
        body.append(args, style="dim")
        return Option(Group(head, body), id=name)

    def on_mount(self) -> None:
        self.query_one(OptionList).focus()

    @on(OptionList.OptionSelected)
    def _chosen(self, event: OptionList.OptionSelected) -> None:
        self.dismiss(event.option.id)

    def action_cancel(self) -> None:
        self.dismiss(None)


class CommandScreen(ModalScreen[str | None]):
    """The preset, expanded into the command that will run. Editable."""

    BINDINGS = [
        ("escape", "cancel", "Cancel"),
        ("ctrl+s", "accept", "Review"),
    ]
    DEFAULT_CSS = """
    CommandScreen { align: center middle; }
    CommandScreen > Vertical {
        width: 84; height: auto; max-height: 80%; background: $panel;
        border: round $primary; padding: 1 2;
    }
    CommandScreen TextArea { height: 5; border: none; }
    CommandScreen .muted { color: $text-muted; }
    CommandScreen #error { color: $error; height: auto; }
    """

    def __init__(self, title: str, command: str, note: str) -> None:
        super().__init__()
        self._title = title
        self._command = command
        self._note = note

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(self._title)
            yield Label("Command — edit freely; the output flags are added for you",
                        classes="muted")
            yield TextArea(self._command, id="command")
            yield Static(self._note, classes="muted")
            yield Static(id="error")
            yield Label("^S review · Esc back", classes="muted")

    def on_mount(self) -> None:
        self.query_one(TextArea).focus()

    def show_error(self, message: str) -> None:
        self.query_one("#error", Static).update(Text(message, style="bold"))

    def action_accept(self) -> None:
        self.dismiss(self.query_one(TextArea).text.strip())

    def action_cancel(self) -> None:
        self.dismiss(None)


class ReviewScreen(ModalScreen[bool]):
    """The second confirmation: the exact argv and what it will do."""

    BINDINGS = [("escape,q", "cancel", "Back")]
    DEFAULT_CSS = """
    ReviewScreen { align: center middle; }
    ReviewScreen > Vertical {
        width: 84; height: auto; max-height: 90%; background: $panel;
        border: round $primary; padding: 1 2;
    }
    ReviewScreen #warn { color: $warning; }
    ReviewScreen .muted { color: $text-muted; }
    ReviewScreen Button { margin: 1 0 0 0; width: 100%; }
    """

    def __init__(self, argv: list[str], targets: list[str], out_base: str,
                 elevated: bool, privilege: str) -> None:
        super().__init__()
        self._argv = argv
        self._targets = targets
        self._out_base = out_base
        self._elevated = elevated
        self._privilege = privilege

    def compose(self) -> ComposeResult:
        body = Text()
        body.append(" ".join(self._argv[:2]) + " ", style="bold")
        body.append(" ".join(self._argv[2:]) + "\n\n")
        body.append(f"  {'scope':<11}", style="dim")
        body.append(f"{len(self._targets)} target(s): "
                    + ", ".join(self._targets[:4])
                    + (" …" if len(self._targets) > 4 else "") + "\n")
        body.append(f"  {'writes':<11}", style="dim")
        body.append(f"{self._out_base}.{{xml,nmap,gnmap}}\n")
        body.append(f"  {'privilege':<11}", style="dim")
        body.append("sudo -n — " if self._elevated else "direct — ")
        body.append(self._privilege or "no elevated flags")
        with Vertical():
            yield Label("Start this scan?")
            yield Static(body)
            yield Static("⚠ scan only what you are authorised to scan", id="warn")
            yield Button("Start the scan", id="start")
            yield Label("↵ start · Esc back", classes="muted")

    def on_mount(self) -> None:
        self.query_one(Button).focus()

    @on(Button.Pressed, "#start")
    def _start(self, _event: Button.Pressed) -> None:
        self.dismiss(True)

    def action_cancel(self) -> None:
        self.dismiss(False)
