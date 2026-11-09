"""Defining a scope, choosing a command, and reviewing it before it runs.

Three screens, in the order they are met:

- `ScopeScreen` — what to scan, when the viewer was opened on nothing to read.
- `CommandScreen` — the preset expanded into a command, editable.
- `ReviewScreen` — the exact argv and what it will do, which is the second of
  the two confirmations. Nothing starts a process until this returns. It is
  also where a plan is copied, to run here by hand or on another machine.

The review is deliberately not a yes/no on a one-line question: a scan is an
action against someone else's network, and the argv, the scope, the file it
writes and the privilege level are all things worth reading first.
"""

from __future__ import annotations

from dataclasses import dataclass

from rich.console import Group
from rich.text import Text
from textual import events, on
from textual.app import ComposeResult
from textual.containers import Vertical, VerticalScroll
from textual.css.query import NoMatches
from textual.screen import ModalScreen
from textual.widgets import Checkbox, Input, Label, OptionList, Static, TextArea
from textual.widgets.option_list import Option

from seek import notify
from seek.actions import ActionError, copy_to_clipboard
from seek.nmap.presets import Scope, needs_root, parse_args


class _Fits:
    """A scan-flow modal whose `.flex` part gives way when the screen is short.

    Each frame used to be 84 columns and sized in fixed rows, so a long scope or
    a command with hundreds of addresses pushed its choices and its keys off a
    small terminal, with nothing to scroll. CSS cannot say "as tall as the
    content, but no taller than what the rest leaves": an `fr` part makes an
    auto-height frame fill the screen. So the flexible part's `max-height` is
    set from the room actually left - on mount, on resize, and when the
    content beside it changes height.
    """

    FLEX_CAP: int | None = None          # the flexible part's comfortable most

    def on_resize(self, _event: events.Resize) -> None:
        self.call_after_refresh(self._fit)

    def _fit(self) -> None:
        try:
            frame = self.query_one("#frame")         # type: ignore[attr-defined]
            flex = self.query_one(".flex")           # type: ignore[attr-defined]
        except NoMatches:
            return
        # Children lay out at their natural height even when the frame clips
        # them, so their sum is what the frame wants; the flexible part may sit
        # inside a row of the frame, which is why it is subtracted rather than
        # skipped.
        natural = sum(c.outer_size.height for c in frame.children)
        chrome = frame.outer_size.height - frame.content_size.height
        others = natural - flex.outer_size.height
        margin = flex.styles.margin.top + flex.styles.margin.bottom
        room = self.size.height - chrome - others - margin  # type: ignore[attr-defined]
        room = max(3, room if self.FLEX_CAP is None else min(room, self.FLEX_CAP))
        flex.styles.max_height = room


class _Tick(Checkbox):
    """A checkbox whose state is a character, `[x]` or `[ ]`. Textual's draws
    `X` either way and says on or off by colour alone."""

    BUTTON_LEFT = "["
    BUTTON_RIGHT = "]"

    @property
    def BUTTON_INNER(self) -> str:  # noqa: N802 - the name Textual reads
        return "x" if self.value else " "


# The frame every scan-flow modal shares: never wider or taller than the screen.
_FRAME = """
    {name} {{ align: center middle; }}
    {name} > #frame {{
        width: 84; max-width: 100%; height: auto; max-height: 100%;
        background: $panel; border: round $primary; padding: 0 2;
    }}
"""


@dataclass(slots=True)
class ScanRequest:
    """What the three screens between them produce."""

    targets: list[str]
    preset: str = ""
    command: str = ""


class ScopeScreen(_Fits, ModalScreen[list[str] | None]):
    """One target per line: addresses, ranges, hostnames or URLs.

    Lines are checked as they are typed and the bad ones are named individually
    with their line number - a scope rejected as a whole tells you nothing about
    which line was wrong.
    """

    BINDINGS = [
        ("escape", "cancel", "Cancel"),
        ("ctrl+s", "accept", "Continue"),
    ]
    DEFAULT_CSS = _FRAME.format(name="ScopeScreen") + """
    ScopeScreen TextArea { height: 12; min-height: 3; border: none; }
    ScopeScreen #summary { height: auto; max-height: 6; }
    ScopeScreen .muted { color: $text-muted; }
    """

    def __init__(self, initial: str = "") -> None:
        super().__init__()
        self._initial = initial

    def compose(self) -> ComposeResult:
        with Vertical(id="frame"):
            yield Label("Scope — one target per line")
            yield Label("addresses, 10.0.0.0/24, 10.0.0.1-20, hostnames, URLs · "
                        "# comments ignored", classes="muted")
            yield TextArea(self._initial, id="scope", classes="flex")
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
        self.call_after_refresh(self._fit)       # the summary's height changed

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


class PresetScreen(_Fits, ModalScreen[str | None]):
    """Choose a scan preset. Returns the preset name, or None if cancelled.

    Each preset is two lines - its name, and a dim preview of the flags it
    stands for - so the list can be told apart at a glance without every long
    name wrapping into its neighbour. The privilege badge sits at the right of
    the name line, where it cannot be torn onto a line of its own.
    """

    BINDINGS = [("escape,q", "cancel", "Cancel")]
    FLEX_CAP = 22
    DEFAULT_CSS = _FRAME.format(name="PresetScreen") + """
    PresetScreen OptionList {
        height: auto; min-height: 3; background: transparent; padding: 0;
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
        with Vertical(id="frame"):
            yield Label(self._title)
            yield Label(self._scope_line, id="scope")
            yield OptionList(*[self._option(name, args)
                               for name, args in self._presets.items()], classes="flex")
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
        self.call_after_refresh(self._fit)

    @on(OptionList.OptionSelected)
    def _chosen(self, event: OptionList.OptionSelected) -> None:
        self.dismiss(event.option.id)

    def action_cancel(self) -> None:
        self.dismiss(None)


class CommandScreen(_Fits, ModalScreen[str | None]):
    """The preset, expanded into the command that will run. Editable."""

    BINDINGS = [
        ("escape", "cancel", "Cancel"),
        ("ctrl+s", "accept", "Review"),
    ]
    FLEX_CAP = 12
    DEFAULT_CSS = _FRAME.format(name="CommandScreen") + """
    CommandScreen TextArea { height: auto; min-height: 3; border: none; }
    CommandScreen .muted { color: $text-muted; }
    CommandScreen #error { color: $error; height: auto; }
    """

    def __init__(self, title: str, command: str, note: str) -> None:
        super().__init__()
        self._title = title
        self._command = command
        self._note = note

    def compose(self) -> ComposeResult:
        with Vertical(id="frame"):
            yield Label(self._title)
            yield Label("Command — edit freely; the output flags are added for you",
                        classes="muted")
            yield TextArea(self._command, id="command", classes="flex")
            yield Static(self._note, classes="muted")
            yield Static(id="error")
            yield Label("^S review · Esc back", classes="muted")

    def on_mount(self) -> None:
        self.query_one(TextArea).focus()
        self.call_after_refresh(self._fit)

    def show_error(self, message: str) -> None:
        self.query_one("#error", Static).update(Text(message, style="bold"))
        self.call_after_refresh(self._fit)

    def action_accept(self) -> None:
        self.dismiss(self.query_one(TextArea).text.strip())

    def action_cancel(self) -> None:
        self.dismiss(None)


class ReviewScreen(_Fits, ModalScreen[bool]):
    """The last step before a run: what will run, and what else can be done with it.

    Shared by a scan and a capture. The choices are one line each: start - or,
    when it cannot start here, the reason, disabled - and the two copy forms,
    which keep the review open. `True` only for start; the notification
    settings chosen for the run are then on `notify_url` / `notify_progress`.
    """

    BINDINGS = [("escape,q", "cancel", "Back"),
                ("y", "copy('remote')", "Copy for another machine"),
                ("Y", "copy('local')", "Copy as shown")]
    DEFAULT_CSS = _FRAME.format(name="ReviewScreen") + """
    /* The command and its paths scroll on their own (`_Fits`), so the choices
       below stay on screen whatever the paths and the scope are. */
    ReviewScreen #review-body { height: auto; min-height: 3; }
    ReviewScreen #warn { color: $warning; }
    ReviewScreen .muted { color: $text-muted; text-wrap: nowrap; text-overflow: ellipsis; }
    ReviewScreen OptionList { height: auto; }
    ReviewScreen #notify-url { border: none; height: 1; padding: 0 1; }
    ReviewScreen Checkbox { background: transparent; border: none; padding: 0; height: 1; }
    """

    def __init__(self, heading: str, body: Text, start_label: str, *,
                 blocked: str | None, copy_local: str | None, copy_remote: str,
                 results: str, notify_url: str = "", notify_progress: bool = False) -> None:
        super().__init__()
        self.notify_url = notify_url
        self.notify_progress = notify_progress
        self._heading = heading
        self._body = body
        self._start_label = start_label
        self._blocked = blocked
        self._copies = {"remote": copy_remote, "local": copy_local}
        self._results = results

    def compose(self) -> ComposeResult:
        options = [Option(f"⊘ {self._blocked}" if self._blocked else self._start_label,
                          id="start", disabled=bool(self._blocked)),
                   Option("y  copy for another machine", id="remote")]
        if self._copies["local"] is not None:
            options.append(Option("Y  copy as shown here", id="local"))
        with Vertical(id="frame"):
            yield Label(self._heading)
            with VerticalScroll(id="review-body", classes="flex"):
                yield Static(self._body)
            yield Static("⚠ scan only what you are authorised to scan", id="warn")
            yield Input(self.notify_url, id="notify-url",
                        placeholder="notify an ntfy URL when it ends - empty: no notification")
            yield _Tick("…and at 25 / 50 / 75 % done", self.notify_progress,
                        id="notify-progress")
            yield OptionList(*options)
            yield Static(self._results, classes="muted")
            yield Label("↵ choose · y/Y copy · Esc back", classes="muted")

    def on_mount(self) -> None:
        self.query_one(OptionList).focus()
        self.call_after_refresh(self._fit)

    @on(OptionList.OptionSelected)
    def _chosen(self, event: OptionList.OptionSelected) -> None:
        if event.option.id == "start":
            try:
                self.notify_url = notify.normalise(self.query_one("#notify-url", Input).value)
            except notify.NotifyError as exc:
                self.notify(f"notification URL: {exc}", severity="error")
                return
            self.notify_progress = self.query_one("#notify-progress", Checkbox).value
            self.dismiss(True)
        else:
            self.action_copy(event.option.id or "")

    def action_copy(self, form: str) -> None:
        text = self._copies.get(form)
        if text is None:
            self.notify("not available here - copy for another machine with y",
                        severity="warning")
            return
        what = "command for another machine" if form == "remote" else "command"
        try:
            copy_to_clipboard(text)
        except ActionError:
            self.app.push_screen(CopyTextScreen(
                f"No clipboard here - select the {what} and copy it yourself", text))
            return
        self.notify(f"copied the {what}")

    def action_cancel(self) -> None:
        self.dismiss(False)


class CopyTextScreen(ModalScreen[None]):
    """Text that could not reach a clipboard, shown so it can be selected."""

    BINDINGS = [("escape,q", "close", "Close")]
    DEFAULT_CSS = """
    CopyTextScreen { align: center middle; }
    CopyTextScreen > Vertical {
        width: 90%; height: auto; max-height: 90%; background: $panel;
        border: round $primary; padding: 1 2;
    }
    CopyTextScreen TextArea { height: auto; max-height: 24; }
    CopyTextScreen .muted { color: $text-muted; }
    """

    def __init__(self, heading: str, text: str) -> None:
        super().__init__()
        self._heading = heading
        self._text = text

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(self._heading)
            yield TextArea(self._text, read_only=True, soft_wrap=False)
            yield Label("Esc close", classes="muted")

    def action_close(self) -> None:
        self.dismiss(None)
