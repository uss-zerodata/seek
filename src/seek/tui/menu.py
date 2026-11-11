"""Modal screens: action menu, confirm dialog, text prompt, single and multi choice."""

from __future__ import annotations

from textual import on
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, OptionList, SelectionList
from textual.widgets.option_list import Option
from textual.widgets.selection_list import Selection


class ActionMenuScreen(ModalScreen[str | None]):
    """Pick an action by name. Returns the action id, or None if cancelled."""

    BINDINGS = [("escape,q", "dismiss_none", "Close")]
    DEFAULT_CSS = """
    ActionMenuScreen { align: center middle; }
    ActionMenuScreen > Vertical {
        width: 44; height: auto; max-height: 80%;
        background: $panel; border: round $primary; padding: 1;
    }
    ActionMenuScreen OptionList { height: auto; max-height: 20; }
    ActionMenuScreen #keys { color: $text-muted; }
    """

    def __init__(self, items: list[tuple[str, str, str]]) -> None:
        # (action_id, label, key)
        super().__init__()
        self._items = items

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("Actions")
            yield OptionList(
                *[
                    Option(f"{label:<26}{key}", id=aid)
                    for aid, label, key in self._items
                ]
            )
            yield Label("↑↓ move · ↵ choose · Esc close", id="keys")

    def on_mount(self) -> None:
        self.query_one(OptionList).focus()

    @on(OptionList.OptionSelected)
    def _chosen(self, event: OptionList.OptionSelected) -> None:
        self.dismiss(event.option.id)

    def action_dismiss_none(self) -> None:
        self.dismiss(None)


class ConfirmScreen(ModalScreen[str]):
    """Returns one of: 'all', 'one', 'cancel'."""

    BINDINGS = [("escape,q", "cancel", "Cancel")]
    DEFAULT_CSS = """
    ConfirmScreen { align: center middle; }
    ConfirmScreen > Vertical {
        width: 50; height: auto; background: $panel;
        border: round $warning; padding: 1;
    }
    ConfirmScreen Button { margin: 1 1 0 0; }
    """

    def __init__(self, count: int) -> None:
        super().__init__()
        self._count = count

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(f"{self._count} results selected.")
            yield Button(f"Act on all {self._count}", id="all", variant="primary")
            yield Button("Just the highlighted one", id="one")
            yield Button("Cancel", id="cancel")

    @on(Button.Pressed)
    def _pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id or "cancel")

    def action_cancel(self) -> None:
        self.dismiss("cancel")


class PromptScreen(ModalScreen[str | None]):
    """One-line text input. Returns the text, or None if cancelled."""

    BINDINGS = [("escape", "cancel", "Cancel")]
    DEFAULT_CSS = """
    PromptScreen { align: center middle; }
    PromptScreen > Vertical {
        width: 60; height: auto; background: $panel;
        border: round $primary; padding: 1;
    }
    PromptScreen #keys { color: $text-muted; }
    """

    def __init__(self, prompt: str, initial: str = "") -> None:
        super().__init__()
        self._prompt = prompt
        self._initial = initial

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(self._prompt)
            yield Input(value=self._initial)
            yield Label("↵ confirm · Esc cancel", id="keys")

    def on_mount(self) -> None:
        self.query_one(Input).focus()

    @on(Input.Submitted)
    def _submit(self, event: Input.Submitted) -> None:
        self.dismiss(event.value)

    def action_cancel(self) -> None:
        self.dismiss(None)


class ChoiceScreen(ModalScreen[str | None]):
    """Pick one of a small set of labelled choices.

    One line per choice, in a list rather than a stack of three-line buttons:
    six export recipes as buttons needed more than twenty rows and ran off the
    bottom of a 24-row terminal, which put the last choice out of reach. A list
    also moves with `j`/`k` like every other list in the viewer, rather than
    asking for `Tab`.
    """

    BINDINGS = [("escape,q", "cancel", "Cancel")]
    DEFAULT_CSS = """
    ChoiceScreen { align: center middle; }
    ChoiceScreen > Vertical {
        width: 52; height: auto; max-height: 80%; background: $panel;
        border: round $primary; padding: 1;
    }
    ChoiceScreen OptionList { height: auto; max-height: 16; }
    ChoiceScreen #keys { color: $text-muted; }
    """

    def __init__(self, prompt: str, choices: list[tuple[str, str]],
                 disabled: set[str] | None = None) -> None:
        super().__init__()
        self._prompt = prompt
        self._choices = choices
        # Shown but unpickable, rather than dropped: a choice that vanishes
        # when its tool is missing teaches nothing, while one that stays and
        # says why teaches what to install.
        self._disabled = disabled or set()

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(self._prompt)
            yield OptionList(*[Option(label, id=cid, disabled=cid in self._disabled)
                               for cid, label in self._choices])
            yield Label("↑↓ move · ↵ choose · Esc cancel", id="keys")

    def on_mount(self) -> None:
        self.query_one(OptionList).focus()

    @on(OptionList.OptionSelected)
    def _chosen(self, event: OptionList.OptionSelected) -> None:
        self.dismiss(event.option.id)

    def choose(self, choice_id: str) -> None:
        """Pick by id without pointing at it - for the command palette and tests."""
        if choice_id in self._disabled:
            return
        self.dismiss(choice_id)

    def action_cancel(self) -> None:
        self.dismiss(None)


class MultiChoiceScreen(ModalScreen[list[str] | None]):
    """Tick any number of labelled options. Returns the ids, or None if cancelled.

    The ids come back in the order they were *offered*, not the order they were
    ticked, so a caller whose list is a catalogue gets its own order back and two
    exports of the same fields line up.
    """

    BINDINGS = [("escape,q", "cancel", "Cancel")]
    DEFAULT_CSS = """
    MultiChoiceScreen { align: center middle; }
    MultiChoiceScreen > Vertical {
        width: 56; height: auto; max-height: 80%; background: $panel;
        border: round $primary; padding: 1;
    }
    MultiChoiceScreen SelectionList { height: auto; max-height: 20; }
    MultiChoiceScreen #hint { color: $text-muted; }
    MultiChoiceScreen Button { margin: 1 0 0 0; width: 100%; }
    """

    def __init__(self, prompt: str, choices: list[tuple[str, str]],
                 preselected: tuple[str, ...] = (), confirm_label: str = "Export these") -> None:
        super().__init__()
        self._prompt = prompt
        self._choices = choices
        self._preselected = preselected
        self._confirm_label = confirm_label

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(self._prompt)
            yield SelectionList(*[Selection(label, cid, cid in self._preselected)
                                  for cid, label in self._choices])
            yield Label("space toggles · Tab then ↵ to confirm · Esc cancel", id="hint")
            yield Button(self._confirm_label, id="confirm")

    def on_mount(self) -> None:
        self.query_one(SelectionList).focus()

    @on(Button.Pressed, "#confirm")
    def _confirm(self, _event: Button.Pressed) -> None:
        self.confirm()

    def confirm(self) -> None:
        chosen = set(self.query_one(SelectionList).selected)
        self.dismiss([cid for cid, _ in self._choices if cid in chosen])

    def action_cancel(self) -> None:
        self.dismiss(None)
