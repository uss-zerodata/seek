"""The tag editor: one screen for everything about a tag - its name, description,
issues and rules. It opens after the rule builder saves (with the new rule in
its list) and from `t` for any tag; `↵` on a rule opens it in the builder and
comes back here. Nothing is written until the editor is saved, then all of it at
once (`Session.plan_tag_edit`).

Translation only (ARC-4): the screen changes a `TagEdit`; the session decides
what that means for the files.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import replace

from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, OptionList, Select, Static
from textual.widgets.option_list import Option

from seek.nmap import tagrules as tr
from seek.nmap.tagedit import RuleItem, TagEdit
from seek.tui.menu import ChoiceScreen
from seek.tui.nmap.scope import _FRAME

ADD_ISSUE = "\x00add"
_SEVERITY_STYLE = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan",
                   "info": "dim"}
KEYS = ("tab moves · ↵ edit an issue or open a rule in the builder · del deletes · "
        "ctrl+s saves all · Esc leaves")


class TagEditScreen(ModalScreen[TagEdit | None]):
    """Returns the edited tag to save, or None when left."""

    BINDINGS = [
        Binding("escape", "leave", "Leave"),
        Binding("ctrl+s", "save", "Save", show=False),
        Binding("delete", "delete", "Delete", show=False),
    ]
    DEFAULT_CSS = _FRAME.format(name="TagEditScreen") + """
    TagEditScreen > #frame { width: 100; height: auto; max-height: 100%; }
    TagEditScreen .head { text-style: bold; margin: 1 0 0 0; }
    TagEditScreen OptionList { height: auto; max-height: 12; background: transparent; }
    TagEditScreen #error { color: $error; height: auto; }
    TagEditScreen #manual, TagEditScreen #keys { color: $text-muted; }
    TagEditScreen #keys { text-wrap: nowrap; text-overflow: ellipsis; }
    """

    def __init__(self, edit: TagEdit,
                 open_rule: Callable[[TagEdit, RuleItem], Awaitable[RuleItem | None]],
                 error: str = "") -> None:
        super().__init__()
        self.edit = edit
        self._start = edit
        self._open_rule = open_rule
        self._error = error

    def compose(self) -> ComposeResult:
        e = self.edit
        with Vertical(id="frame"):
            yield Label(f"Tag · {e.original or 'new'}", id="title")
            yield Label("Name", classes="head")
            yield Input(e.name, id="name", placeholder="lowercase letters, digits, . _ -")
            yield Label("Description", classes="head")
            yield Input(e.description, id="description", placeholder="what this tag means")
            yield Label("Issues", classes="head")
            yield OptionList(id="issues")
            yield Label("Rules", classes="head")
            yield OptionList(id="rules")
            yield Static(id="manual")
            yield Static(self._error, id="error")
            with Horizontal():
                yield Button("Save all", id="save", variant="primary")
                yield Button("Cancel", id="cancel")
            yield Static(KEYS, id="keys")

    def on_mount(self) -> None:
        self._show()
        self.query_one("#description" if self.edit.original else "#name", Input).focus()

    # --- what is on screen ------------------------------------------------------------

    def _show(self) -> None:
        e = self.edit
        issues = self.query_one("#issues", OptionList)
        keep = issues.highlighted
        issues.clear_options()
        for k, issue in enumerate(e.issues):
            label = Text(f"{issue.severity.value:<9}",
                         style=_SEVERITY_STYLE.get(issue.severity.value, ""))
            label.append(issue.title)
            if issue.description:
                label.append(f"\n         {issue.description}", style="dim")
            if issue.references:
                label.append(f"\n         {', '.join(issue.references)}", style="dim")
            issues.add_option(Option(label, id=f"i{k}"))
        issues.add_option(Option(Text("+ add an issue…", style="dim"), id=ADD_ISSUE))
        issues.highlighted = min(keep or 0, issues.option_count - 1)
        rules = self.query_one("#rules", OptionList)
        keep = rules.highlighted
        rules.clear_options()
        for k, item in enumerate(e.rules):
            mark = "+" if item.is_new else "−" if item.deleted else "~" if item.changed else " "
            style = "strike dim" if item.deleted else ""
            label = Text(f"{mark} ")
            label.append(item.name or "(unnamed)", style=style)
            label.append(f"   {item.where}", style="dim")
            rules.add_option(Option(label, id=f"r{k}"))
        if not e.rules:
            rules.add_option(Option(Text("no rules - build one with T", style="dim"),
                                    disabled=True))
        rules.highlighted = min(keep or 0, max(rules.option_count - 1, 0))
        manual = (f"Manual tags: {e.manual_hosts} host(s), {e.manual_services} service(s)"
                  if e.manual_hosts or e.manual_services else "Manual tags: none")
        self.query_one("#manual", Static).update(manual)

    def _typed(self) -> TagEdit:
        return replace(self.edit, name=self.query_one("#name", Input).value.strip(),
                       description=self.query_one("#description", Input).value)

    # --- issues and rules ---------------------------------------------------------------

    @on(OptionList.OptionSelected, "#issues")
    def _issue_chosen(self, event: OptionList.OptionSelected) -> None:
        self._edit_issue(None if event.option.id == ADD_ISSUE else int(event.option.id[1:]))

    @work(exclusive=True, group="tag-editor")
    async def _edit_issue(self, at: int | None) -> None:
        current = self.edit.issues[at] if at is not None else None
        got = await self.app.push_screen_wait(IssueScreen(current))
        if got is None:
            return
        self.edit = self._typed()
        issues = list(self.edit.issues)
        if got == "delete":
            if at is not None:
                del issues[at]
        elif at is None:
            issues.append(got)
        else:
            issues[at] = got
        self.edit = replace(self.edit, issues=tuple(issues))
        self._show()

    @on(OptionList.OptionSelected, "#rules")
    def _rule_chosen(self, event: OptionList.OptionSelected) -> None:
        if event.option.id:
            self._edit_rule(int(event.option.id[1:]))

    @work(exclusive=True, group="tag-editor")
    async def _edit_rule(self, at: int) -> None:
        self.edit = self._typed()
        item = self.edit.rules[at]
        if item.deleted:
            self.notify("the rule is marked for deletion - del keeps it again")
            return
        got = await self._open_rule(self.edit, item)
        if got is not None:
            self.edit = self.edit.with_rule(got, at)
            self._show()

    def action_delete(self) -> None:
        rules = self.query_one("#rules", OptionList)
        issues = self.query_one("#issues", OptionList)
        if self.focused is rules and rules.highlighted_option and rules.highlighted_option.id:
            self.edit = self._typed().toggle_delete(int(rules.highlighted_option.id[1:]))
            self._show()
        elif (self.focused is issues and issues.highlighted_option
              and issues.highlighted_option.id != ADD_ISSUE):
            at = int(issues.highlighted_option.id[1:])
            self.edit = self._typed()
            self.edit = replace(self.edit, issues=tuple(
                i for k, i in enumerate(self.edit.issues) if k != at))
            self._show()

    # --- saving and leaving -------------------------------------------------------------

    @on(Button.Pressed, "#save")
    def _save_pressed(self, _event) -> None:
        self.action_save()

    @on(Button.Pressed, "#cancel")
    def _cancel_pressed(self, _event) -> None:
        self.action_leave()

    def action_save(self) -> None:
        edit = self._typed()
        try:
            edit = replace(edit, name=tr.tag_name(edit.name))
        except tr.RuleError as exc:
            self.query_one("#error", Static).update(str(exc))
            return
        self.dismiss(edit)

    def action_leave(self) -> None:
        self._leave()

    @work(exclusive=True, group="tag-editor")
    async def _leave(self) -> None:
        if self._typed() != self._start:
            answer = await self.app.push_screen_wait(ChoiceScreen(
                "Leave the tag editor? Nothing is saved.",
                [("stay", "stay and keep editing"), ("leave", "leave, discard the changes")]))
            if answer != "leave":
                return
        self.dismiss(None)


class IssueScreen(ModalScreen[tr.Issue | str | None]):
    """One issue: title, severity, description, references. Returns the issue,
    "delete", or None."""

    BINDINGS = [Binding("escape", "cancel", "Cancel"), Binding("ctrl+s", "take", "Take",
                                                                 show=False)]
    DEFAULT_CSS = _FRAME.format(name="IssueScreen") + """
    IssueScreen > #frame { width: 80; }
    IssueScreen Input, IssueScreen Select { margin: 0 0 1 0; }
    IssueScreen #error { color: $error; height: auto; }
    IssueScreen Button { margin: 1 1 0 0; }
    """

    def __init__(self, issue: tr.Issue | None) -> None:
        super().__init__()
        self.issue = issue

    def compose(self) -> ComposeResult:
        i = self.issue
        with Vertical(id="frame"):
            yield Label("Issue" if i else "New issue")
            yield Input(i.title if i else "", id="title", placeholder="title")
            yield Select([(s.value, s.value) for s in tr.Severity],
                         value=(i.severity if i else tr.Severity.MEDIUM).value,
                         allow_blank=False, id="severity")
            yield Input(i.description if i else "", id="description",
                        placeholder="description (optional)")
            yield Input(", ".join(i.references) if i else "", id="references",
                        placeholder="references, comma separated: URLs, CVE ids (optional)")
            yield Static(id="error")
            with Horizontal():
                yield Button("Take", id="take", variant="primary")
                if i is not None:
                    yield Button("Delete", id="delete", variant="error")
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        self.query_one("#title", Input).focus()

    @on(Input.Submitted)
    def _submitted(self, _event) -> None:
        self.action_take()

    @on(Button.Pressed, "#take")
    def _take_pressed(self, _event) -> None:
        self.action_take()

    @on(Button.Pressed, "#delete")
    def _delete_pressed(self, _event) -> None:
        self.dismiss("delete")

    @on(Button.Pressed, "#cancel")
    def _cancel_pressed(self, _event) -> None:
        self.dismiss(None)

    def action_take(self) -> None:
        title = self.query_one("#title", Input).value.strip()
        if not title:
            self.query_one("#error", Static).update("an issue needs a title")
            return
        refs = tuple(r.strip() for r in self.query_one("#references", Input).value.split(",")
                     if r.strip())
        self.dismiss(tr.Issue(title, tr.Severity(self.query_one("#severity", Select).value),
                              self.query_one("#description", Input).value.strip(), refs))

    def action_cancel(self) -> None:
        self.dismiss(None)
