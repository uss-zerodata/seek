"""The rule builder in the terminal: one screen to shape a draft rule, the fact
editor and the save dialog.

Translation only (ARC-4): every count, proposal and condition comes from
`seek.nmap.tagbuild`; this module shows an `Assessment` and turns keys into a
new `Draft`. `assess` and `refine` run off the event loop, debounced, in an
exclusive worker; a result for a draft that is no longer current is dropped, so
the screen always shows the last change.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.suggester import SuggestFromList
from textual.widgets import Button, Checkbox, Input, Label, OptionList, Select, Static
from textual.widgets.option_list import Option

from seek.nmap import tagbuild as tb
from seek.nmap import tagrules as tr
from seek.tui.menu import ChoiceScreen
from seek.tui.nmap.scope import _FRAME

# Time to wait for the next key before counting: typing is not counted per key.
DEBOUNCE = 0.12
_MARK = {tb.State.IGNORE: "·", tb.State.REQUIRE: "+", tb.State.EXCLUDE: "−"}
_CYCLE = {tb.State.IGNORE: tb.State.REQUIRE, tb.State.REQUIRE: tb.State.EXCLUDE,
          tb.State.EXCLUDE: tb.State.IGNORE}
_MODES = [("equals", tb.Mode.EQUALS), ("contains", tb.Mode.CONTAINS),
          ("starts with", tb.Mode.START), ("ends with", tb.Mode.END),
          ("regex", tb.Mode.REGEX)]
_GRANTS = [("the host", tr.Grant.HOST), ("the matched services", tr.Grant.SERVICE),
           ("both", tr.Grant.BOTH)]
KEYS = ("space cycle · + require · - exclude · e edit · p same port · tab hosts · "
        "a add · d drop · x exclude host · s save · Esc leave")


@dataclass(frozen=True, slots=True)
class SaveRequest:
    """What the workbench hands back: the draft and where to save it."""
    draft: tb.Draft
    tag: str
    name: str
    grant: tr.Grant


def _scope_text(fact: tb.Fact) -> str:
    if fact.ports is None:
        return f"any/{fact.protocol}" if fact.protocol else ""
    return tr.format_ports(fact.ports, fact.protocol)


def _counts(selected: int, of: int, others: int) -> str:
    return f"{selected}/{of} sel  {others:>6} others"


class RuleBenchScreen(ModalScreen[SaveRequest | None]):
    """The workbench. Returns a `SaveRequest`, or None when left."""

    BINDINGS = [
        Binding("escape", "leave", "Leave"),
        Binding("space", "cycle", "Cycle", show=False),
        Binding("plus", "set('require')", "Require", show=False),
        Binding("minus", "set('exclude')", "Exclude", show=False),
        Binding("e", "edit", "Edit", show=False),
        Binding("p", "same_port", "Same port", show=False),
        Binding("a", "add_host", "Add", show=False),
        Binding("d", "drop_host", "Drop", show=False),
        Binding("x", "exclude_host", "Exclude host", show=False),
        Binding("s", "save", "Save", show=False),
    ]
    DEFAULT_CSS = _FRAME.format(name="RuleBenchScreen") + """
    RuleBenchScreen > #frame { width: 100%; height: 100%; }
    RuleBenchScreen #body { height: 1fr; }
    RuleBenchScreen #facts { width: 3fr; height: 1fr; }
    RuleBenchScreen #hosts { width: 2fr; height: 1fr; }
    RuleBenchScreen OptionList { background: transparent; }
    RuleBenchScreen #title { text-style: bold; }
    RuleBenchScreen #notes { color: $warning; height: auto; }
    RuleBenchScreen #total { border-top: solid $primary; height: auto; }
    RuleBenchScreen #keys { color: $text-muted; text-wrap: nowrap; text-overflow: ellipsis; }
    """

    def __init__(self, builder: tb.Builder, draft: tb.Draft, tags: list[str], *,
                 rule: tr.Rule | None = None) -> None:
        super().__init__()
        self.builder = builder
        self.draft = draft
        self._start = draft
        self._tags = tags
        self._rule = rule                       # set when a saved rule is edited
        self.assessment: tb.Assessment | None = None
        self._fact_ids: dict[str, tb.Fact] = {}
        self._combo: tuple[tb.Fact, ...] = ()

    def compose(self) -> ComposeResult:
        with Vertical(id="frame"):
            yield Label(id="title")
            with Horizontal(id="body"):
                yield OptionList(id="facts")
                yield OptionList(id="hosts")
            yield Static(id="notes")
            yield Static(id="total")
            yield Static(KEYS, id="keys")

    def on_mount(self) -> None:
        self.query_one("#facts", OptionList).focus()
        self._title()
        self._recount(debounce=False)

    # --- counting -------------------------------------------------------------------

    def _title(self) -> None:
        what = (f"Rule builder · {self._rule.tag} · {self._rule.name}" if self._rule
                else "Rule builder")
        port = "on" if self.draft.same_port else "off"
        self.query_one("#title", Label).update(
            f"{what} · {len(self.draft.selection)} selected · same port: {port} (p)")

    def _change(self, draft: tb.Draft) -> None:
        self.draft = draft
        self._title()
        self._recount()

    def _recount(self, debounce: bool = True) -> None:
        self._assess(self.draft, debounce)

    @work(exclusive=True, group="bench")
    async def _assess(self, draft: tb.Draft, debounce: bool) -> None:
        if debounce:
            await asyncio.sleep(DEBOUNCE)
        got = await asyncio.to_thread(tb.assess, self.builder, draft)
        if draft is self.draft:                 # a newer change counts again
            self.assessment = got
            self._show(got)

    # --- what is on screen ------------------------------------------------------------

    def _show(self, a: tb.Assessment) -> None:
        facts = self.query_one("#facts", OptionList)
        keep = facts.highlighted_option.id if facts.highlighted_option else None
        options: list[Option] = []
        self._fact_ids = {}
        group = None
        n = a.of_selection
        for k, row in enumerate(a.rows):
            if row.fact.group != group:
                group = row.fact.group
                options.append(Option(Text(group, style="bold"), disabled=True))
            fid = f"f{k}"
            self._fact_ids[fid] = row.fact
            label = Text(f" {_MARK[row.state]} ")
            label.append(row.fact.label.removeprefix(f"{group} ") if group != "host"
                         else row.fact.label)
            label.append(f"  {_counts(row.selected, n, row.others)}", style="dim")
            options.append(Option(label, id=fid))
        self._combo = ()
        if a.other_count and (a.exclusions or a.combination):
            options.append(Option(Text(f"exclude to drop {a.other_count}", style="bold"),
                                  disabled=True))
            if a.combination is not None and len(a.combination.facts) > 1:
                self._combo = a.combination.facts
                labels = " and ".join(f.label for f in a.combination.facts)
                options.append(Option(Text(f" − {labels}  (leaves {a.combination.remaining})"),
                                      id="combo"))
            for k, p in enumerate(a.exclusions):
                fid = f"x{k}"
                self._fact_ids[fid] = p.fact
                assumed = (f", assumed on {len(p.assumed_on)} selected" if p.assumed_on
                           else "")
                options.append(Option(Text(f" − {p.fact.label}  (excludes {p.excludes}/"
                                           f"{a.other_count}{assumed})"), id=fid))
        facts.clear_options()
        facts.add_options(options)
        self._keep(facts, keep)
        hosts = self.query_one("#hosts", OptionList)
        keep = hosts.highlighted_option.id if hosts.highlighted_option else None
        rows: list[Option] = [Option(Text(f"selection ({len(a.selection)})", style="bold"),
                                     disabled=True)]
        for m in a.selection:
            mark = ("~" if m.assumed else "✓") if m.matched else "✗"
            rows.append(Option(Text(f" {mark} {m.address:<16} {m.ports}  {m.title}"),
                               id=f"s:{m.address}"))
        if a.other_count:
            more = (f", first {len(a.others)}" if a.other_count > len(a.others) else "")
            rows.append(Option(Text(f"matches also ({a.other_count}{more})", style="bold"),
                               disabled=True))
            for m in a.others:
                rows.append(Option(Text(f"   {m.address:<16} {m.ports}  {m.title}"),
                                   id=f"o:{m.address}"))
        hosts.clear_options()
        hosts.add_options(rows)
        self._keep(hosts, keep)
        self.query_one("#notes", Static).update(
            "\n".join([*a.notes, *([a.confirm] if a.confirm else [])]))
        total = (f"matches {a.matched} · {a.selected_matched}/{a.of_selection} selected · "
                 f"{a.other_count} others · {len(a.assumed)} assumed" if a.rule
                 else "require (+) or exclude (-) a fact to start the rule")
        self.query_one("#total", Static).update(total)

    @staticmethod
    def _keep(options: OptionList, wanted: str | None) -> None:
        if wanted is not None:
            try:
                options.highlighted = options.get_option_index(wanted)
                return
            except Exception:  # noqa: BLE001 - an option that is gone
                pass
        first = next((k for k in range(options.option_count)
                      if not options.get_option_at_index(k).disabled), None)
        options.highlighted = first

    def _highlighted(self, pane: str) -> str | None:
        options = self.query_one(f"#{pane}", OptionList)
        if self.focused is not options or options.highlighted_option is None:
            return None
        return options.highlighted_option.id

    # --- facts -----------------------------------------------------------------------

    def _fact(self) -> tb.Fact | None:
        fid = self._highlighted("facts")
        return self._fact_ids.get(fid) if fid else None

    def action_cycle(self) -> None:
        fid = self._highlighted("facts")
        if fid == "combo":
            self.action_set("exclude")
            return
        fact = self._fact()
        if fact is None:
            return
        state = self.draft.state_of(fact)
        if fid and fid.startswith("x") and state is tb.State.IGNORE:
            self._change(self.draft.with_state(fact, tb.State.EXCLUDE))
            return
        self._change(self.draft.with_state(fact, _CYCLE[state]))

    def action_set(self, state: str) -> None:
        if self._highlighted("facts") == "combo":
            draft = self.draft
            for fact in self._combo:
                draft = draft.with_state(fact, tb.State.EXCLUDE)
            self._change(draft)
            return
        fact = self._fact()
        if fact is not None:
            self._change(self.draft.with_state(fact, tb.State(state)))

    def action_same_port(self) -> None:
        self._change(tb.Draft(self.draft.selection, self.draft.facts,
                              not self.draft.same_port))

    def action_edit(self) -> None:
        fact = self._fact()
        if fact is None:
            return
        if fact.kind in (tb.Kind.TAG, tb.Kind.ADDRESS, tb.Kind.FIXED):
            self.notify("this fact is kept as it is - require, exclude or ignore it",
                        severity="warning")
            return
        self._edit(fact)

    @work(exclusive=True, group="bench-modal")
    async def _edit(self, fact: tb.Fact) -> None:
        new = await self.app.push_screen_wait(FactEditScreen(self.builder, self.draft, fact))
        if new is not None and new != fact:
            self._change(self.draft.replace_fact(fact, new))

    # --- hosts -----------------------------------------------------------------------

    def _host(self, prefix: str) -> str | None:
        hid = self._highlighted("hosts")
        return hid[2:] if hid and hid.startswith(prefix) else None

    def action_add_host(self) -> None:
        address = self._host("o:")
        if address:
            self._change(self.draft.add(address))

    def action_drop_host(self) -> None:
        address = self._host("s:")
        if address:
            self._change(self.draft.drop(address))

    def action_exclude_host(self) -> None:
        address = self._host("o:")
        if address:
            self._change(self.draft.with_state(tb.Fact(tb.Kind.ADDRESS, value=address),
                                               tb.State.EXCLUDE))

    # --- leaving --------------------------------------------------------------------

    def action_leave(self) -> None:
        self._leave()

    @work(exclusive=True, group="bench-modal")
    async def _leave(self) -> None:
        if self.draft != self._start:
            answer = await self.app.push_screen_wait(ChoiceScreen(
                "Leave the rule builder? The draft is not saved.",
                [("stay", "stay and keep the draft"), ("leave", "leave, discard the draft")]))
            if answer != "leave":
                return
        self.dismiss(None)

    def action_save(self) -> None:
        self._save()

    @work(exclusive=True, group="bench-modal")
    async def _save(self) -> None:
        a = await asyncio.to_thread(tb.assess, self.builder, self.draft)
        if not a.rule:
            self.notify("require or exclude a fact first", severity="warning")
            return
        if a.confirm:
            answer = await self.app.push_screen_wait(ChoiceScreen(
                f"{a.confirm.capitalize()}. Save it anyway?",
                [("no", "no, keep editing"), ("yes", "yes, save it")]))
            if answer != "yes":
                return
        rule = self._rule
        got = await self.app.push_screen_wait(RuleSaveScreen(
            self._tags, rule.name if rule else f"built from {a.of_selection} host(s)",
            rule.grant if rule else tr.Grant.HOST, tag=rule.tag if rule else None))
        if got is not None:
            tag, name, grant = got
            self.dismiss(SaveRequest(self.draft, tag, name, grant))


class FactEditScreen(ModalScreen[tb.Fact | None]):
    """Edit one fact: its value, mode, case and ports, counted as it is typed."""

    BINDINGS = [Binding("escape", "cancel", "Cancel"),
                Binding("ctrl+s", "take", "Take", show=False)]
    DEFAULT_CSS = _FRAME.format(name="FactEditScreen") + """
    FactEditScreen > #frame { width: 72; }
    FactEditScreen Input, FactEditScreen Select { margin: 0 0 1 0; }
    FactEditScreen #error { color: $error; height: auto; }
    FactEditScreen #count { height: auto; }
    FactEditScreen #warn { color: $warning; height: auto; }
    FactEditScreen Button { margin: 1 1 0 0; }
    """

    def __init__(self, builder: tb.Builder, draft: tb.Draft, fact: tb.Fact) -> None:
        super().__init__()
        self.builder = builder
        self.draft = draft
        self.fact = fact
        self.current: tb.Fact | None = fact
        self._typed = 0

    def compose(self) -> ComposeResult:
        f = self.fact
        text = f.kind is not tb.Kind.OPEN
        with Vertical(id="frame"):
            yield Label(f"Edit: {f.label}")
            if text:
                yield Label("Value")
                yield Input(f.value, id="value")
                yield Select([(label, m.value) for label, m in _MODES], value=f.mode.value,
                             allow_blank=False, id="mode")
                yield Checkbox("match case", f.case, id="case")
            if f.has_ports:
                yield Label("Ports - one, a list such as 80,8000-8999/tcp, or empty for any")
                yield Input(_scope_text(f), id="ports")
            yield Static(id="count")
            yield Static(id="warn")
            yield Static(id="error")
            with Horizontal():
                yield Button("Take", id="take", variant="primary")
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        self.query(Input).first().focus()
        self._recount()

    def _typed_fact(self) -> tb.Fact:
        f = self.fact
        value = self.query_one("#value", Input).value if f.kind is not tb.Kind.OPEN else ""
        mode = (self.query_one("#mode", Select).value if f.kind is not tb.Kind.OPEN
                else tb.Mode.EQUALS.value)
        case = self.query_one("#case", Checkbox).value if f.kind is not tb.Kind.OPEN else False
        ports = self.query_one("#ports", Input).value if f.has_ports else None
        return tb.fact_from(f.kind, protocol=f.protocol, ports=ports, value=value,
                            mode=mode, case=case)

    @on(Input.Changed)
    @on(Select.Changed)
    @on(Checkbox.Changed)
    def _changed(self, _event) -> None:
        self._recount()

    def _recount(self) -> None:
        error = self.query_one("#error", Static)
        try:
            fact = self._typed_fact()
        except tr.RuleError as exc:
            self.current = None
            error.update(str(exc))
            self.query_one("#take", Button).disabled = True
            return
        error.update("")
        self.query_one("#take", Button).disabled = False
        self.current = fact
        self._count(fact)

    @work(exclusive=True, group="refine")
    async def _count(self, fact: tb.Fact) -> None:
        await asyncio.sleep(DEBOUNCE)
        got = await asyncio.to_thread(tb.refine, self.builder, self.draft, fact)
        if fact != self.current:
            return
        self.query_one("#count", Static).update(
            f"{fact.label}\nmatches {got.selected}/{got.of_selection} selected · "
            f"{got.others} others")
        self.query_one("#warn", Static).update(
            f"drops {len(got.dropped)} selected host(s): {', '.join(got.dropped[:5])}"
            + (" …" if len(got.dropped) > 5 else "") if got.dropped else "")

    @on(Input.Submitted)
    def _submitted(self, _event) -> None:
        self.action_take()

    @on(Button.Pressed, "#take")
    def _take_pressed(self, _event) -> None:
        self.action_take()

    @on(Button.Pressed, "#cancel")
    def _cancel_pressed(self, _event) -> None:
        self.dismiss(None)

    def action_take(self) -> None:
        if self.current is not None:
            self.dismiss(self.current)

    def action_cancel(self) -> None:
        self.dismiss(None)


class RuleSaveScreen(ModalScreen[tuple[str, str, tr.Grant] | None]):
    """Where the rule goes: a tag (an existing one or a new name), the rule's name,
    and what it tags. The tag is fixed when a saved rule is edited."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]
    DEFAULT_CSS = _FRAME.format(name="RuleSaveScreen") + """
    RuleSaveScreen > #frame { width: 64; }
    RuleSaveScreen Input, RuleSaveScreen Select { margin: 0 0 1 0; }
    RuleSaveScreen #error { color: $error; height: auto; }
    RuleSaveScreen Button { margin: 1 1 0 0; }
    """

    def __init__(self, tags: list[str], name: str, grant: tr.Grant,
                 tag: str | None = None) -> None:
        super().__init__()
        self._tags = tags
        self._name = name
        self._grant = grant
        self._tag = tag

    def compose(self) -> ComposeResult:
        with Vertical(id="frame"):
            yield Label("Save the rule")
            yield Label("Tag" + (" (the rule's own)" if self._tag else
                                 f" - one of {len(self._tags)} or a new name"))
            yield Input(self._tag or "", id="tag", disabled=self._tag is not None,
                        suggester=SuggestFromList(self._tags, case_sensitive=False))
            yield Label("Rule name")
            yield Input(self._name, id="name")
            yield Label("It tags")
            yield Select([(label, g.value) for label, g in _GRANTS], value=self._grant.value,
                         allow_blank=False, id="grant")
            yield Static(id="error")
            with Horizontal():
                yield Button("Save", id="save", variant="primary")
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        (self.query_one("#name", Input) if self._tag else self.query_one("#tag", Input)).focus()

    @on(Input.Submitted)
    def _submitted(self, _event) -> None:
        self.action_save()

    @on(Button.Pressed, "#save")
    def _save_pressed(self, _event) -> None:
        self.action_save()

    @on(Button.Pressed, "#cancel")
    def _cancel_pressed(self, _event) -> None:
        self.dismiss(None)

    def action_save(self) -> None:
        error = self.query_one("#error", Static)
        try:
            tag = tr.tag_name(self.query_one("#tag", Input).value)
        except tr.RuleError as exc:
            error.update(str(exc))
            return
        name = self.query_one("#name", Input).value.strip()
        if not name:
            error.update("give the rule a name")
            return
        self.dismiss((tag, name, tr.Grant(self.query_one("#grant", Select).value)))

    def action_cancel(self) -> None:
        self.dismiss(None)
