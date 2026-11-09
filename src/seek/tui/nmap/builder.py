"""The scan chooser and the guided command builder - the terminal's view of
`seek.nmap.builder`, which holds every rule; nothing here decides an option.

Layout, wide (120 columns or more): the step list, the step's content and help
for the focused item side by side, then the command, then the keys. Narrow: the
step list folds into one line and help moves behind `?`.

**The builder is full height, and its list is `1fr`.** The other scan dialogs
size to their content and measure what is left (`_Fits`); the builder did too,
and lost a race: its command line can grow a row a refresh *after* the list's
height was measured, which put the command under the frame's edge at 60x18 -
locally rarely, on a slower CI runner every time. A full-height frame lets
Textual give the list what the title, the command and the keys leave in one
layout pass, with nothing measured; and the dialog keeps its size from step
to step instead of growing and shrinking under the reader.
"""

from __future__ import annotations

import textwrap
import threading
from dataclasses import replace

from rich.console import Group
from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Input, Label, OptionList, Static
from textual.widgets.option_list import Option

from seek.nmap import builder as model
from seek.nmap import options as catalogue
from seek.nmap import timing
from seek.nmap.recent import Earlier, text
from seek.tui.menu import ChoiceScreen
from seek.tui.nmap.scope import _FRAME, PresetScreen

WIDE = 120
_MARK = {"done": "✓", "current": "●", "ahead": "○", "skipped": "–"}
_SOURCE_WORDS = {"you": "you", "your answers": "your answers", "profile": "profile",
                 "measured now": "measured now", "earlier scans": "earlier scans",
                 "default": "default"}


def _when(earlier: Earlier) -> str:
    import datetime
    if not earlier.last:
        return earlier.where
    stamp = datetime.datetime.fromtimestamp(earlier.last).strftime("%Y-%m-%d %H:%M")
    return f"{earlier.where} · {stamp}"


class ChooserScreen(PresetScreen):
    """What to scan with: build a command, one used before, or a preset.

    Returns `@build`, `@recent:N`, `@frequent:N` or a preset name. Typing
    filters every section at once; Esc clears the filter, then leaves.
    """

    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(self, title: str, scope_line: str, presets: dict[str, str],
                 recent: list[Earlier], frequent: list[Earlier]) -> None:
        super().__init__(title, scope_line, presets)
        self.recent = recent
        self.frequent = frequent
        self._filter = ""

    def compose(self) -> ComposeResult:
        with Vertical(id="frame"):
            yield Label(self._title)
            yield Label(self._scope_line, id="scope")
            yield OptionList(*self._options(), classes="flex")
            yield Label("", id="filter")
            yield Label("↑↓ move · ↵ choose · type to filter · Esc cancel", id="keys")

    def _heading(self, text_: str) -> Option:
        return Option(Text(text_, style="bold"), disabled=True)

    def _earlier(self, key: str, earlier: Earlier) -> Option:
        head = Text(earlier.args, style="bold", no_wrap=True, overflow="ellipsis")
        count = f" · used {earlier.count}×" if earlier.count > 1 else ""
        body = Text(f"  {_when(earlier)}{count}", style="dim", no_wrap=True,
                    overflow="ellipsis")
        return Option(Group(head, body), id=key)

    def _matches(self, *texts: str) -> bool:
        needle = self._filter.lower()
        return not needle or any(needle in t.lower() for t in texts)

    def _options(self) -> list[Option]:
        found: list[Option] = []
        if self._matches("build a command guided"):
            found.append(Option(Group(Text("Build a command…", style="bold"),
                                      Text("  guided: explains each option, measures "
                                           "the network, ends with a fast and a "
                                           "reliable command", style="dim", no_wrap=True,
                                           overflow="ellipsis")), id="@build"))
        for title, key, items in (("Recent", "recent", self.recent),
                                  ("Frequent", "frequent", self.frequent)):
            shown = [(i, e) for i, e in enumerate(items) if self._matches(e.args)]
            if shown:
                found.append(self._heading(title))
                found += [self._earlier(f"@{key}:{i}", e) for i, e in shown]
        presets = [(n, a) for n, a in self._presets.items() if self._matches(n, a)]
        if presets:
            found.append(self._heading("Presets"))
            found += [self._option(n, a) for n, a in presets]
        return found

    def _refill(self) -> None:
        options = self.query_one(OptionList)
        options.clear_options()
        options.add_options(self._options())
        self.query_one("#filter", Label).update(
            Text(f"filter: {self._filter}", style="dim") if self._filter else "")
        first = next((i for i in range(options.option_count)
                      if not options.get_option_at_index(i).disabled), None)
        options.highlighted = first
        self.call_after_refresh(self._fit)

    def on_key(self, event) -> None:
        if event.is_printable and event.character and event.character != " ":
            self._filter += event.character
            self._refill()
            event.stop()
        elif event.key == "backspace" and self._filter:
            self._filter = self._filter[:-1]
            self._refill()
            event.stop()

    def action_cancel(self) -> None:
        if self._filter:
            self._filter = ""
            self._refill()
            return
        self.dismiss(None)


class BuilderScreen(ModalScreen[tuple[str, list[str], str] | None]):
    """The guided builder. Returns (profile, arguments, goal) or None."""

    BINDINGS = [
        Binding("escape", "leave", "Leave"),
        Binding("left,h,backspace", "back", "Back", show=False),
        Binding("right,l", "forward", "Forward", show=False),
        Binding("question_mark", "help", "Help", show=False),
        Binding("ctrl+s", "finish", "Finish", show=False),
        Binding("space", "toggle", "Toggle", show=False),
        Binding("slash", "filter", "Filter", show=False),
        Binding("r", "reset", "Reset", show=False),
        Binding("s", "set_first", "Set first", show=False),
        *[Binding(str(n), f"jump({n})", show=False) for n in range(1, 9)],
    ]
    DEFAULT_CSS = _FRAME.format(name="BuilderScreen") + """
    BuilderScreen > #frame { width: 150; height: 100%; }
    BuilderScreen #body { height: 1fr; }
    BuilderScreen #steps { width: 16; display: none; }
    BuilderScreen #content { width: 1fr; height: 1fr; }
    BuilderScreen #help { width: 34; display: none; padding: 0 0 0 2; color: $text-muted; }
    BuilderScreen.wide #steps, BuilderScreen.wide #help { display: block; }
    BuilderScreen.wide #stepline { display: none; }
    BuilderScreen.helping #help { display: block; width: 1fr; }
    BuilderScreen.helping #content { display: none; }
    BuilderScreen #question { text-style: bold; }
    BuilderScreen OptionList { height: 1fr; min-height: 3; background: transparent; }
    BuilderScreen #filter-box, BuilderScreen #edit { display: none; border: none;
        height: 1; padding: 0 1; }
    BuilderScreen #filter-box.on, BuilderScreen #edit.on { display: block; }
    BuilderScreen #error { color: $error; height: auto; display: none; }
    BuilderScreen #notes { color: $text-muted; height: auto; display: none; }
    BuilderScreen #error.on, BuilderScreen #notes.on { display: block; }
    BuilderScreen #command { border-top: solid $primary; padding: 0 0; height: auto; }
    BuilderScreen #keys, BuilderScreen #stepline { color: $text-muted; text-wrap: nowrap;
        text-overflow: ellipsis; }
    """

    def __init__(self, facts: model.Facts, program: str = "nmap",
                 nmap_available: bool = True) -> None:
        super().__init__()
        self.facts = facts
        self.state = model.State()
        self.program = program
        self.nmap_available = nmap_available
        self._query = ""
        self._set_first = False
        self._editing: str | None = None
        self._measuring: threading.Event | None = None
        self._notes: list[str] = []

    # --- layout ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        with Vertical(id="frame"):
            yield Label(f"Build a scan · {len(self.facts.targets)} target(s)")
            yield Static(id="stepline")
            with Horizontal(id="body"):
                yield Static(id="steps")
                with Vertical(id="content"):
                    yield Label(id="question")
                    yield Input(id="filter-box", placeholder="filter options by name or "
                                "description")
                    yield OptionList(id="list")
                    yield Input(id="edit")
                    yield Static(id="error")
                    yield Static(id="notes")
                yield Static(id="help")
            yield Static(id="command")
            yield Static(id="keys")

    def on_mount(self) -> None:
        self._wide()
        self._show()
        self.query_one("#list", OptionList).focus()

    def on_resize(self, _event) -> None:
        self._wide()

    def _wide(self) -> None:
        self.set_class(self.size.width >= WIDE, "wide")

    # --- what is on screen ----------------------------------------------------------

    @property
    def step(self) -> str:
        return self.state.step

    def _show(self, keep: str | None = None) -> None:
        step = next(s for s in model.STEPS if s.key == self.step)
        self.query_one("#question", Label).update(step.question)
        self._steps()
        listing = self.query_one("#list", OptionList)
        listing.clear_options()
        if self.step == "tune":
            listing.add_options(self._tune_options())
        elif self.step == "choose":
            listing.add_options(self._choose_options())
        else:
            listing.add_options(self._choice_options())
        target = keep or self.state.answer(self.step) or \
            model.recommended(self.step, self.state, self.facts)
        index = None
        for i in range(listing.option_count):
            option = listing.get_option_at_index(i)
            if option.disabled:
                continue
            if index is None or option.id == target:
                index = i
                if option.id == target:
                    break
        listing.highlighted = index
        self.query_one("#filter-box").set_class(self.step == "tune" and bool(self._query), "on")
        self._keys()
        self._command()
        self._help()
        notes = self.query_one("#notes", Static)
        notes.update(Text("\n".join(self._notes), style="dim"))
        notes.set_class(bool(self._notes), "on")

    def _width(self) -> int:
        """The text width of a list row - OptionList wraps and ignores no_wrap,
        so rows are wrapped (with a hanging indent) or clipped here instead."""
        width = self.query_one("#list", OptionList).scrollable_content_region.width
        return max(20, (width or 72) - 2)

    def _hang(self, mark: str, words: str, style: str = "dim") -> Text:
        lines = textwrap.wrap(words, self._width() - 6) or [""]
        out = Text(f"    {mark} {lines[0]}", style=style)
        for line in lines[1:]:
            out.append(f"\n      {line}", style=style)
        return out

    def _clip(self, line: Text) -> Text:
        line.truncate(self._width(), overflow="ellipsis")
        return line

    def _steps(self) -> None:
        lines = Text()
        visible = model.visible_steps(self.state)
        for number, step in enumerate(model.STEPS, 1):
            state = model.status(step.key, self.state)
            style = "bold" if state == "current" else ("dim" if state != "done" else "")
            lines.append(f"{_MARK[state]} {number} {step.title}\n", style=style)
        self.query_one("#steps", Static).update(lines)
        index = [s.key for s in visible].index(self.step) + 1
        marks = "".join(_MARK[model.status(s.key, self.state)] for s in visible)
        title = next(s.title for s in model.STEPS if s.key == self.step)
        self.query_one("#stepline", Static).update(
            Text(f"Step {index} of {len(visible)} · {title}  {marks}", style="dim"))

    def _choice_options(self) -> list[Option]:
        found = []
        current = self.state.answer(self.step)
        for choice in model.choices(self.step, self.state, self.facts):
            head = Text(no_wrap=True, overflow="ellipsis")
            head.append("● " if choice.key == current else "○ ")
            head.append(choice.label, style="bold")
            if choice.adds:
                head.append(f"  {choice.adds}", style="cyan")
            if choice.recommended:
                head.append("   recommended", style="italic")
            found.append(Option(Group(self._clip(head), self._hang("+", choice.gain),
                                      self._hang("−", choice.cost)), id=choice.key))
        return found

    def _choose_options(self) -> list[Option]:
        fast, reliable = model.both(self.state, self.facts)
        found = []
        for profile, built, label in ((model.FAST, fast, "Fast"),
                                      (model.RELIABLE, reliable, "Reliable")):
            other = reliable if built is fast else fast
            differs = [" ".join(catalogue.tokens(catalogue.BY_NAME[n], s.value))
                       for n, s in built.settings.items()
                       if s.source != "you" and (n not in other.settings
                                                 or other.settings[n].value != s.value)]
            head = Text(label, style="bold")
            if profile == model.RELIABLE:
                head.append("   recommended", style="italic")
            lines = [head, self._hang(" ", text(built.args), "cyan")]
            if differs:
                lines.append(self._hang("≠", "differs: " + ", ".join(differs)))
            for miss in built.misses:
                lines.append(self._hang("−", miss))
            if not built.misses and profile == model.FAST:
                lines.append(self._hang("−", "nothing the reliable one would find more of"))
            found.append(Option(Group(*lines), id=profile))
        return found

    def _tune_options(self) -> list[Option]:
        view = model.tune_view(self.state, self.facts, query=self._query,
                               set_first=self._set_first)
        found = []
        for group, rows in view.groups:
            count = sum(1 for r in rows if r.setting is not None)
            found.append(Option(Text(f"{group}" + (f" · {count} set" if count else ""),
                                     style="bold"), disabled=True))
            for row in rows:
                found.append(self._row(row))
        if not found:
            found.append(Option(Text("no option matches the filter", style="dim"),
                                disabled=True))
        return found

    def _row(self, row: model.OptionRow) -> Option:
        option, setting = row.option, row.setting
        line = Text(no_wrap=True, overflow="ellipsis")
        if option.owner:
            line.append(f"    {option.name}", style="dim")
            line.append("  set by seek", style="dim italic")
            return Option(self._clip(line), id=option.name)
        if option.flag:
            line.append("[x] " if setting is not None else "[ ] ")
            line.append(option.name, style="bold" if setting else "")
        else:
            line.append("    ")
            line.append(option.name, style="bold" if setting else "")
            if setting is not None:
                line.append(f"  {setting.value or '(on)'}", style="cyan")
        if setting is not None:
            line.append(f"  ‹{_SOURCE_WORDS.get(setting.source, setting.source)}›",
                        style="dim")
        line.append(f"  {option.about}", style="dim")
        return Option(self._clip(line), id=option.name)

    def _keys(self) -> None:
        common = "← back · ? help · ^S finish · Esc leave"
        keys = {
            "tune": "↑↓ move · Space on/off · ↵ edit value · / filter · r reset · "
                    "s set first · " + common,
            "choose": "↑↓ move · ↵ use this command · ← back · Esc leave",
        }.get(self.step, "↑↓ move · ↵ choose · " + common)
        self.query_one("#keys", Static).update(Text(keys))

    def _highlighted(self) -> str | None:
        listing = self.query_one("#list", OptionList)
        if listing.highlighted is None:
            return None
        return listing.get_option_at_index(listing.highlighted).id

    def _command(self) -> None:
        key = self._highlighted()
        if self.step == "choose":
            built = model.resolve(self.state, self.facts, key or model.RELIABLE)
            args = built.args
        elif self.step == "tune" or key is None:
            args = model.resolve(self.state, self.facts, model.RELIABLE).args
        else:
            args = model.preview(self.state, self.facts, self.step, key)
        line = Text()
        line.append(f"{self.program} ", style="bold")
        line.append(text(args))
        line.append(f"  ‹{len(self.facts.targets)} target(s)›", style="dim")
        self.query_one("#command", Static).update(line)

    def _help(self) -> None:
        key = self._highlighted()
        lines: list[str] = []
        if self.step == "tune" and key in catalogue.BY_NAME:
            lines = model.help_text(key)
            setting = model.resolve(self.state, self.facts, model.RELIABLE).settings.get(key)
            if setting is not None:
                lines.insert(2, f"now: {setting.value or 'on'} - {setting.why or setting.source}")
                if setting.overrode:
                    lines.insert(3, f"overrides: {', '.join(setting.overrode)}")
        elif key is not None and self.step not in ("tune", "choose"):
            for choice in model.choices(self.step, self.state, self.facts):
                if choice.key == key:
                    lines = [choice.label, f"+ {choice.gain}", f"− {choice.cost}"]
                    first = next((t for t in choice.adds.split() if t in catalogue.BY_NAME),
                                 None)
                    if first:
                        lines += ["", *model.help_text(first)]
                    elif choice.source in catalogue.PAGES:
                        lines.append(catalogue.page_url(choice.source))
        self.query_one("#help", Static).update(Text("\n".join(lines)))

    # --- reacting ----------------------------------------------------------------------

    @on(OptionList.OptionHighlighted, "#list")
    def _moved(self, _event) -> None:
        self._command()
        self._help()

    @on(OptionList.OptionSelected, "#list")
    def _chosen(self, event: OptionList.OptionSelected) -> None:
        key = event.option.id or ""
        if self.step == "tune":
            self._edit(key)
            return
        if self.step == "choose":
            built = model.resolve(self.state, self.facts, key)
            self.dismiss((key, built.args, self.state.answer("goal") or "scan"))
            return
        if self.step == "network" and key == "measure":
            self._offer_measurement()
            return
        self._take(key)

    def _take(self, key: str) -> None:
        self._notes = []
        self.state = model.advance(self.state, self.step, key)
        self._show()

    def action_back(self) -> None:
        if self._editing is not None:
            self._stop_editing()
            return
        self.state = model.back(self.state)
        self._notes = []
        self._show()

    def action_forward(self) -> None:
        keys = [s.key for s in model.visible_steps(self.state)]
        index = keys.index(self.step)
        if index + 1 < len(keys) and model.status(keys[index + 1], self.state) == "done":
            self.state = replace(self.state, step=keys[index + 1])
            self._show()

    def action_jump(self, number: int) -> None:
        if number - 1 < len(model.STEPS):
            moved = model.jump(self.state, model.STEPS[number - 1].key)
            if moved != self.state:
                self.state = moved
                self._show()

    def action_finish(self) -> None:
        if self.state.answer("goal") is None:
            self.notify("choose a goal first", severity="warning")
            return
        self.state = replace(self.state, step="choose")
        self._show()

    def action_help(self) -> None:
        if not self.has_class("wide"):
            self.toggle_class("helping")

    def action_leave(self) -> None:
        if self.has_class("helping"):
            self.remove_class("helping")
            return
        if self._measuring is not None:
            self._measuring.set()
            return
        if self._editing is not None:
            self._stop_editing()
            return
        if self._query:
            self._query = ""
            self.query_one("#filter-box", Input).value = ""
            self._show()
            return
        if not self.state.answers and not self.state.overrides:
            self.dismiss(None)
            return
        self._confirm_leave()

    @work(exclusive=True, group="builder-modal")
    async def _confirm_leave(self) -> None:
        answer = await self.app.push_screen_wait(ChoiceScreen(
            "Discard the answers?", [("discard", "d  discard them and leave"),
                                     ("continue", "c  continue building")]))
        if answer == "discard":
            self.dismiss(None)

    # --- fine-tune --------------------------------------------------------------------

    def action_toggle(self) -> None:
        if self.step != "tune":
            return
        name = self._highlighted()
        option = catalogue.BY_NAME.get(name or "")
        if option is None or not option.flag or option.owner:
            return
        on = name in model.resolve(self.state, self.facts, model.RELIABLE).settings
        self.state = self.state.set(name, None if on else "")
        self._show(keep=name)

    def action_reset(self) -> None:
        name = self._highlighted()
        if self.step == "tune" and name:
            self.state = self.state.reset(name)
            self._show(keep=name)

    def action_set_first(self) -> None:
        if self.step == "tune":
            self._set_first = not self._set_first
            self._show()

    def action_filter(self) -> None:
        if self.step != "tune":
            return
        box = self.query_one("#filter-box", Input)
        box.add_class("on")
        box.focus()

    @on(Input.Changed, "#filter-box")
    def _filtered(self, event: Input.Changed) -> None:
        self._query = event.value
        self._show()
        self.query_one("#filter-box", Input).focus()

    @on(Input.Submitted, "#filter-box")
    def _filter_done(self, _event) -> None:
        self.query_one("#list", OptionList).focus()

    def _edit(self, name: str) -> None:
        option = catalogue.BY_NAME.get(name)
        if option is None:
            return
        if option.owner:
            self._error(f"{option.name} is set by seek: {option.owner}", "dim")
            return
        if option.flag:
            self.action_toggle()
            return
        current = model.resolve(self.state, self.facts, model.RELIABLE).settings.get(name)
        edit = self.query_one("#edit", Input)
        edit.placeholder = f"{option.name}: {option.value.hint} - ↵ set · Esc cancel"
        edit.value = (current.value or "") if current else ""
        edit.add_class("on")
        self._editing = name
        edit.focus()

    @on(Input.Changed, "#edit")
    def _edited(self, event: Input.Changed) -> None:
        if self._editing is None:
            return
        problem = catalogue.check(catalogue.BY_NAME[self._editing], event.value)
        self._error(f"✗ {problem}" if problem and event.value else "")

    @on(Input.Submitted, "#edit")
    def _edit_done(self, event: Input.Submitted) -> None:
        name = self._editing
        if name is None:
            return
        option = catalogue.BY_NAME[name]
        value = event.value.strip()
        problem = catalogue.check(option, value)
        if value and problem:
            self._error(f"✗ {problem}")
            return
        self.state = self.state.set(name, value if value else None)
        self._stop_editing()
        self._show(keep=name)

    def _stop_editing(self) -> None:
        self._editing = None
        edit = self.query_one("#edit", Input)
        edit.remove_class("on")
        self._error("")
        self.query_one("#list", OptionList).focus()

    def _error(self, message: str, style: str = "bold") -> None:
        error = self.query_one("#error", Static)
        error.update(Text(message, style=style))
        error.set_class(bool(message), "on")

    # --- measuring --------------------------------------------------------------------

    def _pairs(self) -> list[tuple[str, int]]:
        ports = [int(p) for p in self.facts.tcp_ports.split(",") if p.isdigit()]
        up = [t for t in self.facts.targets if t in self.facts.up] or list(self.facts.targets)
        return [(host, ports[0]) for host in up[:timing.HOSTS]] if ports else []

    @work(exclusive=True, group="builder-modal")
    async def _offer_measurement(self) -> None:
        pairs = self._pairs()
        hosts = [h for h, _ in pairs] or list(self.facts.targets[:timing.HOSTS])
        if pairs:
            what = (f"{timing.TRIES} TCP connections each to {len(pairs)} host(s), to port "
                    f"{pairs[0][1]} which is known open - no root needed")
        elif self.nmap_available:
            what = (f"one nmap ping scan (-sn -n) of {len(hosts)} host(s); unprivileged it "
                    "connects to ports 80 and 443")
        else:
            self._notes = ["nothing to measure with: no known open port, and nmap is not "
                           "here - choose the network type instead"]
            self._show()
            return
        answer = await self.app.push_screen_wait(ChoiceScreen(
            f"Measure now? This sends {what}, for at most {int(timing.BUDGET)} seconds.",
            [("measure", "measure now"), ("no", "no - send nothing")]))
        if answer != "measure":
            self._notes = ["nothing was sent"]
            self._show()
            return
        self._measuring = threading.Event()
        self._notes = ["measuring … Esc cancels"]
        self._show()
        rtts = await self._measure(pairs, hosts, self._measuring)
        cancelled = self._measuring.is_set()
        self._measuring = None
        self.facts = replace(self.facts, measured=tuple(rtts))
        if cancelled:
            self._notes = ["measurement cancelled - nothing measured"]
        elif not rtts:
            self._notes = ["no host answered - defaults apply"]
        else:
            note = timing.derive(rtts, model.RELIABLE, len(self.facts.targets)).note
            self._notes = [note]
        self._take("measure")

    async def _measure(self, pairs, hosts, cancel: threading.Event) -> list[timing.Rtt]:
        import asyncio
        if pairs:
            return await asyncio.to_thread(timing.measure_connect, pairs, cancel)
        return await asyncio.to_thread(timing.measure_ping, self.program, hosts)
