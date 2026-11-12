"""Tagging from the viewer: `t` tags the marks (or the row), `T` opens the rule
builder on them (or on the rows in view), `R` reads the tag files again.

Translation only (ARC-4): the dialogs collect choices, the session plans and
writes the change, the rule builder (`nmap/tagbuild.py`) proposes the facts.
File work and large builds run off the event loop.
"""

from __future__ import annotations

import asyncio

from textual import work
from textual.widgets import Input

from seek.nmap import tagbuild as tb
from seek.nmap import tagrules as tr
from seek.nmap.export import Record
from seek.tui.menu import ChoiceScreen, PromptScreen
from seek.tui.nmap.rulebench import RuleBenchScreen

NEW = "\x00new"
EDIT = "\x00edit"
COPY = "\x00copy"
DONE = "\x00done"
RULES = "\x00rules"
VIEW = "\x00view"
ROW = "\x00row"
# The rows in view a rule is built from, at most.
VIEW_LIMIT = 2000


class TagFlows:
    """Mixed into `NmapApp`, which provides `session`, `_marked`, `_current_row`,
    `push_screen_wait`, `notify` and the row reload."""

    def _tag_targets(self) -> list[Record]:
        """The marks when there are any, the row under the cursor when not."""
        if self._marked:
            return list(self._marked.values())
        row = self._current_row()
        return list(row.records) if row is not None and row.records else []

    def _tag_saved(self, result, change_summary: str) -> None:
        if result.errors:
            for error in result.errors:
                self.notify(error, severity="error", timeout=8)
        elif result.saved:
            where = ", ".join(str(p) for p in result.saved)
            self.notify(f"{change_summary} · saved in {where}")
        else:
            self.notify("nothing to change")

    # --- t -------------------------------------------------------------------------

    def action_tag(self) -> None:
        self._tag_flow()

    @work(exclusive=True, group="modal")
    async def _tag_flow(self) -> None:
        records = self._tag_targets()
        if not records:
            self.notify("nothing to tag - select a row or mark some", severity="warning")
            return
        loaded = await asyncio.to_thread(self.session._tag_files_now)
        keys = {r.identity for r in records}
        manual: dict[str, int] = {}
        for entry in loaded.all_entries:
            if entry.subject in keys:
                manual[entry.tag] = manual.get(entry.tag, 0) + 1
        names = sorted(set(loaded.tags) | set(manual))
        n = len(records)
        choices = []
        for name in names:
            have = manual.get(name, 0)
            verb = "remove" if have == n else "add"
            choices.append((name, f"{verb:<7}{name:<26}{have}/{n} carry it"))
        choices += [(NEW, "add a new tag…"), (EDIT, "edit a tag's description and issues…"),
                    (RULES, "edit a tag's rules in the builder…"),
                    (COPY, "copy a tag to the global file…")]
        picked = await self.push_screen_wait(ChoiceScreen(
            f"Tag {n} {'record' if n == 1 else 'records'}:", choices))
        if picked is None:
            return
        if picked == EDIT:
            await self._edit_definition(names)
            return
        if picked == COPY:
            await self._copy_global(names)
            return
        if picked == RULES:
            await self._edit_rules(names)
            return
        add = True
        if picked == NEW:
            name = await self._ask_tag_name("New tag:")
            if name is None:
                return
        else:
            name, add = picked, manual.get(picked, 0) != n
        await self._apply_tag(records, name, add)

    async def _ask_tag_name(self, prompt: str, initial: str = "") -> str | None:
        """A tag name, asked again with the reason until it is one, or None."""
        while True:
            text = await self.push_screen_wait(PromptScreen(prompt, initial))
            if text is None or not text.strip():
                return None
            try:
                return tr.tag_name(text)
            except tr.RuleError as exc:
                prompt, initial = f"{exc}\nNew tag:", text

    async def _apply_tag(self, records, name: str, add: bool) -> None:
        try:
            change = self.session.plan_tag(records, name, add)
        except ValueError as exc:
            self.notify(str(exc), severity="error")
            return
        result = await self.session.apply_tag_change(change, origin="tui")
        self._tag_saved(result, change.summary)

    async def _pick_tag(self, names: list[str], prompt: str,
                        extra: list[tuple[str, str]] | None = None) -> str | None:
        choices = [(n, n) for n in names] + (extra or [])
        if not choices:
            self.notify("there are no tags yet", severity="warning")
            return None
        return await self.push_screen_wait(ChoiceScreen(prompt, choices))

    async def _copy_global(self, names: list[str]) -> None:
        name = await self._pick_tag(names, "Copy which tag to the global file?")
        if name is None:
            return
        try:
            change = self.session.plan_copy_global(name)
        except ValueError as exc:
            self.notify(str(exc), severity="error")
            return
        self._tag_saved(await self.session.apply_tag_change(change, origin="tui"),
                        change.summary)

    async def _edit_definition(self, names: list[str]) -> None:
        name = await self._pick_tag(names, "Edit which tag?", [(NEW, "a new tag…")])
        if name is None:
            return
        if name == NEW:
            name = await self._ask_tag_name("Tag:")
            if name is None:
                return
        current = (await asyncio.to_thread(self.session._tag_files_now)).tags.get(name)
        description = await self.push_screen_wait(PromptScreen(
            f"Description of {name}:", current.description if current else ""))
        if description is None:
            return
        issues = list(current.issues) if current else []
        while True:
            choices = [(str(k), f"remove  {i.severity.value:<9}{i.title}")
                       for k, i in enumerate(issues)]
            choices += [(NEW, "add an issue…"), (DONE, "save")]
            picked = await self.push_screen_wait(ChoiceScreen(
                f"Issues of {name}:", choices))
            if picked is None:
                return
            if picked == DONE:
                break
            if picked == NEW:
                issue = await self._ask_issue()
                if issue is not None:
                    issues.append(issue)
                continue
            issues.pop(int(picked))
        change = self.session.plan_definition(name, description.strip(), issues)
        self._tag_saved(await self.session.apply_tag_change(change, origin="tui"),
                        change.summary)

    async def _ask_issue(self) -> tr.Issue | None:
        title = await self.push_screen_wait(PromptScreen("Issue title:"))
        if not title or not title.strip():
            return None
        severity = await self.push_screen_wait(ChoiceScreen(
            "Severity:", [(s.value, s.value) for s in tr.Severity]))
        if severity is None:
            return None
        description = await self.push_screen_wait(PromptScreen("Description (optional):"))
        return tr.Issue(title.strip(), tr.Severity(severity), (description or "").strip())

    # --- R -------------------------------------------------------------------------

    def action_reload_tags(self) -> None:
        self._reload_tags_flow()

    @work(exclusive=True, group="tags")
    async def _reload_tags_flow(self) -> None:
        loaded = await self.session.reload_tags(origin="tui")
        errors = sum(1 for p in loaded.problems if p.level is tr.Level.ERROR)
        self.notify(f"tag rules reloaded: {len(loaded.files)} file(s), {len(loaded.tags)} "
                    f"tag(s)" + (f", {errors} problem(s)" if errors else ""),
                    severity="warning" if errors else "information")

    # --- T -------------------------------------------------------------------------

    def action_build_rule(self) -> None:
        self._build_rule_flow()

    async def _rule_targets(self) -> list[Record] | None:
        """The marks; with none and a filter on, the row or the rows in view."""
        if self._marked:
            return list(self._marked.values())
        row = self._current_row()
        here = list(row.records) if row is not None and row.records else []
        if self.query_one("#filter", Input).value.strip():
            view = self._visible_records(self._rows)[:VIEW_LIMIT]
            if len(view) > 1:
                picked = await self.push_screen_wait(ChoiceScreen(
                    "Build a rule from:", [(VIEW, f"the {len(view)} rows in view"),
                                           (ROW, "this row")]))
                if picked is None:
                    return None
                return view if picked == VIEW else here
        return here

    @work(exclusive=True, group="modal")
    async def _build_rule_flow(self) -> None:
        records = await self._rule_targets()
        if records is None:
            return
        if not records:
            self.notify("mark the hosts a rule should find, then press T", severity="warning")
            return
        builder = await asyncio.to_thread(self.session.rule_builder, records)
        await self._bench(builder, builder.draft())

    async def _bench(self, builder, draft, rule: tr.Rule | None = None) -> None:
        names = sorted(self.session._tag_files_now().tags)
        got = await self.push_screen_wait(RuleBenchScreen(builder, draft, names, rule=rule))
        if got is None:
            return
        raw = tb.draft_rule(got.draft, got.name, got.grant)
        try:
            change = (self.session.plan_rule_replace(rule, raw) if rule is not None
                      else self.session.plan_rule(got.tag, raw))
        except ValueError as exc:
            self.notify(str(exc), severity="error")
            return
        self._tag_saved(await self.session.apply_tag_change(change, origin="tui"),
                        change.summary)

    async def _edit_rules(self, names: list[str]) -> None:
        name = await self._pick_tag(names, "Edit the rules of which tag?")
        if name is None:
            return
        rules = self.session.rules_of(name)
        if not rules:
            self.notify(f"{name} has no rules - build one with T", severity="warning")
            return
        picked = await self.push_screen_wait(ChoiceScreen(
            f"Which rule of {name}?",
            [(str(k), f"{r.name}  ({r.source})") for k, r in enumerate(rules)]))
        if picked is None:
            return
        rule = rules[int(picked)]
        opened = await asyncio.to_thread(self.session.open_rule, rule)
        if isinstance(opened, str):
            self.notify(opened, severity="warning", timeout=10)
            return
        await self._bench(*opened, rule=rule)
