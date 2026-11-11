"""Tagging from the viewer: `t` tags the marks (or the row), `T` builds a rule
from them, `R` reads the tag files again.

Translation only (ARC-4): the dialogs collect choices, the session plans and
writes the change, the rule builder (`nmap/tagbuild.py`) proposes the facts.
File work and large builds run off the event loop.
"""

from __future__ import annotations

import asyncio

from textual import work

from seek.nmap import tagbuild as tb
from seek.nmap import tagrules as tr
from seek.nmap.export import Record
from seek.tui.menu import ChoiceScreen, MultiChoiceScreen, PromptScreen

NEW = "\x00new"
EDIT = "\x00edit"
COPY = "\x00copy"
DONE = "\x00done"
SAVE = "\x00save"
COMBINED = "\x00combined"


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

    @work(exclusive=True, group="modal")
    async def _build_rule_flow(self) -> None:
        records = self._tag_targets()
        if not records:
            self.notify("mark the hosts a rule should find, then press T", severity="warning")
            return
        builder = await asyncio.to_thread(self.session.rule_builder, records)
        shared = await asyncio.to_thread(tb.shared, builder)
        for note in shared.notes:
            self.notify(note, severity="warning", timeout=8)
        offered = list(shared.facts) + list(shared.partial)
        if not offered:
            return
        facts = {str(k): p.fact for k, p in enumerate(offered)}
        picked = await self.push_screen_wait(MultiChoiceScreen(
            f"What {len(shared.selected)} selected host(s) share - "
            "the number is how many others do too:",
            [(str(k), f"{p.fact.label}  ({p.others} others)") for k, p in enumerate(offered)],
            confirm_label="Next"))
        if not picked:
            return
        positive = [facts[k] for k in picked]
        ex = await asyncio.to_thread(tb.exclusions, builder, positive)
        negative: list[tb.Fact] = []
        if ex.unwanted:
            choices = []
            if ex.combination is not None:
                labels = " and ".join(f.label for f in ex.combination.facts)
                choices.append((COMBINED, f"not {labels}  (leaves {ex.combination.remaining})"))
            singles = {str(k): p for k, p in enumerate(ex.single)}
            for k, p in singles.items():
                assumed = f", assumed on {len(p.assumed_on)} selected" if p.assumed_on else ""
                choices.append((k, f"not {p.fact.label}  (excludes {p.excludes}/{ex.unwanted}"
                                   f"{assumed})"))
            chosen = await self.push_screen_wait(MultiChoiceScreen(
                f"These facts also match {ex.unwanted} unselected host(s). Exclude:",
                choices, confirm_label="Next"))
            if chosen is None:
                return
            for k in chosen:
                if k == COMBINED and ex.combination is not None:
                    negative += list(ex.combination.facts)
                elif k in singles:
                    negative.append(singles[k].fact)
        negative = list(dict.fromkeys(negative))
        shown = await asyncio.to_thread(tb.preview, builder, positive, negative)
        summary = (f"Matches {len(shown.matched)} host(s): {shown.selected} of "
                   f"{shown.of_selection} selected, {len(shown.assumed)} on an assumption.")
        if shown.confirm:
            summary += f"\nNote: {shown.confirm}."
        action = await self.push_screen_wait(ChoiceScreen(
            summary, [(SAVE, "save as a rule of a tag…")]))
        if action != SAVE:
            return
        name = await self._ask_tag_name("Save the rule to tag:")
        if name is None:
            return
        raw = tb.draft(f"built from {shown.of_selection} host(s)", positive, negative)
        try:
            change = self.session.plan_rule(name, raw)
        except ValueError as exc:
            self.notify(str(exc), severity="error")
            return
        self._tag_saved(await self.session.apply_tag_change(change, origin="tui"),
                        change.summary)
