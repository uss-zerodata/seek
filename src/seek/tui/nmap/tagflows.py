"""Tagging from the viewer: `t` tags the marks (or the row) and opens the tag
editor, `T` opens the rule builder on them (or on the rows in view), `R` reads
the tag files again.

Everything about one tag - name, description, issues, rules - is edited in one
place, the tag editor (`tageditor.py`); the rule builder hands its rule to it.

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
from seek.nmap.tagedit import RuleItem, TagEdit
from seek.tui.menu import ChoiceScreen, PromptScreen
from seek.tui.nmap.rulebench import RuleBenchScreen
from seek.tui.nmap.tageditor import TagEditScreen

NEW = "\x00new"
EDIT = "\x00edit"
EDIT_ONE = "\x00edit:"
COPY = "\x00copy"
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
        loaded = await asyncio.to_thread(self.session._tag_files_now)
        keys = {r.identity for r in records}
        manual: dict[str, int] = {}
        for entry in loaded.all_entries:
            if entry.subject in keys:
                manual[entry.tag] = manual.get(entry.tag, 0) + 1
        names = sorted(set(loaded.tags) | set(manual)
                       | {e.tag for e in loaded.all_entries})
        n = len(records)
        # The tags the selection carries, first: the usual reason to press `t` on
        # a tagged row is to look at or change one of them.
        carried = await asyncio.to_thread(self.session.tags_of, records) if records else []
        choices = [(EDIT_ONE + name, f"edit {name}…  (on {'this' if n == 1 else 'these'})")
                   for name in carried]
        if records:
            for name in names:
                have = manual.get(name, 0)
                verb = "remove" if have == n else "add"
                choices.append((name, f"{verb:<7}{name:<26}{have}/{n} carry it"))
            choices.append((NEW, "add a new tag…"))
        choices += [(EDIT, "edit a tag: name, description, issues, rules…"),
                    (COPY, "copy a tag to the global file…")]
        prompt = (f"Tag {n} {'record' if n == 1 else 'records'}:" if records
                  else "Tags:")
        picked = await self.push_screen_wait(ChoiceScreen(prompt, choices))
        if picked is None:
            return
        if picked.startswith(EDIT_ONE):
            await self._edit_tag(picked[len(EDIT_ONE):])
            return
        if picked == EDIT:
            name = await self._pick_tag(names, "Edit which tag?", [(NEW, "a new tag…")])
            if name is not None:
                await self._edit_tag(None if name == NEW else name)
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

    # --- the tag editor --------------------------------------------------------------

    async def _edit_tag(self, name: str | None, edit: TagEdit | None = None) -> None:
        """The tag editor, until it is saved or left. A change that cannot be
        saved opens it again with the reason and everything typed."""
        if edit is None:
            edit = await asyncio.to_thread(self.session.tag_edit, name)
        error = ""
        while True:
            got = await self.push_screen_wait(TagEditScreen(edit, self._open_rule, error))
            if got is None:
                return
            edit = got
            try:
                change = self.session.plan_tag_edit(edit)
            except ValueError as exc:
                error = str(exc)
                continue
            if change.overwrites:
                files = ", ".join(str(p) for p in change.overwrites)
                answer = await self.push_screen_wait(ChoiceScreen(
                    f"This rewrites {files} in seek's layout - its comments and order are "
                    "lost. Save anyway?",
                    [("no", "no, back to the editor"), ("yes", "yes, rewrite it")]))
                if answer != "yes":
                    error = ""
                    continue
            result = await self.session.apply_tag_change(change, origin="tui")
            self._tag_saved(result, change.summary)
            if result.ok:
                return
            error = "; ".join(result.errors)
            if "changed on disk" in error:
                return                     # the editor's rules are stale: start again

    async def _open_rule(self, edit: TagEdit, item: RuleItem) -> RuleItem | None:
        """A rule of the editor in the builder; the rule as saved there, or None."""
        tag = edit.original or edit.name
        rule = (item.origin if item.origin is not None and not item.changed
                else tr._native_rule(tag, item.raw, item.where, None, 1))
        opened = await asyncio.to_thread(self.session.open_rule, rule)
        if isinstance(opened, str):
            self.notify(opened, severity="warning", timeout=10)
            return None
        builder, draft = opened
        names = sorted(self.session._tag_files_now().tags)
        got = await self.push_screen_wait(RuleBenchScreen(builder, draft, names, rule=rule))
        if got is None:
            return None
        return RuleItem(tb.draft_rule(got.draft, got.name, got.grant), item.origin)

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
        names = sorted(self.session._tag_files_now().tags)
        got = await self.push_screen_wait(RuleBenchScreen(builder, builder.draft(), names))
        if got is None:
            return
        # The rule goes to the tag editor, where the tag gets its description and
        # issues; nothing is written before the editor is saved.
        edit = await asyncio.to_thread(self.session.tag_edit, got.tag)
        if edit.original is None:
            edit = TagEdit(None, got.tag, manual_hosts=edit.manual_hosts,
                           manual_services=edit.manual_services)
        item = RuleItem(tb.draft_rule(got.draft, got.name, got.grant))
        await self._edit_tag(got.tag, edit.with_rule(item))
