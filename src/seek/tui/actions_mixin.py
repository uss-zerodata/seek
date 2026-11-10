"""Result-action handling for SeekApp.

Opening a target keeps the session: an editor gets the terminal while the app
is suspended and the app carries on when it exits; the default application and
``code`` are windows of their own and are started detached. Copy and
file/clipboard export run in-process.

Actions that end the session - printing to stdout, ``cd`` - must run *after*
Textual has restored the terminal. Those set ``self.exit_request`` and quit;
:func:`perform_exit_request` runs them once ``app.run()`` has returned.
"""

from __future__ import annotations

import sys

from textual import work
from textual.app import SuspendNotSupported

from seek import actions
from seek.actions import ActionError, ExitRequest
from seek.models import MatchKind, Result
from seek.shell import write_cd_target
from seek.tui.keyhints import pretty_key
from seek.tui.menu import ActionMenuScreen, ChoiceScreen, ConfirmScreen, PromptScreen

_MENU_ITEMS = [
    ("open_default", "Open in default app", "open_default"),
    ("open_editor", "Open in editor", "open_editor"),
    ("open_code", "Open in code", "open_code"),
    ("copy", "Copy path(s)", "copy"),
    ("export", "Export selection…", "export"),
    ("goto_dir", "Go to directory (cd)", "goto_dir"),
    ("reroot", "Re-root search here", "reroot"),
    ("refresh", "Refresh (re-walk)", "refresh"),
    ("toggle_file", "Toggle filename mode", "toggle_file"),
    ("toggle_dir", "Toggle directory mode", "toggle_dir"),
    ("toggle_content", "Toggle content mode", "toggle_content"),
    ("toggle_format", "Toggle content formatting", "toggle_format"),
    ("help", "Help", "help"),
]


class ActionsMixin:
    config: object
    exit_request: ExitRequest | None

    def commit_query_history(self) -> None:  # provided by SeekApp
        ...

    def after_external_edit(self) -> None:  # provided by SeekApp
        ...

    # --- keybound entry points (workers so they can await modal screens) -----

    @work(exclusive=True, group="modal")
    async def action_seek_action_menu(self) -> None:
        keys = self.config.keys  # type: ignore[attr-defined]
        # Shown the same way the hint bar and the help overlay show them: the
        # menu used to print the raw Textual spec (`ctrl+o`) beside a `^O` hint.
        items = [
            (aid, label, pretty_key(keys.get(kb, kb))) for aid, label, kb in _MENU_ITEMS
        ]
        choice = await self.push_screen_wait(ActionMenuScreen(items))
        if choice:
            await self._dispatch_menu(choice)

    @work(exclusive=True, group="modal")
    async def action_seek_open_default(self) -> None:
        await self._exec_action("default")

    @work(exclusive=True, group="modal")
    async def action_seek_open_editor(self) -> None:
        await self._exec_action("editor")

    @work(exclusive=True, group="modal")
    async def action_seek_open_code(self) -> None:
        await self._exec_action("code")

    @work(exclusive=True, group="modal")
    async def action_seek_copy(self) -> None:
        await self._do_copy()

    @work(exclusive=True, group="modal")
    async def action_seek_export(self) -> None:
        await self._do_export()

    def action_seek_goto_dir(self) -> None:
        self._do_goto_dir()


    # --- menu dispatch -----------------------------------------------------

    async def _dispatch_menu(self, choice: str) -> None:
        if choice == "open_default":
            await self._exec_action("default")
        elif choice == "open_editor":
            await self._exec_action("editor")
        elif choice == "open_code":
            await self._exec_action("code")
        elif choice == "copy":
            await self._do_copy()
        elif choice == "export":
            await self._do_export()
        elif choice == "goto_dir":
            self._do_goto_dir()
        elif choice == "help":
            self.action_seek_help()
        else:  # reroot, refresh, toggle_*
            getattr(self, f"action_seek_{choice}")()

    # --- implementations -------------------------------------------------

    async def _do_copy(self) -> None:
        targets = await self._targets()
        if not targets:
            return
        text = actions.format_lines(targets, self.config)  # type: ignore[arg-type]
        try:
            actions.copy_to_clipboard(text)
            self.notify(f"Copied {len(targets)} path(s)")
        except ActionError as exc:
            self.notify(str(exc), severity="error")

    async def _do_export(self) -> None:
        targets = await self._targets()
        if not targets:
            return
        dest = await self.push_screen_wait(
            ChoiceScreen(
                "Export selection to:",
                [("stdout", "stdout (exit)"), ("clipboard", "clipboard"), ("file", "file")],
            )
        )
        if dest is None:
            return
        text = actions.format_lines(targets, self.config)  # type: ignore[arg-type]
        if dest == "clipboard":
            try:
                actions.copy_to_clipboard(text)
                self.notify("Exported to clipboard")
            except ActionError as exc:
                self.notify(str(exc), severity="error")
        elif dest == "file":
            path = await self.push_screen_wait(PromptScreen("Write to file:"))
            if not path:
                return
            try:
                actions.write_new(path, text)
                self.notify(f"Wrote {len(targets)} path(s) to {path}")
            except (OSError, ActionError) as exc:
                self.notify(f"write failed: {exc}", severity="error")
        else:  # stdout
            self.exit_request = ExitRequest(kind="print", text=text)
            self.exit(0)

    def _do_goto_dir(self) -> None:
        self.commit_query_history()
        cur = self._current_result()
        if cur is None:
            self.notify("Nothing selected")
            return
        # A directory result -> that directory; a file result -> its parent.
        target = cur.path if cur.kind is MatchKind.DIRNAME else cur.path.parent
        self.exit_request = ExitRequest(kind="cd", path=target)
        self.exit(0)

    async def _exec_action(self, which: str) -> None:
        targets = await self._targets()
        if not targets:
            return
        try:
            if which == "editor":
                argv = actions.editor_argv(self.config, targets)  # type: ignore[arg-type]
                self._run_in_terminal(argv)
                return
            if which == "default":
                # One opener process per file (openers detach immediately).
                argvs = [actions.opener_argv(t.path) for t in targets]
            else:
                argvs = [actions.code_argv(targets)]
            for argv in argvs:
                actions.spawn_detached(argv)
        except ActionError as exc:
            self.notify(str(exc), severity="error")
            return
        self.notify(f"Opened {len(targets)} path(s)")

    def _run_in_terminal(self, argv: list[str]) -> None:
        """Lend the terminal to ``argv`` and take it back when it exits."""
        actions.resolve_program(argv)  # a missing editor is reported, not flashed
        try:
            with self.suspend():  # type: ignore[attr-defined]
                actions.run_foreground(argv)
        except SuspendNotSupported:
            # No way to step aside on this driver: hand over for good instead.
            self.exit_request = ExitRequest(kind="exec", argv=argv)
            self.exit(0)  # type: ignore[attr-defined]
            return
        self.after_external_edit()

    # --- shared plumbing ------------------------------------------------

    def _current_result(self) -> Result | None:
        return self._active_list().current()  # type: ignore[attr-defined]

    def _selected_results(self) -> list[Result]:
        return self._active_list().selected_results()  # type: ignore[attr-defined]

    async def _targets(self) -> list[Result]:
        self.commit_query_history()  # acting on a result means the query was meant
        selection = self._selected_results()
        highlighted = self._current_result()
        resolved = actions.resolve_targets(selection, highlighted)
        if not resolved:
            self.notify("Nothing selected")
            return []
        if len(selection) > 1:
            answer = await self.push_screen_wait(ConfirmScreen(len(selection)))
            if answer == "cancel":
                return []
            if answer == "one":
                return [highlighted] if highlighted else []
        return resolved


def perform_exit_request(req: ExitRequest) -> int:
    """Run a deferred action after the Textual app has torn down."""
    if req.kind == "exec" and req.argv:
        try:
            actions.perform_exec(req.argv)  # replaces the process on POSIX
        except ActionError as exc:
            print(f"seek: {exc}", file=sys.stderr)
            return 1
        return 0
    if req.kind == "print" and req.text is not None:
        print(req.text)
        return 0
    if req.kind == "cd" and req.path is not None:
        if not write_cd_target(req.path):
            print(str(req.path))
        return 0
    return req.status
