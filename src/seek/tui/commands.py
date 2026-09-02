"""Every search-session action, exposed through the command palette.

The scan viewer has had this since it moved to bare keys; a search session needs
it for the same reason. Its actions are on modifiers because the query box keeps
focus, and a modifier combination is exactly the kind of thing you forget. The
palette lists them by name, so nothing is reachable only by knowing a keystroke.

`Ctrl+P` opens it in both modes. It used to be "go to directory" here and the
palette there - the same key meaning two different things across the app's two
halves. Going to a directory moved to `Alt+C`, which is what `fzf` binds the
same action to.
"""

from __future__ import annotations

from collections.abc import Callable

from textual.command import DiscoveryHit, Hit, Hits, Provider

# (title, subtitle, method name on the app, optional argument)
_STATIC: list[tuple[str, str, str, object]] = [
    ("Open in default app", "Hand the result to the OS opener",
     "action_seek_open_default", None),
    ("Open in editor", "Open at the matching line in your editor",
     "action_seek_open_editor", None),
    ("Open in code", "Open at the matching line in VS Code",
     "action_seek_open_code", None),
    ("Copy paths", "Copy the selected path(s) to the clipboard",
     "action_seek_copy", None),
    ("Export selection", "Send the list to stdout, the clipboard or a file",
     "action_seek_export", None),
    ("Go to directory", "cd there on exit; needs the shell wrapper",
     "action_seek_goto_dir", None),
    ("Open detail view", "Read the whole file, matches highlighted",
     "action_seek_detail", None),
    ("Mark or unmark the row", "Build a selection to act on together",
     "action_seek_mark", None),
    ("Clear all marks", "Drop the selection", "action_seek_clear_marks", None),
    ("Toggle filename matching", "Match against file names",
     "action_seek_toggle_file", None),
    ("Toggle directory matching", "Match against directory names",
     "action_seek_toggle_dir", None),
    ("Toggle content matching", "Match against the text inside files",
     "action_seek_toggle_content", None),
    ("Toggle content formatting", "Re-indent minified files before indexing",
     "action_seek_toggle_format", None),
    ("Re-root here", "Search from the highlighted directory",
     "action_seek_reroot", None),
    ("Back one level", "Pop the breadcrumb", "action_seek_breadcrumb_pop", None),
    ("Refresh", "Re-read the filesystem and drop cached contents",
     "action_seek_refresh", None),
    ("Previous query", "Recall the query before this one",
     "action_seek_history_prev", None),
    ("Next query", "Recall the query after this one",
     "action_seek_history_next", None),
    ("Action menu", "The short list of actions on a result",
     "action_seek_action_menu", None),
    ("Help", "The full key and query-syntax reference", "action_seek_help", None),
]


def _bind(app, method: str, argument: object) -> Callable[[], None]:
    target = getattr(app, method)
    if argument is None:
        return lambda: target()
    return lambda: target(argument)


def _commands(app) -> list[tuple[str, str, Callable[[], None]]]:
    keys = getattr(app, "config", None)
    keys = getattr(keys, "keys", {}) or {}
    from seek.tui.keyhints import pretty_key

    out = []
    for title, subtitle, method, argument in _STATIC:
        action = method.removeprefix("action_seek_")
        spec = keys.get(action)
        # Name the key alongside the description, as the viewer's palette does.
        help_text = f"{subtitle} ({pretty_key(spec)})" if spec else subtitle
        out.append((title, help_text, _bind(app, method, argument)))
    return out


class SeekCommands(Provider):
    """Makes every search-session action reachable by name."""

    async def discover(self) -> Hits:
        for title, subtitle, run in _commands(self.app):
            yield DiscoveryHit(title, run, help=subtitle)

    async def search(self, query: str) -> Hits:
        matcher = self.matcher(query)
        for title, subtitle, run in _commands(self.app):
            score = matcher.match(title)
            if score > 0:
                yield Hit(score, matcher.highlight(title), run, help=subtitle)
