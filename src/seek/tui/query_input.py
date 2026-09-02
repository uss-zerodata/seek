"""The query input.

It stays focused for the whole session, so printable keys always edit the
query. The one special case: a lone ``?`` on an empty query opens help (once
you have typed anything, ``?`` is a literal search character). ``F1`` opens
help unconditionally via an app binding.
"""

from __future__ import annotations

from textual.message import Message
from textual.widgets import Input


class QueryInput(Input):
    class HelpRequested(Message):
        pass

    async def _on_key(self, event) -> None:  # noqa: ANN001 - Textual event
        if event.character == "?" and not self.value:
            event.stop()
            event.prevent_default()
            self.post_message(self.HelpRequested())
            return
        await super()._on_key(event)
