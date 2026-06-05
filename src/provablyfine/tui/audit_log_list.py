import datetime
import typing

import provablyfine_client as pfc
import textual
import textual.app
import textual.widgets

from . import base, header


class AuditLogListScreen(base.Screen):
    BINDINGS: typing.ClassVar = [("escape", "app.pop_screen", "Back")]

    def __init__(self, auth: pfc.AsyncSessionClient) -> None:
        super().__init__()
        self._auth = auth
        self._entries: list[pfc.schemas.AuditLogEntry] = []

    def compose(self) -> textual.app.ComposeResult:
        yield header.AppHeader()
        yield textual.widgets.DataTable(cursor_type="row")
        yield textual.widgets.Footer(compact=True, show_command_palette=False)

    async def on_mount(self) -> None:
        table = self.query_one(textual.widgets.DataTable[str])
        table.add_columns("Time", "Level", "Type", "By")
        response = await self._auth.list_audit_log()
        self._entries = response.entries
        self._populate_table(table)

    @textual.work
    async def on_screen_resume(self) -> None:
        response = await self._auth.list_audit_log()
        self._entries = response.entries
        self._populate_table(self.query_one(textual.widgets.DataTable[str]))

    def _populate_table(self, table: textual.widgets.DataTable[str]) -> None:
        table.clear(columns=False)
        for entry in self._entries:
            level = "WARN" if entry.level == 2 else "INFO"
            at = datetime.datetime.fromtimestamp(entry.at).strftime("%Y-%m-%d %H:%M:%S")
            table.add_row(at, level, entry.type, entry.by_identity_id or "")
