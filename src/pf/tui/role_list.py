import typing

import textual
import textual.app
import textual.screen
import textual.widgets

from . import async_client, header, role_view


def _ellipsize(s: str, max_len: int) -> str:
    if len(s) <= max_len:
        return s
    return s[:max_len] + "…"


class RoleListScreen(textual.screen.Screen[None]):
    TITLE = "Provably Fine"
    BINDINGS: typing.ClassVar = [
        ("enter", "view_role", "View"),
    ]

    def __init__(self, auth: async_client.AsyncClient) -> None:
        super().__init__()
        self._auth = auth
        self._roles: list = []

    def compose(self) -> textual.app.ComposeResult:
        yield header.AppHeader()
        yield textual.widgets.DataTable(cursor_type="row")
        yield textual.widgets.Footer()

    async def on_mount(self) -> None:
        table = self.query_one(textual.widgets.DataTable)
        table.add_columns("Name", "Description", "Members", "Grants")
        self._roles = await self._auth.list_roles()
        for role in self._roles:
            table.add_row(
                role["name"],
                _ellipsize(role["description"], 40),
                str(len(role["member_list"])),
                str(len(role["grant_list"])),
            )

    @textual.on(textual.widgets.DataTable.RowSelected)
    def _on_row_selected(self) -> None:
        self.action_view_role()

    def action_view_role(self) -> None:
        if not self._roles:
            return
        table = self.query_one(textual.widgets.DataTable)
        role = self._roles[table.cursor_row]
        self.app.push_screen(role_view.RoleViewScreen(self._auth, role))
