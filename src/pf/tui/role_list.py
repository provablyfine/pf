import asyncio
import typing

import textual.app
import textual.screen
import textual.widgets

from .. import client
from . import grant_list


def _ellipsize(s: str, max_len: int) -> str:
    if len(s) <= max_len:
        return s
    return s[:max_len] + "…"


class RoleListScreen(textual.screen.Screen[None]):
    TITLE = "Provably Fine"
    BINDINGS: typing.ClassVar = [("g", "view_grants", "View grants")]

    def __init__(self, auth: client.HttpClient) -> None:
        super().__init__()
        self._auth = auth
        self._roles: list = []

    async def _list_roles(self) -> list:
        response = await asyncio.to_thread(self._auth.get, self._auth.directory.role)
        if response.status_code != 200:
            self.notify(response.json().get("title", "Failed to read list of roles"), severity="error")
            return []
        return response.json()["roles"]

    def compose(self) -> textual.app.ComposeResult:
        yield textual.widgets.DataTable(cursor_type="row")
        yield textual.widgets.Footer()

    async def on_mount(self) -> None:
        table = self.query_one(textual.widgets.DataTable)
        table.add_columns("Name", "Description", "Members", "Grants")
        self._roles = await self._list_roles()
        for role in self._roles:
            table.add_row(
                role["name"],
                _ellipsize(role["description"], 40),
                str(len(role["member_list"])),
                str(len(role["grant_list"])),
            )

    def action_view_grants(self) -> None:
        table = self.query_one(textual.widgets.DataTable)
        if not self._roles:
            return
        role = self._roles[table.cursor_row]
        self.app.push_screen(
            grant_list.GrantListScreen(self._auth, role["grant_list"], f"Roles > {role['name']} > Grants", role["id"])
        )
