import asyncio

import textual.app
import textual.screen
import textual.widgets

from .. import client


def _ellipsize(s: str, max_len: int) -> str:
    if len(s) <= max_len:
        return s
    return s[:max_len] + "…"


class RoleListScreen(textual.screen.Screen[None]):
    TITLE = "Provably Fine"

    def __init__(self, auth: client.HttpClient) -> None:
        super().__init__()
        self._auth = auth

    async def _list_roles(self) -> list:
        response = await asyncio.to_thread(self._auth.get, self._auth.directory.role)
        if response.status_code != 200:
            self.notify(response.json().get("title", "Failed to read list of roles"), severity="error")
            return []
        return response.json()["roles"]

    def compose(self) -> textual.app.ComposeResult:
        yield textual.widgets.DataTable()

    async def on_mount(self) -> None:
        table = self.query_one(textual.widgets.DataTable)
        table.add_columns("Name", "Description", "Members", "Grants")
        roles = await self._list_roles()
        for role in roles:
            table.add_row(
                role["name"],
                _ellipsize(role["description"], 40),
                str(len(role["member_list"])),
                str(len(role["grant_list"])),
            )
