import asyncio
import typing

import textual
import textual.app
import textual.screen
import textual.widgets

from .. import client
from . import grant_edit


class GrantListScreen(textual.screen.Screen[None]):
    BINDINGS: typing.ClassVar = [("escape", "app.pop_screen", "Back"), ("e", "edit_grant", "Edit")]

    def __init__(self, auth: client.HttpClient, grant_list: list, sub_title: str, role_id: int) -> None:
        super().__init__()
        self._auth = auth
        self._grant_list = grant_list
        self._sub_title = sub_title
        self._role_id = role_id

    def compose(self) -> textual.app.ComposeResult:
        yield textual.widgets.DataTable(cursor_type="row")
        yield textual.widgets.Footer()

    def on_mount(self) -> None:
        self.sub_title = self._sub_title
        table = self.query_one(textual.widgets.DataTable)
        table.add_columns("Type", "Filter", "Permissions")
        for grant in self._grant_list:
            grant_type, filter_str, perm_str = client.grant.to_text(grant)
            table.add_row(grant_type, filter_str, perm_str)

    @textual.work
    async def action_edit_grant(self) -> None:
        table = self.query_one(textual.widgets.DataTable)
        if not self._grant_list:
            return
        index = table.cursor_row
        updated_grant = await self.app.push_screen_wait(grant_edit.GrantEditScreen(self._auth, self._grant_list[index]))
        if updated_grant is None:
            print("updated is nonoe")
            return
        print("updated ok")
        print(updated_grant)
        self._grant_list[index] = updated_grant
        response = await asyncio.to_thread(
            self._auth.patch,
            f"{self._auth.directory.role}/{self._role_id}",
            json={"grant_list": self._grant_list},
        )
        print("patched")
        if response.status_code != 200:
            print(response.json())
            self.notify(response.json().get("title", "Failed to save grants"), severity="error")
            return
        table.clear(columns=False)
        for grant in self._grant_list:
            grant_type, filter_str, perm_str = client.grant.to_text(grant)
            table.add_row(grant_type, filter_str, perm_str)
        self.notify("Grants saved")
        print("saved")
