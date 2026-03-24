import typing

import textual.app
import textual.screen
import textual.widgets

from .. import client
from . import grant_edit


class GrantListScreen(textual.screen.Screen[None]):
    BINDINGS: typing.ClassVar = [("escape", "pop_screen", "Back"), ("e", "edit_grant", "Edit")]

    def __init__(self, auth: client.HttpClient, grant_list: list, sub_title: str) -> None:
        super().__init__()
        self._auth = auth
        self._grant_list = grant_list
        self._sub_title = sub_title

    def compose(self) -> textual.app.ComposeResult:
        yield textual.widgets.DataTable()
        yield textual.widgets.Footer()

    def on_mount(self) -> None:
        self.sub_title = self._sub_title
        table = self.query_one(textual.widgets.DataTable)
        table.add_columns("Type", "Filter", "Permissions")
        for grant in self._grant_list:
            grant_type, filter_str, perm_str = client.grant.to_text(grant)
            table.add_row(grant_type, filter_str, perm_str)

    def action_edit_grant(self) -> None:
        table = self.query_one(textual.widgets.DataTable)
        if not self._grant_list:
            return
        grant = self._grant_list[table.cursor_row]
        self.app.push_screen(grant_edit.GrantEditScreen(self._auth, grant))
