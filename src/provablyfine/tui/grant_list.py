from __future__ import annotations

import typing

import provablyfine_client as pfc
import textual
import textual.app
import textual.containers
import textual.screen
import textual.widgets

from .. import client
from . import base, grant_edit, header

GRANT_TYPES = ["identity", "tag", "role", "boundary", "tenant", "ssh-shell", "ssh-port-forwarding", "ssh-command"]


class GrantTypeScreen(textual.screen.ModalScreen[str | None]):
    DEFAULT_CSS = """
    GrantTypeScreen {
        align: center middle;
    }
    GrantTypeScreen > VerticalGroup {
        width: auto;
        height: auto;
        padding: 1 2;
        background: $surface;
        border: thick $primary;
    }
    #popup ListView {
        height: auto;
        width: auto;
        padding: 1 2;
    }
    #popup ListView ListItem{
        height: auto;
        width: auto;
    }
    """
    BINDINGS: typing.ClassVar = [
        ("escape", "cancel", "Cancel"),
        ("up", "app.focus_previous", ""),
        ("down", "app.focus_next", ""),
    ]

    def compose(self) -> textual.app.ComposeResult:
        with textual.containers.VerticalGroup(id="popup"):
            yield textual.widgets.ListView(
                *[
                    textual.widgets.ListItem(textual.widgets.Label(grant_type), id=grant_type)
                    for grant_type in GRANT_TYPES
                ]
            )

    def on_mount(self) -> None:
        self.query_one("#popup").border_title = "Add grant"

    def action_cancel(self) -> None:
        self.dismiss(None)

    @textual.on(textual.widgets.ListView.Selected)
    def _on_pressed(self, event: textual.widgets.ListView.Selected) -> None:
        self.dismiss(event.item.id)


class GrantListScreen(base.Screen):
    BINDINGS: typing.ClassVar = [
        ("escape", "app.pop_screen", "Back"),
        ("a", "add_grant", "Add"),
        ("d", "delete_grant", "Delete"),
        ("e", "edit_grant", "Edit"),
    ]

    class _StrDataTable(textual.widgets.DataTable[str]):
        pass

    def __init__(
        self,
        auth: client.aio.Client,
        grant_list: list[pfc.schemas.Grant],
        sub_title: str,
        role_id: int,
    ) -> None:
        super().__init__()
        self._auth = auth
        self._grant_list = grant_list
        self._sub_title = sub_title
        self._role_id = role_id

    def compose(self) -> textual.app.ComposeResult:
        yield header.AppHeader()
        yield self._StrDataTable(cursor_type="row")
        yield textual.widgets.Footer(compact=True, show_command_palette=False)

    def on_mount(self) -> None:
        self.sub_title = self._sub_title
        table = self.query_one(self._StrDataTable)
        table.add_columns("Type", "Filter", "Permissions")
        self._populate_table(table)

    def _populate_table(self, table: GrantListScreen._StrDataTable) -> None:
        table.clear(columns=False)
        for grant in self._grant_list:
            grant_text = grant.to_text()
            table.add_row(grant_text.type, grant_text.filter, grant_text.permission)

    async def _save_grants(self) -> bool:
        await self._auth.update_role(
            self._role_id,
            grant_list=self._grant_list,
        )
        return True

    @textual.work
    async def action_add_grant(self) -> None:
        grant_type = await self.app.push_screen_wait(GrantTypeScreen())
        if grant_type is None:
            return
        new_grant = grant_edit.new_grant(grant_type)
        updated_grant = await self.app.push_screen_wait(grant_edit.GrantEditScreen(self._auth, new_grant))
        if updated_grant is None:
            return
        self._grant_list.append(updated_grant)
        if not await self._save_grants():
            self._grant_list.pop()
            return
        self._populate_table(self.query_one(self._StrDataTable))
        self.notify("Grant added")

    @textual.work
    async def action_delete_grant(self) -> None:
        table = self.query_one(self._StrDataTable)
        if not self._grant_list:
            return
        index = table.cursor_row
        deleted = self._grant_list.pop(index)
        if not await self._save_grants():
            self._grant_list.insert(index, deleted)
            return
        self._populate_table(table)
        self.notify("Grant deleted")

    @textual.work
    async def action_edit_grant(self) -> None:
        table = self.query_one(self._StrDataTable)
        if not self._grant_list:
            return
        index = table.cursor_row
        updated_grant = await self.app.push_screen_wait(grant_edit.GrantEditScreen(self._auth, self._grant_list[index]))
        if updated_grant is None:
            return
        self._grant_list[index] = updated_grant
        if not await self._save_grants():
            return
        self._populate_table(table)
        self.notify("Grants saved")
