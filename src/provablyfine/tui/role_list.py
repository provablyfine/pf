import typing

import provablyfine_client as pfc
import textual
import textual.app
import textual.containers
import textual.screen
import textual.widgets

from .. import client
from . import _utils, base, header, role_view


class _RoleNameScreen(textual.screen.ModalScreen[str | None]):
    DEFAULT_CSS = """
    _RoleNameScreen {
        align: center middle;
    }
    _RoleNameScreen > VerticalGroup {
        width: 40;
        height: auto;
        padding: 1 2;
        background: $surface;
        border: thick $primary;
    }
    """
    BINDINGS: typing.ClassVar = [("escape", "cancel", "Cancel")]

    def compose(self) -> textual.app.ComposeResult:
        with textual.containers.VerticalGroup() as container:
            container.border_title = "Add a role"
            yield textual.widgets.Input(placeholder="name", id="name", compact=True)

    def action_cancel(self) -> None:
        self.dismiss(None)

    @textual.on(textual.widgets.Input.Submitted)
    def _on_submit(self) -> None:
        name = self.query_one(textual.widgets.Input).value.strip()
        if not name:
            return
        self.dismiss(name)


class RoleListScreen(base.Screen):
    TITLE = "Provably Fine"
    BINDINGS: typing.ClassVar = [
        ("enter", "view_role", "View"),
        ("a", "add_role", "Add"),
        ("d", "delete_role", "Delete"),
        ("escape", "app.pop_screen", "Back"),
    ]

    def __init__(self, auth: client.aio.Client) -> None:
        super().__init__()
        self._auth = auth
        self._roles: list[pfc.schemas.Role] = []

    def compose(self) -> textual.app.ComposeResult:
        yield header.AppHeader()
        yield textual.widgets.DataTable(cursor_type="row")
        yield textual.widgets.Footer(compact=True, show_command_palette=False)

    async def on_mount(self) -> None:
        table = self.query_one(textual.widgets.DataTable[str])
        table.add_columns("Name", "Description", "Members", "Grants")
        self._roles = (await self._auth.list_roles()).roles
        self._populate_table(table)

    @textual.work
    async def on_screen_resume(self) -> None:
        self._roles = (await self._auth.list_roles()).roles
        self._populate_table(self.query_one(textual.widgets.DataTable[str]))

    def _populate_table(self, table: textual.widgets.DataTable[str]) -> None:
        table.clear(columns=False)
        for role in self._roles:
            table.add_row(
                role.name,
                _utils.ellipsize(role.description, 40),
                str(len(role.member_list)),
                str(len(role.grant_list)),
            )

    @textual.on(textual.widgets.DataTable.RowSelected)
    def _on_row_selected(self) -> None:
        self.action_view_role()

    def action_view_role(self) -> None:
        if not self._roles:
            return
        table = self.query_one(textual.widgets.DataTable[str])
        role = self._roles[table.cursor_row]
        self.app.push_screen(role_view.RoleViewScreen(self._auth, role))

    @textual.work
    async def action_add_role(self) -> None:
        name = await self.app.push_screen_wait(_RoleNameScreen())
        if name is None:
            return
        role = await self._auth.create_role(name, "")
        self._roles.append(role)
        table = self.query_one(textual.widgets.DataTable[str])
        self._populate_table(table)
        table.move_cursor(row=len(self._roles) - 1)
        self.app.push_screen(role_view.RoleViewScreen(self._auth, role))

    @textual.work
    async def action_delete_role(self) -> None:
        if not self._roles:
            return
        table = self.query_one(textual.widgets.DataTable[str])
        index = table.cursor_row
        role = self._roles[index]
        await self._auth.delete_role(role.id)
        self._roles.pop(index)
        self._populate_table(table)
        self.notify(f"Role '{role.name}' deleted")
