import typing

import textual
import textual.app
import textual.containers
import textual.screen
import textual.widgets

from . import async_client, header, role_view


def _ellipsize(s: str, max_len: int) -> str:
    if len(s) <= max_len:
        return s
    return s[:max_len] + "…"


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


class RoleListScreen(textual.screen.Screen[None]):
    TITLE = "Provably Fine"
    BINDINGS: typing.ClassVar = [
        ("enter", "view_role", "View"),
        ("a", "add_role", "Add"),
        ("d", "delete_role", "Delete"),
        ("escape", "app.pop_screen", "Back"),
    ]

    def __init__(self, auth: async_client.AsyncClient) -> None:
        super().__init__()
        self._auth = auth
        self._roles: list = []

    def compose(self) -> textual.app.ComposeResult:
        yield header.AppHeader()
        yield textual.widgets.DataTable(cursor_type="row")
        yield textual.widgets.Footer(compact=True, show_command_palette=False)

    async def on_mount(self) -> None:
        table = self.query_one(textual.widgets.DataTable)
        table.add_columns("Name", "Description", "Members", "Grants")
        self._roles = await self._auth.list_roles()
        self._populate_table(table)

    def _populate_table(self, table: textual.widgets.DataTable) -> None:
        table.clear(columns=False)
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

    @textual.work
    async def action_add_role(self) -> None:
        name = await self.app.push_screen_wait(_RoleNameScreen())
        if name is None:
            return
        response = await self._auth.post(self._auth.directory.role, json={"name": name})
        if response.status_code != 201:
            self.notify(response.json().get("title", "Failed to create role"), severity="error")
            return
        role = response.json()
        self._roles.append(role)
        table = self.query_one(textual.widgets.DataTable)
        self._populate_table(table)
        table.move_cursor(row=len(self._roles) - 1)
        self.app.push_screen(role_view.RoleViewScreen(self._auth, role))

    @textual.work
    async def action_delete_role(self) -> None:
        if not self._roles:
            return
        table = self.query_one(textual.widgets.DataTable)
        index = table.cursor_row
        role = self._roles[index]
        response = await self._auth.delete(f"{self._auth.directory.role}/{role['id']}")
        if response.status_code != 204:
            self.notify(response.json().get("title", "Failed to delete role"), severity="error")
            return
        self._roles.pop(index)
        self._populate_table(table)
        self.notify(f"Role '{role['name']}' deleted")
