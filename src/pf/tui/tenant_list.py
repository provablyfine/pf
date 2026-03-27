import typing

import textual
import textual.app
import textual.containers
import textual.screen
import textual.widgets

from . import async_client, header


class _TenantCreateScreen(textual.screen.ModalScreen[dict | None]):
    DEFAULT_CSS = """
    _TenantCreateScreen {
        align: center middle;
    }
    _TenantCreateScreen > VerticalGroup {
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
            container.border_title = "Add a tenant"
            yield textual.widgets.Input(placeholder="name", id="name", compact=True)
            yield textual.widgets.Input(placeholder="display name", id="display_name", compact=True)

    def action_cancel(self) -> None:
        self.dismiss(None)

    @textual.on(textual.widgets.Input.Submitted)
    def _on_submit(self) -> None:
        name = self.query_one("#name", textual.widgets.Input).value.strip()
        display_name = self.query_one("#display_name", textual.widgets.Input).value.strip()
        if not name or not display_name:
            return
        self.dismiss({"name": name, "display_name": display_name})


class TenantListScreen(textual.screen.Screen[None]):
    BINDINGS: typing.ClassVar = [
        ("a", "add_tenant", "Add"),
        ("d", "delete_tenant", "Delete"),
        ("escape", "app.pop_screen", "Back"),
    ]

    def __init__(self, auth: async_client.AsyncClient) -> None:
        super().__init__()
        self._auth = auth
        self._tenants: list = []

    def compose(self) -> textual.app.ComposeResult:
        yield header.AppHeader()
        yield textual.widgets.DataTable(cursor_type="row")
        yield textual.widgets.Footer()

    async def on_mount(self) -> None:
        table = self.query_one(textual.widgets.DataTable)
        table.add_columns("Name", "Display Name", "Enabled")
        self._tenants = await self._auth.list_tenants()
        self._populate_table(table)

    def _populate_table(self, table: textual.widgets.DataTable) -> None:
        table.clear(columns=False)
        for tenant in self._tenants:
            table.add_row(
                tenant["name"],
                tenant["display_name"],
                "yes" if tenant["is_enabled"] else "no",
            )

    @textual.work
    async def action_add_tenant(self) -> None:
        data = await self.app.push_screen_wait(_TenantCreateScreen())
        if data is None:
            return
        response = await self._auth.post(self._auth.directory.tenant, json=data)
        if response.status_code not in (200, 201):
            self.notify(response.json().get("title", "Failed to create tenant"), severity="error")
            return
        self._tenants = await self._auth.list_tenants()
        table = self.query_one(textual.widgets.DataTable)
        self._populate_table(table)

    @textual.work
    async def action_delete_tenant(self) -> None:
        if not self._tenants:
            return
        table = self.query_one(textual.widgets.DataTable)
        index = table.cursor_row
        tenant = self._tenants[index]
        response = await self._auth.delete(f"{self._auth.directory.tenant}/{tenant['id']}")
        if response.status_code != 204:
            self.notify(response.json().get("title", "Failed to delete tenant"), severity="error")
            return
        self._tenants.pop(index)
        self._populate_table(table)
        self.notify(f"Tenant '{tenant['name']}' deleted")
