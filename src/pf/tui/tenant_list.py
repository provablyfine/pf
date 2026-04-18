import typing

import textual
import textual.app
import textual.containers
import textual.screen
import textual.widgets

from .. import client
from . import header


class _TenantCreateScreen(textual.screen.ModalScreen[dict[str, str] | None]):
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
    class _StrDataTable(textual.widgets.DataTable[str]):
        pass

    BINDINGS: typing.ClassVar = [
        ("a", "add_tenant", "Add"),
        ("d", "delete_tenant", "Delete"),
        ("escape", "app.pop_screen", "Back"),
    ]

    def __init__(self, auth: client.aio.Client) -> None:
        super().__init__()
        self._auth = auth
        self._tenants: list[client.schemas.Tenant] = []

    def compose(self) -> textual.app.ComposeResult:
        yield header.AppHeader()
        yield self._StrDataTable(cursor_type="row")
        yield textual.widgets.Footer(compact=True, show_command_palette=False)

    async def on_mount(self) -> None:
        table = self.query_one(self._StrDataTable)
        table.add_columns("Name", "Display Name", "Enabled")
        self._tenants = (await self._auth.list_tenants()).tenants
        self._populate_table(table)

    def _populate_table(self, table: "TenantListScreen._StrDataTable") -> None:
        table.clear(columns=False)
        for tenant in self._tenants:
            table.add_row(
                tenant.name,
                tenant.display_name,
                "yes" if tenant.is_enabled else "no",
            )

    @textual.work
    async def action_add_tenant(self) -> None:
        data = await self.app.push_screen_wait(_TenantCreateScreen())  # pyright: ignore[reportUnknownMemberType]
        if data is None:
            return
        tenant = await self._auth.create_tenant(data["name"], data["display_name"])
        self._tenants.append(tenant)
        table = self.query_one(self._StrDataTable)
        self._populate_table(table)

    @textual.work
    async def action_delete_tenant(self) -> None:
        if not self._tenants:
            return
        table = self.query_one(self._StrDataTable)
        index = table.cursor_row
        tenant = self._tenants[index]
        await self._auth.delete_tenant(tenant.id)
        self._tenants.pop(index)
        self._populate_table(table)
        self.notify(f"Tenant '{tenant.name}' deleted")
