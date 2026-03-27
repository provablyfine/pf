import typing

import textual
import textual.app
import textual.containers
import textual.screen
import textual.widgets

from . import async_client, header


class _IdentityCreateScreen(textual.screen.ModalScreen[str | None]):
    DEFAULT_CSS = """
    _IdentityCreateScreen {
        align: center middle;
    }
    _IdentityCreateScreen > VerticalGroup {
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
            container.border_title = "Add an identity"
            yield textual.widgets.Input(placeholder="name", id="name", compact=True)

    def action_cancel(self) -> None:
        self.dismiss(None)

    @textual.on(textual.widgets.Input.Submitted)
    def _on_submit(self) -> None:
        name = self.query_one("#name", textual.widgets.Input).value.strip()
        if not name:
            return
        self.dismiss(name)


class IdentityListScreen(textual.screen.Screen[None]):
    BINDINGS: typing.ClassVar = [
        ("a", "add_identity", "Add"),
        ("d", "delete_identity", "Delete"),
        ("escape", "app.pop_screen", "Back"),
    ]

    def __init__(self, auth: async_client.AsyncClient) -> None:
        super().__init__()
        self._auth = auth
        self._identities: list = []

    def compose(self) -> textual.app.ComposeResult:
        yield header.AppHeader()
        yield textual.widgets.DataTable(cursor_type="row")
        yield textual.widgets.Footer()

    async def on_mount(self) -> None:
        table = self.query_one(textual.widgets.DataTable)
        table.add_columns("Name", "Tags", "Boundaries")
        self._identities = await self._auth.list_identities()
        self._populate_table(table)

    def _populate_table(self, table: textual.widgets.DataTable) -> None:
        table.clear(columns=False)
        for identity in self._identities:
            table.add_row(
                identity["name"],
                str(len(identity["tags"])),
                str(len(identity["boundaries"])),
            )

    @textual.work
    async def action_add_identity(self) -> None:
        name = await self.app.push_screen_wait(_IdentityCreateScreen())
        if name is None:
            return
        response = await self._auth.post(
            self._auth.directory.identity,
            json={
                "name": name,
                "boundary_id_list": [],
                "boundary_name_list": [],
                "tag_id_list": [],
                "tag_name_value_list": [],
            },
        )
        if response.status_code != 201:
            self.notify(response.json().get("title", "Failed to create identity"), severity="error")
            return
        self._identities = await self._auth.list_identities()
        table = self.query_one(textual.widgets.DataTable)
        self._populate_table(table)

    @textual.work
    async def action_delete_identity(self) -> None:
        if not self._identities:
            return
        table = self.query_one(textual.widgets.DataTable)
        index = table.cursor_row
        identity = self._identities[index]
        response = await self._auth.delete(f"{self._auth.directory.identity}/{identity['id']}")
        if response.status_code != 204:
            self.notify(response.json().get("title", "Failed to delete identity"), severity="error")
            return
        self._identities.pop(index)
        self._populate_table(table)
        self.notify(f"Identity '{identity['name']}' deleted")
