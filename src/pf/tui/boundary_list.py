import typing

import textual
import textual.app
import textual.containers
import textual.screen
import textual.widgets

from . import async_client, header


class _BoundaryCreateScreen(textual.screen.ModalScreen[dict | None]):
    DEFAULT_CSS = """
    _BoundaryCreateScreen {
        align: center middle;
    }
    _BoundaryCreateScreen > VerticalGroup {
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
            container.border_title = "Add a boundary"
            yield textual.widgets.Input(placeholder="name", id="name", compact=True)
            yield textual.widgets.Input(placeholder="description", id="description", compact=True)

    def action_cancel(self) -> None:
        self.dismiss(None)

    @textual.on(textual.widgets.Input.Submitted)
    def _on_submit(self) -> None:
        name = self.query_one("#name", textual.widgets.Input).value.strip()
        if not name:
            return
        description = self.query_one("#description", textual.widgets.Input).value.strip()
        self.dismiss({"name": name, "description": description})


class BoundaryListScreen(textual.screen.Screen[None]):
    BINDINGS: typing.ClassVar = [
        ("a", "add_boundary", "Add"),
        ("d", "delete_boundary", "Delete"),
        ("escape", "app.pop_screen", "Back"),
    ]

    def __init__(self, auth: async_client.AsyncClient) -> None:
        super().__init__()
        self._auth = auth
        self._boundaries: list = []

    def compose(self) -> textual.app.ComposeResult:
        yield header.AppHeader()
        yield textual.widgets.DataTable(cursor_type="row")
        yield textual.widgets.Footer(compact=True, show_command_palette=False)

    async def on_mount(self) -> None:
        table = self.query_one(textual.widgets.DataTable)
        table.add_columns("Name", "Description")
        self._boundaries = await self._auth.list_boundaries()
        self._populate_table(table)

    def _populate_table(self, table: textual.widgets.DataTable) -> None:
        table.clear(columns=False)
        for boundary in self._boundaries:
            table.add_row(boundary["name"], boundary["description"])

    @textual.work
    async def action_add_boundary(self) -> None:
        data = await self.app.push_screen_wait(_BoundaryCreateScreen())
        if data is None:
            return
        response = await self._auth.post(self._auth.directory.boundary, json=data)
        if response.status_code != 201:
            self.notify(response.json().get("title", "Failed to create boundary"), severity="error")
            return
        self._boundaries = await self._auth.list_boundaries()
        table = self.query_one(textual.widgets.DataTable)
        self._populate_table(table)

    @textual.work
    async def action_delete_boundary(self) -> None:
        if not self._boundaries:
            return
        table = self.query_one(textual.widgets.DataTable)
        index = table.cursor_row
        boundary = self._boundaries[index]
        response = await self._auth.delete(f"{self._auth.directory.boundary}/{boundary['id']}")
        if response.status_code != 204:
            self.notify(response.json().get("title", "Failed to delete boundary"), severity="error")
            return
        self._boundaries.pop(index)
        self._populate_table(table)
        self.notify(f"Boundary '{boundary['name']}' deleted")
