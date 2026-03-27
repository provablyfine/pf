import typing

import textual
import textual.app
import textual.containers
import textual.screen
import textual.widgets

from . import async_client, header


class _TagCreateScreen(textual.screen.ModalScreen[dict | None]):
    DEFAULT_CSS = """
    _TagCreateScreen {
        align: center middle;
    }
    _TagCreateScreen > VerticalGroup {
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
            container.border_title = "Add a tag"
            yield textual.widgets.Input(placeholder="name", id="name", compact=True)
            yield textual.widgets.Input(placeholder="value", id="value", compact=True)

    def action_cancel(self) -> None:
        self.dismiss(None)

    @textual.on(textual.widgets.Input.Submitted)
    def _on_submit(self) -> None:
        name = self.query_one("#name", textual.widgets.Input).value.strip()
        value = self.query_one("#value", textual.widgets.Input).value.strip()
        if not name or not value:
            return
        self.dismiss({"name": name, "value": value})


class TagListScreen(textual.screen.Screen[None]):
    BINDINGS: typing.ClassVar = [
        ("a", "add_tag", "Add"),
        ("d", "delete_tag", "Delete"),
        ("escape", "app.pop_screen", "Back"),
    ]

    def __init__(self, auth: async_client.AsyncClient) -> None:
        super().__init__()
        self._auth = auth
        self._tags: list = []

    def compose(self) -> textual.app.ComposeResult:
        yield header.AppHeader()
        yield textual.widgets.DataTable(cursor_type="row")
        yield textual.widgets.Footer(compact=True, show_command_palette=False)

    async def on_mount(self) -> None:
        table = self.query_one(textual.widgets.DataTable)
        table.add_columns("Name", "Value")
        self._tags = await self._auth.list_tags()
        self._populate_table(table)

    def _populate_table(self, table: textual.widgets.DataTable) -> None:
        table.clear(columns=False)
        for tag in self._tags:
            table.add_row(tag["name"], tag["value"])

    @textual.work
    async def action_add_tag(self) -> None:
        data = await self.app.push_screen_wait(_TagCreateScreen())
        if data is None:
            return
        response = await self._auth.post(self._auth.directory.tag, json=data)
        if response.status_code != 201:
            self.notify(response.json().get("title", "Failed to create tag"), severity="error")
            return
        self._tags = await self._auth.list_tags()
        table = self.query_one(textual.widgets.DataTable)
        self._populate_table(table)

    @textual.work
    async def action_delete_tag(self) -> None:
        if not self._tags:
            return
        table = self.query_one(textual.widgets.DataTable)
        index = table.cursor_row
        tag = self._tags[index]
        response = await self._auth.delete(f"{self._auth.directory.tag}/{tag['id']}")
        if response.status_code != 204:
            self.notify(response.json().get("title", "Failed to delete tag"), severity="error")
            return
        self._tags.pop(index)
        self._populate_table(table)
        self.notify(f"Tag '{tag['name']}={tag['value']}' deleted")
