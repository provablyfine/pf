import typing

import provablyfine_client as pfc
import textual
import textual.app
import textual.containers
import textual.widgets

from . import base


class _TagCreateScreen(base.ModalScreen[pfc.schemas.TagNameValue | None]):
    DEFAULT_CSS = """
    _TagCreateScreen > VerticalGroup {
        width: 40;
    }
    """
    BINDINGS: typing.ClassVar = [("escape", "cancel", "Cancel")]

    def compose(self) -> textual.app.ComposeResult:
        with textual.containers.VerticalGroup() as container:
            container.border_title = "Add a tag"
            yield base.Input(placeholder="Name", id="name", compact=True)
            yield base.Input(placeholder="Value", id="value", compact=True)

    def action_cancel(self) -> None:
        self.dismiss(None)

    @textual.on(textual.widgets.Input.Submitted)
    def _on_submit(self) -> None:
        name = self.query_one("#name", textual.widgets.Input).value.strip()
        value = self.query_one("#value", textual.widgets.Input).value.strip()
        if not name or not value:
            return
        self.dismiss(pfc.schemas.TagNameValue(name=name, value=value))


class TagListScreen(base.Screen):
    BINDINGS: typing.ClassVar = [
        ("a", "add_tag", "Add"),
        ("d", "delete_tag", "Delete"),
        ("escape", "app.pop_screen", "Back"),
    ]

    def __init__(self, auth: pfc.AsyncSessionClient) -> None:
        super().__init__()
        self._auth = auth
        self._tags: list[pfc.schemas.Tag] = []

    def compose(self) -> textual.app.ComposeResult:
        yield textual.widgets.DataTable(cursor_type="row")
        yield textual.widgets.Label("No tags — add one with 'a'", id="tags-placeholder")
        yield textual.widgets.Footer(compact=True, show_command_palette=False)

    async def on_mount(self) -> None:
        table = self.query_one(textual.widgets.DataTable[str])
        table.add_columns("Name", "Value")
        self._tags = (await self._auth.list_tags()).tags
        self._populate_table(table)

    def _populate_table(self, table: textual.widgets.DataTable[str]) -> None:
        table.clear(columns=False)
        for tag in self._tags:
            table.add_row(tag.name, tag.value)
        self.query_one("#tags-placeholder").display = not bool(self._tags)

    @textual.work
    async def action_add_tag(self) -> None:
        data = await self.app.push_screen_wait(_TagCreateScreen())
        if data is None:
            return
        tag = await self._auth.create_tag(data.name, data.value)
        self._tags.append(tag)
        table = self.query_one(textual.widgets.DataTable[str])
        self._populate_table(table)

    @textual.work
    async def action_delete_tag(self) -> None:
        if not self._tags:
            return
        table = self.query_one(textual.widgets.DataTable[str])
        index = table.cursor_row
        tag = self._tags[index]
        await self._auth.delete_tag(tag.id)
        self._tags.pop(index)
        self._populate_table(table)
        self.notify(f"Tag '{tag.name}={tag.value}' deleted")
