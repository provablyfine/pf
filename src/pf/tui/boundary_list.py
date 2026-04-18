import typing

import textual
import textual.app
import textual.containers
import textual.screen
import textual.widgets

from .. import client
from . import _utils, base, boundary_view, header


class _BoundaryCreateScreen(textual.screen.ModalScreen[str | None]):
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

    def action_cancel(self) -> None:
        self.dismiss(None)

    @textual.on(textual.widgets.Input.Submitted)
    def _on_submit(self) -> None:
        name = self.query_one("#name", textual.widgets.Input).value.strip()
        if not name:
            return
        self.dismiss(name)


class BoundaryListScreen(base.Screen):
    BINDINGS: typing.ClassVar = [
        ("enter", "view_boundary", "View"),
        ("a", "add_boundary", "Add"),
        ("d", "delete_boundary", "Delete"),
        ("escape", "app.pop_screen", "Back"),
    ]

    def __init__(self, auth: client.aio.Client) -> None:
        super().__init__()
        self._auth = auth
        self._boundaries: list[client.schemas.Boundary] = []

    def compose(self) -> textual.app.ComposeResult:
        yield header.AppHeader()
        yield textual.widgets.DataTable(cursor_type="row")
        yield textual.widgets.Footer(compact=True, show_command_palette=False)

    async def on_mount(self) -> None:
        table = self.query_one(textual.widgets.DataTable[str])
        table.add_columns("Name", "Description", "Denied", "Ceiling")
        self._boundaries = (await self._auth.list_boundaries()).boundaries
        self._populate_table(table)

    @textual.work
    async def on_screen_resume(self) -> None:
        self._boundaries = (await self._auth.list_boundaries()).boundaries
        self._populate_table(self.query_one(textual.widgets.DataTable[str]))

    def _populate_table(self, table: textual.widgets.DataTable[str]) -> None:
        table.clear(columns=False)
        for boundary in self._boundaries:
            ceiling = boundary.ceiling_list
            ceiling_count = str(len(ceiling)) if ceiling is not None else "—"
            table.add_row(
                boundary.name,
                _utils.ellipsize(boundary.description, 40),
                str(len(boundary.denied_list)),
                ceiling_count,
            )

    @textual.on(textual.widgets.DataTable.RowSelected)
    def _on_row_selected(self) -> None:
        self.action_view_boundary()

    def action_view_boundary(self) -> None:
        if not self._boundaries:
            return
        table = self.query_one(textual.widgets.DataTable[str])
        boundary = self._boundaries[table.cursor_row]
        self.app.push_screen(boundary_view.BoundaryViewScreen(self._auth, boundary))

    @textual.work
    async def action_add_boundary(self) -> None:
        name = await self.app.push_screen_wait(_BoundaryCreateScreen())
        if name is None:
            return
        boundary = await self._auth.create_boundary(name, "")
        self._boundaries.append(boundary)
        table = self.query_one(textual.widgets.DataTable[str])
        self._populate_table(table)
        table.move_cursor(row=len(self._boundaries) - 1)
        self.app.push_screen(boundary_view.BoundaryViewScreen(self._auth, boundary))

    @textual.work
    async def action_delete_boundary(self) -> None:
        if not self._boundaries:
            return
        table = self.query_one(textual.widgets.DataTable[str])
        index = table.cursor_row
        boundary = self._boundaries[index]
        await self._auth.delete_boundary(boundary.id)
        self._boundaries.pop(index)
        self._populate_table(table)
        self.notify(f"Boundary '{boundary.name}' deleted")
