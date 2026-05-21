from __future__ import annotations

import typing

import textual
import textual.app
import textual.containers
import textual.events
import textual.widgets

from .. import client
from . import base, grant_edit, grant_list, header


class _DeniedTable(textual.widgets.DataTable[str]):
    class RowSelected(textual.widgets.DataTable.RowSelected):
        data_table: _DeniedTable


class _CeilingTable(textual.widgets.DataTable[str]):
    class RowSelected(textual.widgets.DataTable.RowSelected):
        data_table: _CeilingTable


class BoundaryViewScreen(base.Screen):
    BINDINGS: typing.ClassVar = [
        ("ctrl+s", "save", "Save"),
        ("escape", "app.pop_screen", "Back"),
        ("a", "add", "Add"),
        ("d", "delete", "Delete"),
    ]
    DEFAULT_CSS = """
    Vertical {
        height: auto;
    }
    .field {
        border: solid;
        height: auto;
    }
    #description {
        height: auto;
    }
    #denied, #ceiling {
        height: auto;
    }
    """

    def __init__(self, auth: client.aio.Client, boundary: client.schemas.Boundary) -> None:
        super().__init__()
        self._auth = auth
        self._boundary = boundary
        self._denied_list = list(boundary.denied_list)
        self._ceiling_list = list(boundary.ceiling_list) if boundary.ceiling_list is not None else None
        self._saved_name: str = boundary.name
        self._saved_description: str = boundary.description
        self._saved_denied_list = list(boundary.denied_list)
        self._saved_ceiling_list = list(boundary.ceiling_list) if boundary.ceiling_list is not None else None

    def compose(self) -> textual.app.ComposeResult:
        yield header.AppHeader()
        with textual.containers.Vertical():
            with textual.containers.HorizontalGroup(classes="field") as container:
                container.border_title = "Name"
                yield textual.widgets.Input(self._boundary.name, id="name", compact=True)
            with textual.containers.Horizontal(classes="field") as container:
                container.border_title = "Description"
                yield textual.widgets.Input(self._boundary.description, id="description", compact=True)
            with textual.containers.Container(classes="field") as container:
                container.border_title = "Denied grants"
                yield _DeniedTable(id="denied", cursor_type="row")
                yield textual.widgets.Label("No denied grants — add one with 'a'", id="denied-placeholder")
            with textual.containers.Container(classes="field") as container:
                container.border_title = "Ceiling grants"
                yield _CeilingTable(id="ceiling", cursor_type="row")
                yield textual.widgets.Label("No ceiling grants — add one with 'a'", id="ceiling-placeholder")
        yield textual.widgets.Footer(compact=True, show_command_palette=False)

    async def on_mount(self) -> None:
        self.sub_title = f"Boundaries > {self._boundary.name}"
        self.query_one("#denied", _DeniedTable).add_columns("Type", "Filter", "Permissions")
        self.query_one("#ceiling", _CeilingTable).add_columns("Type", "Filter", "Permissions")
        self._populate_denied()
        self._populate_ceiling()

    def on_descendant_focus(self, event: textual.events.DescendantFocus) -> None:
        self.refresh_bindings()

    def on_descendant_blur(self, event: textual.events.DescendantBlur) -> None:
        self.refresh_bindings()

    def _populate_denied(self) -> None:
        table = self.query_one("#denied", _DeniedTable)
        table.clear(columns=False)
        for g in self._denied_list:
            grant_text = g.to_text()
            table.add_row(grant_text.type, grant_text.filter, grant_text.permission)
        self.query_one("#denied-placeholder").display = not bool(self._denied_list)

    def _populate_ceiling(self) -> None:
        table = self.query_one("#ceiling", _CeilingTable)
        table.clear(columns=False)
        ceiling = self._ceiling_list or []
        for g in ceiling:
            grant_text = g.to_text()
            table.add_row(grant_text.type, grant_text.filter, grant_text.permission)
        self.query_one("#ceiling-placeholder").display = not bool(ceiling)

    @textual.on(_DeniedTable.RowSelected)
    def _on_denied_row_selected(self) -> None:
        self._edit_grant_in("denied")

    @textual.on(_CeilingTable.RowSelected)
    def _on_ceiling_row_selected(self) -> None:
        self._edit_grant_in("ceiling")

    @textual.work
    async def action_add(self) -> None:
        focused = self.focused
        if focused is None:
            return
        if focused.id in ("denied", "ceiling"):
            grant_type = await self.app.push_screen_wait(grant_list.GrantTypeScreen())
            if grant_type is None:
                return
            new_grant = grant_edit.new_grant(grant_type)
            updated_grant = await self.app.push_screen_wait(grant_edit.GrantEditScreen(self._auth, new_grant))
            if updated_grant is None:
                return
            if focused.id == "denied":
                self._denied_list.append(updated_grant)
                self._populate_denied()
            else:
                if self._ceiling_list is None:
                    self._ceiling_list = []
                self._ceiling_list.append(updated_grant)
                self._populate_ceiling()

    @textual.work
    async def action_delete(self) -> None:
        focused = self.focused
        if focused is None:
            return
        if focused.id == "denied":
            table = self.query_one("#denied", _DeniedTable)
            if not self._denied_list:
                return
            self._denied_list.pop(table.cursor_row)
            self._populate_denied()
        elif focused.id == "ceiling":
            table = self.query_one("#ceiling", _CeilingTable)
            if not self._ceiling_list:
                return
            self._ceiling_list.pop(table.cursor_row)
            self._populate_ceiling()

    @textual.work
    async def _edit_grant_in(self, table_id: str) -> None:
        if table_id == "denied":
            table = self.query_one("#denied", _DeniedTable)
            grant_list_ref = self._denied_list
        else:
            table = self.query_one("#ceiling", _CeilingTable)
            grant_list_ref = self._ceiling_list or []
        if not grant_list_ref:
            return
        index = table.cursor_row
        updated_grant = await self.app.push_screen_wait(grant_edit.GrantEditScreen(self._auth, grant_list_ref[index]))
        if updated_grant is None:
            return
        grant_list_ref[index] = updated_grant
        if table_id == "denied":
            self._populate_denied()
        else:
            self._populate_ceiling()
        table.focus()

    @textual.work
    async def action_save(self) -> None:
        name = self.query_one("#name", textual.widgets.Input).value
        description = self.query_one("#description", textual.widgets.Input).value

        name_changed = name != self._saved_name
        description_changed = description != self._saved_description
        denied_changed = self._denied_list != self._saved_denied_list
        ceiling_changed = self._ceiling_list != self._saved_ceiling_list

        if not (name_changed or description_changed or denied_changed or ceiling_changed):
            self.notify("No changes")
            return

        await self._auth.update_boundary(
            self._boundary.id,
            name=name if name_changed else None,
            description=description if description_changed else None,
            denied_list=self._denied_list if denied_changed else None,
            ceiling_list=self._ceiling_list if ceiling_changed else None,
        )
        self.app.pop_screen()
