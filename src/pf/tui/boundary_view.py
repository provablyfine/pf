import typing

import textual
import textual.app
import textual.containers
import textual.events
import textual.screen
import textual.widgets

from .. import client
from . import async_client, grant_edit, grant_list, header


class BoundaryViewScreen(textual.screen.Screen[None]):
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

    def __init__(self, auth: async_client.AsyncClient, boundary: dict) -> None:
        super().__init__()
        self._auth = auth
        self._boundary = boundary
        self._denied_list: list = list(boundary["denied_list"])
        self._ceiling_list: list | None = (
            list(boundary["ceiling_list"]) if boundary["ceiling_list"] is not None else None
        )
        self._saved_name: str = boundary["name"]
        self._saved_description: str = boundary["description"]
        self._saved_denied_list: list = list(boundary["denied_list"])
        self._saved_ceiling_list: list | None = (
            list(boundary["ceiling_list"]) if boundary["ceiling_list"] is not None else None
        )

    def compose(self) -> textual.app.ComposeResult:
        yield header.AppHeader()
        with textual.containers.Vertical():
            with textual.containers.HorizontalGroup(classes="field") as container:
                container.border_title = "Name"
                yield textual.widgets.Input(self._boundary["name"], id="name", compact=True)
            with textual.containers.Horizontal(classes="field") as container:
                container.border_title = "Description"
                yield textual.widgets.Input(self._boundary["description"], id="description", compact=True)
            with textual.containers.Container(classes="field") as container:
                container.border_title = "Denied grants"
                yield textual.widgets.DataTable(id="denied", cursor_type="row")
                yield textual.widgets.Label("No denied grants — add one with 'a'", id="denied-placeholder")
            with textual.containers.Container(classes="field") as container:
                container.border_title = "Ceiling grants"
                yield textual.widgets.DataTable(id="ceiling", cursor_type="row")
                yield textual.widgets.Label("No ceiling grants — add one with 'a'", id="ceiling-placeholder")
        yield textual.widgets.Footer(compact=True, show_command_palette=False)

    async def on_mount(self) -> None:
        self.sub_title = f"Boundaries > {self._boundary['name']}"
        self.query_one("#denied", textual.widgets.DataTable).add_columns("Type", "Filter", "Permissions")
        self.query_one("#ceiling", textual.widgets.DataTable).add_columns("Type", "Filter", "Permissions")
        self._populate_denied()
        self._populate_ceiling()

    def on_descendant_focus(self, event: textual.events.DescendantFocus) -> None:
        self.refresh_bindings()

    def on_descendant_blur(self, event: textual.events.DescendantBlur) -> None:
        self.refresh_bindings()

    def _populate_denied(self) -> None:
        table = self.query_one("#denied", textual.widgets.DataTable)
        table.clear(columns=False)
        for g in self._denied_list:
            type_str, filter_str, perm_str = client.grant.to_text(g)
            table.add_row(type_str, filter_str, perm_str)
        self.query_one("#denied-placeholder").display = not bool(self._denied_list)

    def _populate_ceiling(self) -> None:
        table = self.query_one("#ceiling", textual.widgets.DataTable)
        table.clear(columns=False)
        ceiling = self._ceiling_list or []
        for g in ceiling:
            type_str, filter_str, perm_str = client.grant.to_text(g)
            table.add_row(type_str, filter_str, perm_str)
        self.query_one("#ceiling-placeholder").display = not bool(ceiling)

    @textual.on(textual.widgets.DataTable.RowSelected)
    def _on_row_selected(self, event: textual.widgets.DataTable.RowSelected) -> None:
        if event.data_table.id == "denied":
            self._edit_grant_in("denied")
        elif event.data_table.id == "ceiling":
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
            table = self.query_one("#denied", textual.widgets.DataTable)
            if not self._denied_list:
                return
            self._denied_list.pop(table.cursor_row)
            self._populate_denied()
        elif focused.id == "ceiling":
            table = self.query_one("#ceiling", textual.widgets.DataTable)
            if not self._ceiling_list:
                return
            self._ceiling_list.pop(table.cursor_row)
            self._populate_ceiling()

    @textual.work
    async def _edit_grant_in(self, table_id: str) -> None:
        table = self.query_one(f"#{table_id}", textual.widgets.DataTable)
        grant_list_ref = self._denied_list if table_id == "denied" else (self._ceiling_list or [])
        if not grant_list_ref:
            return
        index = table.cursor_row
        updated_grant = await self.app.push_screen_wait(
            grant_edit.GrantEditScreen(self._auth, grant_list_ref[index])
        )
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

        patch: dict = {}
        if name != self._saved_name:
            patch["name"] = name
        if description != self._saved_description:
            patch["description"] = description
        if self._denied_list != self._saved_denied_list:
            patch["denied_list"] = self._denied_list
        if self._ceiling_list != self._saved_ceiling_list:
            patch["ceiling_list"] = self._ceiling_list

        if not patch:
            self.notify("No changes")
            return

        response = await self._auth.patch(
            f"{self._auth.directory.boundary}/{self._boundary['id']}",
            json=patch,
        )
        if response.status_code != 200:
            self.notify(response.json().get("title", "Failed to save"), severity="error")
        else:
            self.app.pop_screen()
