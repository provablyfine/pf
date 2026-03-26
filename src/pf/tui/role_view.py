import typing

import textual
import textual.app
import textual.containers
import textual.events
import textual.screen
import textual.widgets

from .. import client
from . import async_client, grant_edit, grant_list, header, member_list


class RoleViewScreen(textual.screen.Screen[None]):
    BINDINGS: typing.ClassVar = [
        ("ctrl+s", "save", "Save"),
        ("escape", "app.pop_screen", "Back"),
        ("a", "add", "Add"),
        ("d", "delete", "Delete"),
        ("enter", "edit_grant", "Edit grant"),
    ]

    def __init__(self, auth: async_client.AsyncClient, role: dict) -> None:
        super().__init__()
        self._auth = auth
        self._role = role
        self._member_list: list = list(role["member_list"])
        self._grant_list: list = list(role["grant_list"])
        self._saved_name: str = role["name"]
        self._saved_description: str = role["description"]
        self._saved_member_names: set[str] = {m["name"] for m in role["member_list"]}
        self._saved_grant_list: list = list(role["grant_list"])

    def compose(self) -> textual.app.ComposeResult:
        yield header.AppHeader()
        with textual.containers.Vertical():
            with textual.containers.Horizontal():
                yield textual.widgets.Label("Name")
                yield textual.widgets.Input(self._role["name"], id="name", compact=True)
            with textual.containers.Horizontal():
                yield textual.widgets.Label("Description")
                yield textual.widgets.Input(self._role["description"], id="description", compact=True)
            yield textual.widgets.Label("Members", classes="section-label")
            yield textual.widgets.ListView(id="members")
            yield textual.widgets.Label("No members — add one with 'a'", id="members-placeholder")
            yield textual.widgets.Label("Grants", classes="section-label")
            yield textual.widgets.DataTable(id="grants", cursor_type="row")
            yield textual.widgets.Label("No grants — add one with 'a'", id="grants-placeholder")
        yield textual.widgets.Footer()

    async def on_mount(self) -> None:
        self.sub_title = f"Roles > {self._role['name']}"
        self.query_one("#grants", textual.widgets.DataTable).add_columns("Type", "Filter", "Permissions")
        await self._populate_members()
        self._populate_grants()
        self.query_one("#members").focus()

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        if action == "edit_grant":
            focused = self.focused
            return focused is not None and focused.id == "grants"
        return True

    def on_descendant_focus(self, event: textual.events.DescendantFocus) -> None:
        self.refresh_bindings()

    def on_descendant_blur(self, event: textual.events.DescendantBlur) -> None:
        self.refresh_bindings()

    async def _populate_members(self) -> None:
        lv = self.query_one("#members", textual.widgets.ListView)
        await lv.clear()
        for m in self._member_list:
            await lv.append(textual.widgets.ListItem(textual.widgets.Label(m["name"])))
        self.query_one("#members-placeholder").display = not bool(self._member_list)

    def _populate_grants(self) -> None:
        table = self.query_one("#grants", textual.widgets.DataTable)
        table.clear(columns=False)
        for g in self._grant_list:
            type_str, filter_str, perm_str = client.grant.to_text(g)
            table.add_row(type_str, filter_str, perm_str)
        self.query_one("#grants-placeholder").display = not bool(self._grant_list)

    @textual.on(textual.widgets.DataTable.RowSelected)
    def _on_row_selected(self, event: textual.widgets.DataTable.RowSelected) -> None:
        if event.data_table.id == "grants":
            self.action_edit_grant()

    @textual.work
    async def action_add(self) -> None:
        focused = self.focused
        if focused is None:
            return
        if focused.id == "members":
            identities = await self._auth.list_identities()
            names = [i["name"] for i in identities]
            name = await self.app.push_screen_wait(member_list.MemberAddScreen(names))
            if name is None:
                return
            self._member_list.append({"name": name})
            await self._populate_members()
        elif focused.id == "grants":
            grant_type = await self.app.push_screen_wait(grant_list.GrantTypeScreen())
            if grant_type is None:
                return
            new_grant = grant_edit.new_grant(grant_type)
            updated_grant = await self.app.push_screen_wait(grant_edit.GrantEditScreen(self._auth, new_grant))
            if updated_grant is None:
                return
            self._grant_list.append(updated_grant)
            self._populate_grants()

    @textual.work
    async def action_delete(self) -> None:
        focused = self.focused
        if focused is None:
            return
        if focused.id == "members":
            lv = self.query_one("#members", textual.widgets.ListView)
            index = lv.index
            if index is None or not self._member_list:
                return
            self._member_list.pop(index)
            await self._populate_members()
        elif focused.id == "grants":
            table = self.query_one("#grants", textual.widgets.DataTable)
            if not self._grant_list:
                return
            self._grant_list.pop(table.cursor_row)
            self._populate_grants()

    @textual.work
    async def action_edit_grant(self) -> None:
        table = self.query_one("#grants", textual.widgets.DataTable)
        if not self._grant_list:
            return
        index = table.cursor_row
        updated_grant = await self.app.push_screen_wait(
            grant_edit.GrantEditScreen(self._auth, self._grant_list[index])
        )
        if updated_grant is None:
            return
        self._grant_list[index] = updated_grant
        self._populate_grants()
        self.query_one("#grants").focus()

    @textual.work
    async def action_save(self) -> None:
        name = self.query_one("#name", textual.widgets.Input).value
        description = self.query_one("#description", textual.widgets.Input).value
        current_member_names = {m["name"] for m in self._member_list}

        patch: dict = {}
        if name != self._saved_name:
            patch["name"] = name
        if description != self._saved_description:
            patch["description"] = description
        if current_member_names != self._saved_member_names:
            patch["member_list"] = [{"name": m["name"]} for m in self._member_list]
        if self._grant_list != self._saved_grant_list:
            patch["grant_list"] = self._grant_list

        if not patch:
            self.notify("No changes")
            return

        response = await self._auth.patch(
            f"{self._auth.directory.role}/{self._role['id']}",
            json=patch,
        )
        if response.status_code != 200:
            self.notify(response.json().get("title", "Failed to save"), severity="error")
        else:
            self._saved_name = name
            self._saved_description = description
            self._saved_member_names = current_member_names
            self._saved_grant_list = list(self._grant_list)
            self.notify("Saved")
