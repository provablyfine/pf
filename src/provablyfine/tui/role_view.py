from __future__ import annotations

import typing

import provablyfine_client as pfc
import textual
import textual.app
import textual.containers
import textual.events
import textual.widgets

from .. import client
from . import base, grant_edit, grant_list, header, member_list


class _GrantsTable(textual.widgets.DataTable[str]):
    pass


class RoleViewScreen(base.Screen):
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
    .label {
        padding: 0 2 0 0;
    }
    .field {
        border: solid;
        height: auto;
    }
    #description, #members {
        height: auto;
    }
    """

    def __init__(self, auth: client.aio.Client, role: pfc.schemas.Role) -> None:
        super().__init__()
        self._auth = auth
        self._role = role
        self._member_names: list[str] = [m.name for m in role.member_list]
        self._grant_list: list[pfc.schemas.Grant] = list(role.grant_list)
        self._saved_name: str = role.name
        self._saved_description: str = role.description
        self._saved_member_names: set[str] = {m.name for m in role.member_list}
        self._saved_grant_list: list[pfc.schemas.Grant] = list(role.grant_list)

    def compose(self) -> textual.app.ComposeResult:
        yield header.AppHeader()
        with textual.containers.Vertical():
            with textual.containers.HorizontalGroup(classes="field") as container:
                container.border_title = "Name"
                yield textual.widgets.Input(self._role.name, id="name", compact=True)
            with textual.containers.Horizontal(classes="field") as container:
                container.border_title = "Description"
                yield textual.widgets.Input(self._role.description, id="description", compact=True)
            with textual.containers.Container(classes="field") as container:
                container.border_title = "Members"
                yield textual.widgets.ListView(id="members")
                yield textual.widgets.Label("No members — add one with 'a'", id="members-placeholder")
            with textual.containers.Container(classes="field") as container:
                container.border_title = "Grants"
                yield _GrantsTable(id="grants", cursor_type="row")
                yield textual.widgets.Label("No grants — add one with 'a'", id="grants-placeholder")
        yield textual.widgets.Footer(compact=True, show_command_palette=False)

    async def on_mount(self) -> None:
        self.sub_title = f"Roles > {self._role.name}"
        self.query_one("#grants", _GrantsTable).add_columns("Type", "Filter", "Permissions")
        await self._populate_members()
        self._populate_grants()

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
        for name in self._member_names:
            await lv.append(textual.widgets.ListItem(textual.widgets.Label(name)))
        self.query_one("#members-placeholder").display = not bool(self._member_names)

    def _populate_grants(self) -> None:
        table = self.query_one("#grants", _GrantsTable)
        table.clear(columns=False)
        for g in self._grant_list:
            grant_text = g.to_text()
            table.add_row(grant_text.type, grant_text.filter, grant_text.permission)
        self.query_one("#grants-placeholder").display = not bool(self._grant_list)

    @textual.on(_GrantsTable.RowSelected)
    def _on_row_selected(self, event: _GrantsTable.RowSelected) -> None:
        self.action_edit_grant()

    @textual.work
    async def action_add(self) -> None:
        focused = self.focused
        if focused is None:
            return
        if focused.id == "members":
            identities = (await self._auth.list_identities()).identities
            existing = set(self._member_names)
            names = [i.name for i in identities if i.name not in existing]
            name = await self.app.push_screen_wait(member_list.MemberAddScreen(names))
            if name is None:
                return
            self._member_names.append(name)
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
            if index is None or not self._member_names:
                return
            self._member_names.pop(index)
            await self._populate_members()
        elif focused.id == "grants":
            table = self.query_one("#grants", _GrantsTable)
            if not self._grant_list:
                return
            self._grant_list.pop(table.cursor_row)
            self._populate_grants()

    @textual.work
    async def action_edit_grant(self) -> None:
        table = self.query_one("#grants", _GrantsTable)
        if not self._grant_list:
            return
        index = table.cursor_row
        updated_grant = await self.app.push_screen_wait(grant_edit.GrantEditScreen(self._auth, self._grant_list[index]))
        if updated_grant is None:
            return
        self._grant_list[index] = updated_grant
        self._populate_grants()
        self.query_one("#grants").focus()

    @textual.work
    async def action_save(self) -> None:
        name = self.query_one("#name", textual.widgets.Input).value
        description = self.query_one("#description", textual.widgets.Input).value
        current_member_names = set(self._member_names)

        name_changed = name != self._saved_name
        description_changed = description != self._saved_description
        members_changed = current_member_names != self._saved_member_names
        grants_changed = self._grant_list != self._saved_grant_list

        if not (name_changed or description_changed or members_changed or grants_changed):
            self.notify("No changes")
            return

        await self._auth.update_role(
            self._role.id,
            name=name if name_changed else None,
            description=description if description_changed else None,
            grant_list=self._grant_list if grants_changed else None,
            member_list=[pfc.schemas.RoleMemberRef(name=name) for name in self._member_names]
            if members_changed
            else None,
        )
        self._saved_name = name
        self._saved_description = description
        self._saved_member_names = current_member_names
        self._saved_grant_list = list(self._grant_list)
        self.notify("Saved")
