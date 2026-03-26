import typing

import textual
import textual.app
import textual.containers
import textual.screen
import textual.widgets

from . import async_client, header


class MemberAddScreen(textual.screen.ModalScreen[str | None]):
    DEFAULT_CSS = """
    MemberAddScreen {
        align: center middle;
    }
    MemberAddScreen > VerticalGroup {
        width: 40;
        height: auto;
        padding: 1 2;
        background: $surface;
        border: thick $primary;
    }
    """
    BINDINGS: typing.ClassVar = [("escape", "cancel", "Cancel")]

    def __init__(self, identity_names: list[str]) -> None:
        super().__init__()
        self._identity_names = identity_names

    def compose(self) -> textual.app.ComposeResult:
        with textual.containers.VerticalGroup():
            yield textual.widgets.Label("Add member")
            yield textual.widgets.Select.from_values(self._identity_names, allow_blank=True, compact=True)
            yield textual.widgets.Button("Add", variant="primary")

    def action_cancel(self) -> None:
        self.dismiss(None)

    @textual.on(textual.widgets.Button.Pressed)
    def _on_add(self) -> None:
        select = self.query_one(textual.widgets.Select)
        if select.value is textual.widgets.Select.BLANK:
            return
        self.dismiss(str(select.value))


class MemberListScreen(textual.screen.Screen[None]):
    BINDINGS: typing.ClassVar = [
        ("escape", "app.pop_screen", "Back"),
        ("a", "add_member", "Add"),
        ("d", "delete_member", "Delete"),
    ]

    def __init__(self, auth: async_client.AsyncClient, member_list: list, sub_title: str, role_id: int) -> None:
        super().__init__()
        self._auth = auth
        self._member_list = member_list
        self._sub_title = sub_title
        self._role_id = role_id

    def compose(self) -> textual.app.ComposeResult:
        yield header.AppHeader()
        yield textual.widgets.DataTable(cursor_type="row")
        yield textual.widgets.Footer()

    def on_mount(self) -> None:
        self.sub_title = self._sub_title
        table = self.query_one(textual.widgets.DataTable)
        table.add_columns("Name")
        self._populate_table(table)

    def _populate_table(self, table: textual.widgets.DataTable) -> None:
        table.clear(columns=False)
        for member in self._member_list:
            table.add_row(member["name"])

    async def _save_members(self) -> bool:
        response = await self._auth.patch(
            f"{self._auth.directory.role}/{self._role_id}",
            json={"member_list": [{"name": m["name"]} for m in self._member_list]},
        )
        if response.status_code != 200:
            self.notify(response.json().get("title", "Failed to save members"), severity="error")
            return False
        return True

    @textual.work
    async def action_add_member(self) -> None:
        identities = await self._auth.list_identities()
        names = [i["name"] for i in identities]
        name = await self.app.push_screen_wait(MemberAddScreen(names))
        if name is None:
            return
        self._member_list.append({"name": name})
        if not await self._save_members():
            self._member_list.pop()
            return
        self._populate_table(self.query_one(textual.widgets.DataTable))
        self.notify("Member added")

    @textual.work
    async def action_delete_member(self) -> None:
        table = self.query_one(textual.widgets.DataTable)
        if not self._member_list:
            return
        index = table.cursor_row
        deleted = self._member_list.pop(index)
        if not await self._save_members():
            self._member_list.insert(index, deleted)
            return
        self._populate_table(table)
        self.notify("Member deleted")
