import typing

import textual
import textual.app
import textual.containers
import textual.screen
import textual.widgets

from .. import client
from . import clipboard, header, identity_view


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


class _InviteMethodScreen(textual.screen.ModalScreen[str | None]):
    DEFAULT_CSS = """
    _InviteMethodScreen {
        align: center middle;
    }
    _InviteMethodScreen > VerticalGroup {
        width: auto;
        height: auto;
        padding: 1 2;
        background: $surface;
        border: thick $primary;
    }
    _InviteMethodScreen ListView {
        height: auto;
        width: auto;
        padding: 1 2;
    }
    _InviteMethodScreen ListItem {
        height: auto;
        width: auto;
    }
    """
    BINDINGS: typing.ClassVar = [("escape", "cancel", "Cancel")]

    def compose(self) -> textual.app.ComposeResult:
        with textual.containers.VerticalGroup() as container:
            container.border_title = "Invitation method"
            yield textual.widgets.ListView(
                textual.widgets.ListItem(textual.widgets.Label("manual"), id="manual"),
                textual.widgets.ListItem(textual.widgets.Label("email"), id="email"),
            )

    def action_cancel(self) -> None:
        self.dismiss(None)

    @textual.on(textual.widgets.ListView.Selected)
    def _on_selected(self, event: textual.widgets.ListView.Selected) -> None:
        self.dismiss(event.item.id)


class _InviteSecretScreen(textual.screen.ModalScreen[None]):
    DEFAULT_CSS = """
    _InviteSecretScreen {
        align: center middle;
    }
    _InviteSecretScreen > VerticalGroup {
        width: 60;
        height: auto;
        padding: 1 2;
        background: $surface;
        border: thick $primary;
    }
    #secret {
        width: 1fr;
    }
    """
    BINDINGS: typing.ClassVar = [
        ("escape", "dismiss_screen", "Close"),
    ]

    def __init__(self, secret: str) -> None:
        super().__init__()
        self._secret = secret

    def compose(self) -> textual.app.ComposeResult:
        with textual.containers.VerticalGroup() as container:
            container.border_title = "Invitation secret"
            yield textual.widgets.Input(self._secret, id="secret", compact=True)

    @textual.work
    async def on_mount(self) -> None:
        self.query_one("#secret", textual.widgets.Input).can_focus = False
        try:
            await clipboard.copy(self.app, self._secret)
            self.notify("Copied to clipboard")
        except Exception:
            self.notify("Failed to copy to clipboard", severity="warning")

    def action_dismiss_screen(self) -> None:
        self.dismiss(None)


class IdentityListScreen(textual.screen.Screen[None]):
    BINDINGS: typing.ClassVar = [
        ("enter", "view_identity", "View"),
        ("a", "add_identity", "Add"),
        ("d", "delete_identity", "Delete"),
        ("i", "invite_identity", "Invite"),
        ("escape", "app.pop_screen", "Back"),
    ]

    def __init__(self, auth: client.aio.Client) -> None:
        super().__init__()
        self._auth = auth
        self._identities: list[client.schemas.Identity] = []

    def compose(self) -> textual.app.ComposeResult:
        yield header.AppHeader()
        yield textual.widgets.DataTable(cursor_type="row")
        yield textual.widgets.Footer(compact=True, show_command_palette=False)

    async def on_mount(self) -> None:
        table = self.query_one(textual.widgets.DataTable)
        table.add_columns("Name", "Tags", "Boundaries")
        self._identities = (await self._auth.list_identities()).identities
        self._populate_table(table)

    @textual.work
    async def on_screen_resume(self) -> None:
        self._identities = (await self._auth.list_identities()).identities
        self._populate_table(self.query_one(textual.widgets.DataTable))

    def _populate_table(self, table: textual.widgets.DataTable) -> None:
        table.clear(columns=False)
        for identity in self._identities:
            table.add_row(
                identity["name"],
                str(len(identity["tags"])),
                str(len(identity["boundaries"])),
            )

    @textual.on(textual.widgets.DataTable.RowSelected)
    def _on_row_selected(self) -> None:
        self.action_view_identity()

    def action_view_identity(self) -> None:
        if not self._identities:
            return
        table = self.query_one(textual.widgets.DataTable)
        identity = self._identities[table.cursor_row]
        self.app.push_screen(identity_view.IdentityViewScreen(self._auth, identity))

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
        identity = response.json()
        self._identities.append(identity)
        table = self.query_one(textual.widgets.DataTable)
        self._populate_table(table)
        table.move_cursor(row=len(self._identities) - 1)
        self.app.push_screen(identity_view.IdentityViewScreen(self._auth, identity))

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

    @textual.work
    async def action_invite_identity(self) -> None:
        if not self._identities:
            return
        table = self.query_one(textual.widgets.DataTable)
        identity = self._identities[table.cursor_row]
        method = await self.app.push_screen_wait(_InviteMethodScreen())
        if method is None:
            return
        response = await self._auth.post(
            f"{self._auth.directory.identity}/{identity['id']}/invite",
            json={"delivery": method},
        )
        if response.status_code >= 400:
            self.notify(response.json().get("title", "Failed to invite identity"), severity="error")
            return
        if method == "manual":
            secret = response.json()["key"]["k"]
            await self.app.push_screen_wait(_InviteSecretScreen(secret))
        else:
            self.notify(f"Invitation sent to '{identity['name']}'")
