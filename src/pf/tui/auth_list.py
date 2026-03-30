import typing

import textual
import textual.app
import textual.containers
import textual.screen
import textual.widgets

from . import async_client, auth_view, header


class _AuthTypeScreen(textual.screen.ModalScreen[str | None]):
    DEFAULT_CSS = """
    _AuthTypeScreen {
        align: center middle;
    }
    _AuthTypeScreen > VerticalGroup {
        width: auto;
        height: auto;
        padding: 1 2;
        background: $surface;
        border: thick $primary;
    }
    _AuthTypeScreen ListView {
        height: auto;
        width: auto;
        padding: 1 2;
    }
    _AuthTypeScreen ListItem {
        height: auto;
        width: auto;
    }
    """
    BINDINGS: typing.ClassVar = [("escape", "cancel", "Cancel")]

    def compose(self) -> textual.app.ComposeResult:
        with textual.containers.VerticalGroup() as container:
            container.border_title = "Auth type"
            yield textual.widgets.ListView(
                textual.widgets.ListItem(textual.widgets.Label("http_sig"), id="http_sig"),
                textual.widgets.ListItem(textual.widgets.Label("oidc"), id="oidc"),
                textual.widgets.ListItem(textual.widgets.Label("oauth2-github"), id="oauth2-github"),
            )

    def action_cancel(self) -> None:
        self.dismiss(None)

    @textual.on(textual.widgets.ListView.Selected)
    def _on_selected(self, event: textual.widgets.ListView.Selected) -> None:
        self.dismiss(event.item.id)


class _AuthParamsScreen(textual.screen.ModalScreen[dict | None]):
    DEFAULT_CSS = """
    _AuthParamsScreen {
        align: center middle;
    }
    _AuthParamsScreen > VerticalGroup {
        width: 60;
        height: auto;
        padding: 1 2;
        background: $surface;
        border: thick $primary;
    }
    """
    BINDINGS: typing.ClassVar = [("escape", "cancel", "Cancel")]

    def __init__(self, auth_type: str) -> None:
        super().__init__()
        self._type = auth_type

    def compose(self) -> textual.app.ComposeResult:
        with textual.containers.VerticalGroup() as container:
            container.border_title = f"New {self._type} auth"
            yield textual.widgets.Input(placeholder="name", id="name", compact=True)
            if self._type == "oidc":
                yield textual.widgets.Input(placeholder="issuer", id="issuer", compact=True)
                yield textual.widgets.Input(placeholder="client_id", id="client_id", compact=True)
                yield textual.widgets.Input(
                    placeholder="client_secret (optional)", id="client_secret", compact=True, password=True
                )
            elif self._type == "oauth2-github":
                yield textual.widgets.Input(placeholder="client_id", id="client_id", compact=True)
                yield textual.widgets.Input(
                    placeholder="client_secret", id="client_secret", compact=True, password=True
                )

    def action_cancel(self) -> None:
        self.dismiss(None)

    @textual.on(textual.widgets.Input.Submitted)
    def _on_submit(self) -> None:
        name = self.query_one("#name", textual.widgets.Input).value.strip()
        if not name:
            return
        body: dict = {"name": name, "type": self._type, "tags": []}
        if self._type == "oidc":
            issuer = self.query_one("#issuer", textual.widgets.Input).value.strip()
            client_id = self.query_one("#client_id", textual.widgets.Input).value.strip()
            if not issuer or not client_id:
                return
            oidc_params: dict = {"issuer": issuer, "client_id": client_id}
            secret = self.query_one("#client_secret", textual.widgets.Input).value.strip()
            if secret:
                oidc_params["client_secret"] = secret
            body["oidc_params"] = oidc_params
        elif self._type == "oauth2-github":
            client_id = self.query_one("#client_id", textual.widgets.Input).value.strip()
            client_secret = self.query_one("#client_secret", textual.widgets.Input).value.strip()
            if not client_id or not client_secret:
                return
            body["oauth2_params"] = {"client_id": client_id, "client_secret": client_secret}
        self.dismiss(body)


class AuthListScreen(textual.screen.Screen[None]):
    BINDINGS: typing.ClassVar = [
        ("enter", "view_auth", "View"),
        ("a", "add_auth", "Add"),
        ("d", "delete_auth", "Delete"),
        ("escape", "app.pop_screen", "Back"),
    ]

    def __init__(self, auth: async_client.AsyncClient) -> None:
        super().__init__()
        self._auth = auth
        self._auths: list = []

    def compose(self) -> textual.app.ComposeResult:
        yield header.AppHeader()
        yield textual.widgets.DataTable(cursor_type="row")
        yield textual.widgets.Footer(compact=True, show_command_palette=False)

    async def on_mount(self) -> None:
        table = self.query_one(textual.widgets.DataTable)
        table.add_columns("Name", "Type", "Enabled")
        self._auths = await self._auth.list_auths()
        self._populate_table(table)

    @textual.work
    async def on_screen_resume(self) -> None:
        self._auths = await self._auth.list_auths()
        self._populate_table(self.query_one(textual.widgets.DataTable))

    def _populate_table(self, table: textual.widgets.DataTable) -> None:
        table.clear(columns=False)
        for a in self._auths:
            table.add_row(a["name"], a["type"], str(a["is_enabled"]))

    @textual.on(textual.widgets.DataTable.RowSelected)
    def _on_row_selected(self) -> None:
        self.action_view_auth()

    def action_view_auth(self) -> None:
        if not self._auths:
            return
        table = self.query_one(textual.widgets.DataTable)
        a = self._auths[table.cursor_row]
        self.app.push_screen(auth_view.AuthViewScreen(self._auth, a))

    @textual.work
    async def action_add_auth(self) -> None:
        auth_type = await self.app.push_screen_wait(_AuthTypeScreen())
        if auth_type is None:
            return
        body = await self.app.push_screen_wait(_AuthParamsScreen(auth_type))
        if body is None:
            return
        response = await self._auth.post(self._auth.directory.auth, json=body)
        if response.status_code != 201:
            self.notify(response.json().get("title", "Failed to create auth"), severity="error")
            return
        a = response.json()
        self._auths.append(a)
        table = self.query_one(textual.widgets.DataTable)
        self._populate_table(table)
        table.move_cursor(row=len(self._auths) - 1)
        self.app.push_screen(auth_view.AuthViewScreen(self._auth, a))

    @textual.work
    async def action_delete_auth(self) -> None:
        if not self._auths:
            return
        table = self.query_one(textual.widgets.DataTable)
        index = table.cursor_row
        a = self._auths[index]
        response = await self._auth.delete(f"{self._auth.directory.auth}/{a['id']}")
        if response.status_code != 204:
            self.notify(response.json().get("title", "Failed to delete auth"), severity="error")
            return
        self._auths.pop(index)
        self._populate_table(table)
        self.notify(f"Auth '{a['name']}' deleted")
