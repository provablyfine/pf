import dataclasses
import typing

import provablyfine_client as pfc
import textual
import textual.app
import textual.containers
import textual.screen
import textual.widgets

from . import auth_view, base, header


@dataclasses.dataclass
class _HttpSigParams:
    name: str


@dataclasses.dataclass
class _OidcParams:
    name: str
    issuer: str
    client_id: str
    client_secret: str | None


@dataclasses.dataclass
class _OAuth2Params:
    name: str
    client_id: str
    client_secret: str


_AuthParamsResult = _HttpSigParams | _OidcParams | _OAuth2Params


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


class _AuthParamsScreen(textual.screen.ModalScreen[_AuthParamsResult | None]):
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
        if self._type == "oidc":
            issuer = self.query_one("#issuer", textual.widgets.Input).value.strip()
            client_id = self.query_one("#client_id", textual.widgets.Input).value.strip()
            if not issuer or not client_id:
                return
            secret = self.query_one("#client_secret", textual.widgets.Input).value.strip()
            self.dismiss(_OidcParams(name=name, issuer=issuer, client_id=client_id, client_secret=secret or None))
        elif self._type == "oauth2-github":
            client_id = self.query_one("#client_id", textual.widgets.Input).value.strip()
            client_secret = self.query_one("#client_secret", textual.widgets.Input).value.strip()
            if not client_id or not client_secret:
                return
            self.dismiss(_OAuth2Params(name=name, client_id=client_id, client_secret=client_secret))
        else:
            self.dismiss(_HttpSigParams(name=name))


class AuthListScreen(base.Screen):
    BINDINGS: typing.ClassVar = [
        ("enter", "view_auth", "View"),
        ("a", "add_auth", "Add"),
        ("d", "delete_auth", "Delete"),
        ("escape", "app.pop_screen", "Back"),
    ]

    class _StrDataTable(textual.widgets.DataTable[str]):
        pass

    def __init__(self, auth: pfc.AsyncSessionClient) -> None:
        super().__init__()
        self._auth = auth
        self._auths: list[pfc.schemas.Auth] = []

    def compose(self) -> textual.app.ComposeResult:
        yield header.AppHeader()
        yield self._StrDataTable(cursor_type="row")
        yield textual.widgets.Footer(compact=True, show_command_palette=False)

    async def on_mount(self) -> None:
        table = self.query_one(self._StrDataTable)
        table.add_columns("Name", "Type", "Enabled")
        self._auths = (await self._auth.list_auths()).auths
        self._populate_table(table)

    @textual.work
    async def on_screen_resume(self) -> None:
        self._auths = (await self._auth.list_auths()).auths
        self._populate_table(self.query_one(self._StrDataTable))

    def _populate_table(self, table: "AuthListScreen._StrDataTable") -> None:
        table.clear(columns=False)
        for a in self._auths:
            table.add_row(a.name, a.config.type, str(a.is_enabled))

    @textual.on(textual.widgets.DataTable.RowSelected)
    def _on_row_selected(self) -> None:
        self.action_view_auth()

    def action_view_auth(self) -> None:
        if not self._auths:
            return
        table = self.query_one(self._StrDataTable)
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
        match body:
            case _HttpSigParams():
                a = await self._auth.create_auth_http_sig(body.name, "", [])
            case _OidcParams():
                a = await self._auth.create_auth_oidc(
                    body.name, "", [], body.issuer, body.client_id, body.client_secret
                )
            case _OAuth2Params():
                a = await self._auth.create_auth_oauth2_github(body.name, "", [], body.client_id, body.client_secret)
        self._auths.append(a)
        table = self.query_one(self._StrDataTable)
        self._populate_table(table)
        table.move_cursor(row=len(self._auths) - 1)
        self.app.push_screen(auth_view.AuthViewScreen(self._auth, a))

    @textual.work
    async def action_delete_auth(self) -> None:
        if not self._auths:
            return
        table = self.query_one(self._StrDataTable)
        index = table.cursor_row
        a = self._auths[index]
        await self._auth.delete_auth(a.id)
        self._auths.pop(index)
        self._populate_table(table)
        self.notify(f"Auth '{a.name}' deleted")
