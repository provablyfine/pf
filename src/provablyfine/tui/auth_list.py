import dataclasses
import typing

import provablyfine_client as pfc
import textual
import textual.app
import textual.containers
import textual.widgets

from . import auth_view, base


@dataclasses.dataclass
class _HttpSigParams:
    name: str
    client_type: str


@dataclasses.dataclass
class _OidcParams:
    auth_type: str
    name: str
    client_type: str
    issuer: str
    client_id: str
    # Empty means the flow needs no client authentication.
    client_secret: str
    require_email_verified: bool


_AuthParamsResult = _HttpSigParams | _OidcParams

# Auth configs that talk to an identity provider. They all ask for the same fields.
_OIDC_TYPES = ("oidc", "oidc-device-code", "oidc-secret-device-code")


class _AuthTypeScreen(base.ModalScreen[str | None]):
    DEFAULT_CSS = """
    _AuthTypeScreen > VerticalGroup {
        width: auto;
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
                textual.widgets.ListItem(textual.widgets.Label("oidc-device-code"), id="oidc-device-code"),
                textual.widgets.ListItem(
                    textual.widgets.Label("oidc-secret-device-code"), id="oidc-secret-device-code"
                ),
            )

    def action_cancel(self) -> None:
        self.dismiss(None)

    @textual.on(textual.widgets.ListView.Selected)
    def _on_selected(self, event: textual.widgets.ListView.Selected) -> None:
        self.dismiss(event.item.id)


class _AuthParamsScreen(base.ModalScreen[_AuthParamsResult | None]):
    DEFAULT_CSS = """
    _AuthParamsScreen > VerticalGroup {
        width: 60;
    }
    """
    BINDINGS: typing.ClassVar = [("escape", "cancel", "Cancel")]

    def __init__(self, auth_type: str) -> None:
        super().__init__()
        self._type = auth_type

    def compose(self) -> textual.app.ComposeResult:
        with textual.containers.VerticalGroup() as container:
            container.border_title = f"New {self._type} auth"
            yield base.Input(placeholder="Name", id="name", compact=True)
            if self._type == "oidc-secret-device-code":
                # A client secret only ever belongs to a cli client.
                yield base.Input("cli", id="client_type", compact=True, disabled=True)
            else:
                yield base.Input(placeholder="Client type (cli or web)", id="client_type", compact=True)
            if self._type in _OIDC_TYPES:
                yield base.Input(placeholder="Issuer", id="issuer", compact=True)
                yield base.Input(placeholder="Client ID", id="client_id", compact=True)
                optional = "" if self._type == "oidc-secret-device-code" else " (optional)"
                yield base.Input(
                    placeholder=f"Client secret{optional}", id="client_secret", compact=True, password=True
                )
                yield textual.widgets.Checkbox(
                    "Require verified email", value=True, id="require_email_verified", compact=True
                )

    def action_cancel(self) -> None:
        self.dismiss(None)

    @textual.on(textual.widgets.Input.Submitted)
    def _on_submit(self) -> None:
        name = self.query_one("#name", textual.widgets.Input).value.strip()
        if not name:
            return
        client_type = self.query_one("#client_type", textual.widgets.Input).value.strip()
        if client_type not in ("cli", "web"):
            return
        if self._type in _OIDC_TYPES:
            issuer = self.query_one("#issuer", textual.widgets.Input).value.strip()
            client_id = self.query_one("#client_id", textual.widgets.Input).value.strip()
            if not issuer or not client_id:
                return
            secret = self.query_one("#client_secret", textual.widgets.Input).value.strip()
            if self._type == "oidc-secret-device-code" and not secret:
                self.notify("This auth type requires a client secret", severity="error")
                return
            require_email_verified = self.query_one("#require_email_verified", textual.widgets.Checkbox).value
            self.dismiss(
                _OidcParams(
                    auth_type=self._type,
                    name=name,
                    client_type=client_type,
                    issuer=issuer,
                    client_id=client_id,
                    client_secret=secret,
                    require_email_verified=require_email_verified,
                )
            )
        else:
            self.dismiss(_HttpSigParams(name=name, client_type=client_type))


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
        yield self._StrDataTable(cursor_type="row")
        yield textual.widgets.Label("No auths — add one with 'a'", id="auths-placeholder")
        yield textual.widgets.Footer(compact=True, show_command_palette=False)

    async def on_mount(self) -> None:
        table = self.query_one(self._StrDataTable)
        table.add_columns("Name", "Client Type", "Type", "Enabled")
        self._auths = (await self._auth.list_auths()).auths
        self._populate_table(table)

    @textual.work
    async def on_screen_resume(self) -> None:
        self._auths = (await self._auth.list_auths()).auths
        self._populate_table(self.query_one(self._StrDataTable))

    def _populate_table(self, table: "AuthListScreen._StrDataTable") -> None:
        table.clear(columns=False)
        for a in self._auths:
            table.add_row(a.name, a.client_type, a.config.type, "yes" if a.is_enabled else "no")
        self.query_one("#auths-placeholder").display = not bool(self._auths)

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
                a = await self._auth.create_auth_http_sig(body.name, body.client_type, "")
            case _OidcParams(auth_type="oidc"):
                a = await self._auth.create_auth_oidc(
                    body.name,
                    body.client_type,
                    "",
                    body.issuer,
                    body.client_id,
                    body.client_secret or None,
                    body.require_email_verified,
                )
            case _OidcParams(auth_type="oidc-device-code"):
                a = await self._auth.create_auth_oidc_device_code(
                    body.name,
                    body.client_type,
                    "",
                    body.issuer,
                    body.client_id,
                    body.require_email_verified,
                )
            case _OidcParams(auth_type="oidc-secret-device-code"):
                a = await self._auth.create_auth_oidc_secret_device_code(
                    body.name,
                    body.client_type,
                    "",
                    body.issuer,
                    body.client_id,
                    body.client_secret,
                    body.require_email_verified,
                )
            case _:
                assert False, body
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
