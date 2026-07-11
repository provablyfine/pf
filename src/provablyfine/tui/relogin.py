import threading
import typing
import webbrowser

import provablyfine_client as pfc
import textual
import textual.app
import textual.containers
import textual.widgets

from .. import browser_login, client, jwk
from . import base


class _LoginCancelled(Exception):
    pass


def has_valid_session(config: client.Config) -> bool:
    return browser_login.has_valid_session(config)


class _RoleSelectScreen(base.ModalScreen[int | None]):
    BINDINGS: typing.ClassVar = [("escape", "cancel", "Cancel")]
    DEFAULT_CSS = """
    _RoleSelectScreen { align: center middle; }
    _RoleSelectScreen > VerticalGroup {
        width: 40; height: auto; background: $surface; border: thick $primary;
    }
    _RoleSelectScreen ListView { height: auto; max-height: 10; }
    """

    def __init__(self, roles: list[pfc.schemas.LoginRoleInfo]) -> None:
        super().__init__()
        self._roles = roles

    def compose(self) -> textual.app.ComposeResult:
        with textual.containers.VerticalGroup() as c:
            c.border_title = "Select Role"
            yield textual.widgets.ListView(
                *[textual.widgets.ListItem(textual.widgets.Label(r.name)) for r in self._roles]
            )

    def on_mount(self) -> None:
        self.query_one(textual.widgets.ListView).focus()

    def action_cancel(self) -> None:
        self.dismiss(None)

    @textual.on(textual.widgets.ListView.Selected)
    def _on_selected(self) -> None:
        index = self.query_one(textual.widgets.ListView).index
        if index is None or index >= len(self._roles):
            return
        self.dismiss(self._roles[index].id)


def _tui_select_role(
    roles: list[pfc.schemas.LoginRoleInfo],
    session_key: jwk.Private,
    api: client.Client,
    cfg: client.Config,
    screen: base.Screen | None = None,
) -> None:
    factory = client.Factory(api.config)
    session_client = factory.session_with_private_key(session_key)

    if len(roles) == 0:
        return

    if cfg.role_id is not None:
        session_client.update_session(cfg.role_id)
        return

    if len(roles) == 1:
        cfg.role_id = roles[0].id
        session_client.update_session(roles[0].id)
        return

    # Multiple roles
    if screen is not None:
        selected: list[int | None] = []
        done = threading.Event()

        def _on_role_selected(role_id: int | None) -> None:
            selected.append(role_id)
            done.set()

        def _push() -> None:
            screen.app.push_screen(_RoleSelectScreen(roles), callback=_on_role_selected)

        screen.app.call_from_thread(_push)
        done.wait()
        role_id = selected[0] if selected else None
        if role_id is None:
            raise _LoginCancelled()
    else:
        role_id = roles[0].id

    cfg.role_id = role_id
    session_client.update_session(role_id)


def http_sig_login(cfg: client.Config, api: client.Client, screen: base.Screen | None = None) -> str:
    session_key, fp = browser_login.generate_session_key()
    account = cfg.account_key_fingerprint or cfg.account_key_file
    http_client = api.login_auth(account=account, session=fp)
    response = http_client.post(
        url=http_client.directory.login,
        json={"session_public_key": session_key.public().to_dict()},
    )
    if response.status_code != 200:
        raise pfc.exceptions.UI(f"Login failed: {response.text}")
    roles = [pfc.schemas.LoginRoleInfo(**r) for r in response.json().get("roles", [])]
    _tui_select_role(roles, session_key, api, cfg, screen)
    return fp


def oidc_login(api: client.Client, auth_name: str, cfg: client.Config, screen: base.Screen | None = None) -> str:
    session_key, fp = browser_login.generate_session_key()
    auth_public = client.Factory(api.config).public().get_public_auth(auth_name, "cli")
    if not isinstance(auth_public.config, pfc.schemas.OidcConfig):
        raise pfc.exceptions.UI(f"Auth '{auth_name}' is not OIDC")
    id_token = browser_login.oidc_flow(auth_public.config)
    session_http = api.session_auth(session=fp)
    response = session_http.post(
        url=session_http.directory.login_oidc,
        json={
            "auth_name": auth_public.name,
            "client_type": "cli",
            "id_token": id_token,
            "session_public_key": session_key.public().to_dict(),
        },
    )
    if response.status_code != 200:
        raise pfc.exceptions.UI(f"OIDC login failed: {response.text}")
    roles = [pfc.schemas.LoginRoleInfo(**r) for r in response.json().get("roles", [])]
    _tui_select_role(roles, session_key, api, cfg, screen)
    return fp


def oidc_device_code_login(
    api: client.Client,
    auth_name: str,
    cfg: client.Config,
    screen: base.Screen | None = None,
    on_code: typing.Callable[[str, str], None] | None = None,
) -> str:
    session_key, fp = browser_login.generate_session_key()
    auth_public = client.Factory(api.config).public().get_public_auth(auth_name, "cli")
    if not isinstance(auth_public.config, pfc.schemas.OidcDeviceCodeConfig):
        raise pfc.exceptions.UI(f"Auth '{auth_name}' is not OIDC device code")
    id_token = browser_login.oidc_device_code_flow(auth_public.config, display=on_code)
    session_http = api.session_auth(session=fp)
    response = session_http.post(
        url=session_http.directory.login_oidc,
        json={
            "auth_name": auth_public.name,
            "client_type": "cli",
            "id_token": id_token,
            "session_public_key": session_key.public().to_dict(),
        },
    )
    if response.status_code != 200:
        raise pfc.exceptions.UI(f"OIDC device code login failed: {response.text}")
    roles = [pfc.schemas.LoginRoleInfo(**r) for r in response.json().get("roles", [])]
    _tui_select_role(roles, session_key, api, cfg, screen)
    return fp


def login(
    api: client.Client,
    auth_name: str,
    auth_type: str,
    cfg: client.Config,
    screen: base.Screen | None = None,
) -> str:
    match auth_type:
        case "oidc":
            return oidc_login(api, auth_name, cfg, screen)
        case "oidc-device-code":
            return oidc_device_code_login(api, auth_name, cfg, screen)
        case _:
            raise pfc.exceptions.UI(f"Unsupported browser auth type: {auth_type}")


class ReloginScreen(base.Screen):
    BINDINGS: typing.ClassVar = [("escape", "quit", "Cancel")]
    DEFAULT_CSS = """
    ReloginScreen #status {
        margin: 1 2;
    }
    """

    def __init__(self, cfg: client.Config, api: client.Client, config_path: str) -> None:
        super().__init__()
        self._cfg = cfg
        self._api = api
        self._config_path = config_path

    def compose(self) -> textual.app.ComposeResult:
        auth_name = self._cfg.auth_name or "default"
        yield textual.widgets.Label(f"Reconnecting via {auth_name}…", id="status")
        yield textual.widgets.Footer(compact=True, show_command_palette=False)

    def action_quit(self) -> None:
        self.app.exit()

    @textual.work
    async def on_mount(self) -> None:
        auth_name = self._cfg.auth_name or "default"
        status = self.query_one("#status", textual.widgets.Label)

        try:
            auth_public = await client.Factory(self._api.config).async_public().get_public_auth(auth_name, "cli")
        except pfc.exceptions.UI as e:
            self.notify(str(e), severity="error")
            return
        auth_type = auth_public.config.type

        if auth_type not in ("http_sig", "oidc-device-code"):
            status.update(f"Opening browser for {auth_name}…")

        self._login(auth_name, auth_type)

    @textual.work(thread=True)
    def _login(self, auth_name: str, auth_type: str) -> None:
        try:
            match auth_type:
                case "http_sig":
                    fp = http_sig_login(self._cfg, self._api, screen=self)
                case "oidc":
                    fp = oidc_login(self._api, auth_name, self._cfg, screen=self)
                case "oidc-device-code":

                    def _show(user_code: str, uri: str) -> None:
                        webbrowser.open(uri)

                        def _update() -> None:
                            self.query_one("#status", textual.widgets.Label).update(f"Visit {uri}\nCode: {user_code}")

                        self.app.call_from_thread(_update)

                    fp = oidc_device_code_login(self._api, auth_name, self._cfg, screen=self, on_code=_show)
                case _:
                    raise pfc.exceptions.UI(f"Unsupported auth type: {auth_type}")
            self._cfg.session_key_fingerprint = fp
            self._cfg.session_key_file = None
            self._cfg.session_key_pem = None
            self.app.call_from_thread(self.app.exit)
        except _LoginCancelled:
            self.app.call_from_thread(self.app.exit)
        except pfc.exceptions.UI as e:
            self.notify(str(e), severity="error")
