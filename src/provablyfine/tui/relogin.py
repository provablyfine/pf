import socket
import typing
import webbrowser

import textual
import textual.app
import textual.widgets
import provablyfine_client as pfc

from .. import browser_login, client
from . import base


def has_valid_session(config: client.Config) -> bool:
    return browser_login.has_valid_session(config)


def http_sig_login(cfg: client.Config, api: client.Client) -> str:
    session_key, fp = browser_login.generate_session_key()
    http_client = api.login_auth(account=cfg.account_key, session=fp)
    response = http_client.post(
        url=http_client.directory.login,
        json={"session_public_key": session_key.public().to_dict()},
    )
    if response.status_code != 204:
        raise pfc.exceptions.UI(f"Login failed: {response.text}")
    return fp


def oidc_login(api: client.Client, auth_name: str) -> str:
    session_key, fp = browser_login.generate_session_key()
    sync_client = client.sync.Client(api.config)
    auth_public = sync_client.get_public_auth(auth_name)
    if not isinstance(auth_public.config, client.schemas.OidcConfig):
        raise pfc.exceptions.UI(f"Auth '{auth_name}' is not OIDC")
    id_token = browser_login.oidc_flow(auth_public.config)
    session_http = api.session_auth(session=fp)
    response = session_http.post(
        url=session_http.directory.login_oidc,
        json={
            "auth_name": auth_public.name,
            "id_token": id_token,
            "session_public_key": session_key.public().to_dict(),
        },
    )
    if response.status_code != 204:
        raise pfc.exceptions.UI(f"OIDC login failed: {response.text}")
    return fp


def oauth2_login(api: client.Client, auth_name: str) -> str:
    session_key, fp = browser_login.generate_session_key()
    sync_client = client.sync.Client(api.config)
    auth_public = sync_client.get_public_auth(auth_name)

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    client_redirect_uri = f"http://127.0.0.1:{port}/done"

    session_http = api.session_auth(session=fp)
    response = session_http.post(
        url=session_http.directory.login_oauth2_start,
        json={
            "auth_name": auth_public.name,
            "session_public_key": session_key.public().to_dict(),
            "client_redirect_uri": client_redirect_uri,
        },
    )
    if response.status_code != 200:
        raise pfc.exceptions.UI(f"Unable to start OAuth2 login: {response.text}")
    webbrowser.open(response.json()["auth_url"])
    browser_login.oauth2_callback(port)
    return fp


def login(api: client.Client, auth_name: str, auth_type: str) -> str:
    match auth_type:
        case "oidc":
            return oidc_login(api, auth_name)
        case "oauth2-github":
            return oauth2_login(api, auth_name)
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

        aio_client = client.aio.Client(self._api.config)
        try:
            auth_public = await aio_client.get_public_auth(auth_name)
        except pfc.exceptions.UI as e:
            self.notify(str(e), severity="error")
            return
        auth_type = auth_public.config.type

        if auth_type != "http_sig":
            status.update(f"Opening browser for {auth_name}…")

        self._login(auth_name, auth_type)

    @textual.work(thread=True)
    def _login(self, auth_name: str, auth_type: str) -> None:
        try:
            match auth_type:
                case "http_sig":
                    fp = http_sig_login(self._cfg, self._api)
                case "oidc":
                    fp = oidc_login(self._api, auth_name)
                case "oauth2-github":
                    fp = oauth2_login(self._api, auth_name)
                case _:
                    raise pfc.exceptions.UI(f"Unsupported auth type: {auth_type}")
            self._cfg.session_key = fp
            self._cfg.save(self._config_path)
            self.app.call_from_thread(self.app.exit)
        except pfc.exceptions.UI as e:
            self.notify(str(e), severity="error")
