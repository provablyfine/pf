import hashlib
import http.server
import secrets
import socket
import typing
import urllib.parse
import webbrowser

import requests
import textual
import textual.app
import textual.screen
import textual.widgets

from .. import base64url, client, jwk, ssh


def has_valid_session(config: client.Config) -> bool:
    if not config.session_key:
        return False
    try:
        agent = ssh.agent.Client()
        for identity in agent.list_identities():
            if identity.public_key.match_ssh_fingerprint(config.session_key):
                return True
    except Exception:
        pass
    return False


def http_sig_login(cfg: client.Config, api: client.Client) -> str:
    try:
        agent = ssh.agent.Client()
    except Exception:
        raise client.exceptions.UI("Unable to connect to SSH agent")
    session_key = jwk.Private.generate_ed25519()
    agent.add(session_key, comment="pf-session", lifetime=1800)
    fp = session_key.public().ssh_fingerprint()
    http_client = api.login_auth(account=cfg.account_key, session=fp)
    response = http_client.post(
        url=http_client.directory.login,
        json={"session_public_key": session_key.public().to_dict()},
    )
    if response.status_code != 204:
        raise client.exceptions.UI(f"Login failed: {response.text}")
    return fp


def oidc_login(api: client.Client, auth_name: str) -> str:
    try:
        agent = ssh.agent.Client()
    except Exception:
        raise client.exceptions.UI("Unable to connect to SSH agent")
    session_key = jwk.Private.generate_ed25519()
    agent.add(session_key, comment="pf-session", lifetime=1800)
    fp = session_key.public().ssh_fingerprint()

    response = api.no_auth.get(f"{api.directory.auth}/{auth_name}")
    if response.status_code != 200:
        raise client.exceptions.UI(f"Unable to read auth config: {response.text}")
    auth_public = response.json()
    params = auth_public["params"]

    discovery_resp = requests.get(f"{params['issuer']}/.well-known/openid-configuration", timeout=10)
    if discovery_resp.status_code != 200:
        raise client.exceptions.UI("Unable to fetch OIDC discovery document")
    discovery = discovery_resp.json()

    code_verifier = base64url.encode(secrets.token_bytes(32))
    code_challenge = base64url.encode(hashlib.sha256(code_verifier.encode()).digest())

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    redirect_uri = f"http://127.0.0.1:{port}/callback"

    auth_url = (
        f"{discovery['authorization_endpoint']}"
        f"?client_id={urllib.parse.quote(params['client_id'])}"
        f"&redirect_uri={urllib.parse.quote(redirect_uri)}"
        f"&response_type=code&scope=openid+email"
        f"&code_challenge={urllib.parse.quote(code_challenge)}&code_challenge_method=S256"
    )
    webbrowser.open(auth_url)

    code_holder: list[str] = []

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            if "code" in qs:
                code_holder.append(qs["code"][0])
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Login successful. You may close this tab.")

        def log_message(self, format, *args):
            pass

    http.server.HTTPServer(("127.0.0.1", port), _Handler).handle_request()
    if not code_holder:
        raise client.exceptions.UI("OIDC callback did not receive authorization code")

    token_data: dict = {
        "grant_type": "authorization_code",
        "code": code_holder[0],
        "code_verifier": code_verifier,
        "redirect_uri": redirect_uri,
        "client_id": params["client_id"],
    }
    if params.get("client_secret"):
        token_data["client_secret"] = params["client_secret"]
    token_resp = requests.post(discovery["token_endpoint"], data=token_data, timeout=10)
    if token_resp.status_code != 200:
        raise client.exceptions.UI(f"Unable to exchange code for token: {token_resp.text}")
    id_token = token_resp.json().get("id_token")
    if not id_token:
        raise client.exceptions.UI("Token response did not include id_token")

    session_http = api.session_auth(session=fp)
    response = session_http.post(
        url=session_http.directory.login_oidc,
        json={
            "auth_name": auth_public["name"],
            "id_token": id_token,
            "session_public_key": session_key.public().to_dict(),
        },
    )
    if response.status_code != 204:
        raise client.exceptions.UI(f"OIDC login failed: {response.text}")
    return fp


def oauth2_login(api: client.Client, auth_name: str) -> str:
    try:
        agent = ssh.agent.Client()
    except Exception:
        raise client.exceptions.UI("Unable to connect to SSH agent")
    session_key = jwk.Private.generate_ed25519()
    agent.add(session_key, comment="pf-session", lifetime=1800)
    fp = session_key.public().ssh_fingerprint()

    response = api.no_auth.get(f"{api.directory.auth}/{auth_name}")
    if response.status_code != 200:
        raise client.exceptions.UI(f"Unable to read auth config: {response.text}")
    auth_public = response.json()

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    client_redirect_uri = f"http://127.0.0.1:{port}/done"

    session_http = api.session_auth(session=fp)
    response = session_http.post(
        url=session_http.directory.login_oauth2_start,
        json={
            "auth_name": auth_public["name"],
            "session_public_key": session_key.public().to_dict(),
            "client_redirect_uri": client_redirect_uri,
        },
    )
    if response.status_code != 200:
        raise client.exceptions.UI(f"Unable to start OAuth2 login: {response.text}")
    webbrowser.open(response.json()["auth_url"])

    result: list[dict] = []

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            status = qs.get("status", ["error"])[0]
            reason = qs.get("reason", ["Unknown error"])[0]
            result.append({"status": status, "reason": reason})
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            msg = b"Login successful. You may close this tab."
            if status != "ok":
                msg = b"Login failed. You may close this tab."
            self.wfile.write(msg)

        def log_message(self, format, *args):
            pass

    http.server.HTTPServer(("127.0.0.1", port), _Handler).handle_request()
    if not result or result[0]["status"] != "ok":
        reason = result[0]["reason"] if result else "unknown"
        raise client.exceptions.UI(f"OAuth2 login failed: {reason}")
    return fp


def browser_login(api: client.Client, auth_name: str, auth_type: str) -> str:
    match auth_type:
        case "oidc":
            return oidc_login(api, auth_name)
        case "oauth2-github":
            return oauth2_login(api, auth_name)
        case _:
            raise client.exceptions.UI(f"Unsupported browser auth type: {auth_type}")


class ReloginScreen(textual.screen.Screen[None]):
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
        import asyncio

        auth_name = self._cfg.auth_name or "default"
        status = self.query_one("#status", textual.widgets.Label)

        try:
            resp = await asyncio.to_thread(lambda: self._api.no_auth.get(f"{self._api.directory.auth}/{auth_name}"))
        except client.exceptions.UI as e:
            self.notify(str(e), severity="error")
            return
        if resp.status_code != 200:
            self.notify(f"Auth config '{auth_name}' not found", severity="error")
            return
        auth_type = resp.json()["type"]

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
                    raise client.exceptions.UI(f"Unsupported auth type: {auth_type}")
            self._cfg.session_key = fp
            self._cfg.save(self._config_path)
            self.app.call_from_thread(self.app.exit)
        except client.exceptions.UI as e:
            self.notify(str(e), severity="error")
