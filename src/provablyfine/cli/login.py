import base64
import getpass
import glob
import hashlib
import http.server
import os
import secrets
import socket
import typing
import urllib.parse
import webbrowser

import requests

from .. import client, jwk, ssh


def _agent_has_key(key: str | None) -> bool:
    if not key:
        return False
    try:
        agent = ssh.agent.Client()
        for identity in agent.list_identities():
            if identity.public_key.match_ssh_fingerprint(key):
                return True
    except Exception:
        pass
    return False


def _find_key_filename(fingerprint: str) -> str:
    ssh_dir = os.path.expanduser("~/.ssh")
    for pub_path in sorted(glob.glob(os.path.join(ssh_dir, "*.pub"))):
        with open(pub_path, "rb") as f:
            pub = jwk.Public.from_openssh(f.read())
        if not pub.match_ssh_fingerprint(fingerprint):
            continue

        private_path = pub_path.removesuffix(".pub")
        if not os.path.isfile(private_path):
            continue
        return private_path
    raise client.exceptions.UI(
        f"Account key {fingerprint} not found in SSH agent or ~/.ssh/. Add your key file with 'ssh-add'."
    )


def _agent_load_key(account_key: str) -> None:
    private_path = _find_key_filename(account_key)
    try:
        with open(private_path, "rb") as f:
            data = f.read()
        try:
            key = client.ssh_utils.load_private_key(data, password=None)
        except TypeError:
            passphrase = getpass.getpass(f"Passphrase for {private_path}: ").encode()
            key = client.ssh_utils.load_private_key(data, password=passphrase)
        agent = ssh.agent.Client()
        agent.add(key, comment="pf-account", lifetime=60)
        return
    except Exception as e:
        raise client.exceptions.UI(f"Failed to load account key {private_path}: {e}") from e


def has_valid_session(c: client.Config) -> bool:
    return _agent_has_key(c.session_key)


def http_sig_login(c: client.Config, sc: client.sync.Client, session_key_path: str | None = None) -> str:
    """HTTP signature login. Returns session fingerprint. Caller updates config."""
    if c.account_key is not None and not os.path.exists(c.account_key) and not _agent_has_key(c.account_key):
        _agent_load_key(c.account_key)

    if session_key_path is None:
        try:
            ssh_agent = ssh.agent.Client()
        except Exception:
            raise client.exceptions.UI("Unable to connect to user's SSH agent")
        session_key = jwk.Private.generate_ed25519()
        ssh_agent.add(session_key, comment="pf-session", lifetime=1800)
        session_fingerprint = session_key.public().ssh_fingerprint()
    else:
        with open(session_key_path, "rb") as f:
            data = f.read()
        try:
            session_key = client.ssh_utils.load_private_key(data)
        except ValueError:
            raise client.exceptions.UI("Unable to parse data either as PEM or SSH format")
        session_fingerprint = session_key_path

    sc.login_http_sig(session_key.public().to_dict(), session_fingerprint)
    return session_fingerprint


def oidc_login(c: client.Config, sc: client.sync.Client, auth_name: str) -> str:
    """OIDC login. Returns session fingerprint. Caller updates config."""
    auth_public = sc.get_public_auth(auth_name)
    if not isinstance(auth_public.config, client.schemas.OidcConfig):
        raise client.exceptions.UI(f"Auth '{auth_name}' is not OIDC")
    oidc_config = auth_public.config

    # Fetch OIDC discovery
    discovery_resp = requests.get(f"{oidc_config.issuer}/.well-known/openid-configuration", timeout=10)
    if discovery_resp.status_code != 200:
        raise client.exceptions.UI("Unable to fetch OIDC discovery document")
    discovery = discovery_resp.json()
    authorization_endpoint = discovery["authorization_endpoint"]
    token_endpoint = discovery["token_endpoint"]

    # Generate PKCE code verifier and challenge
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8").rstrip("=")
    code_challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).decode("utf-8").rstrip("=")
    )

    # Start local HTTP server to capture the authorization code (bind first, before opening browser)
    code_holder: list[str] = []

    class CallbackHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)
            if "code" in params:
                code_holder.append(params["code"][0])
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Login successful. You may close this tab.")

        def log_message(self, format: str, *args: typing.Any) -> None:
            pass  # suppress server log output

    server = http.server.HTTPServer(("127.0.0.1", 0), CallbackHandler)
    server.timeout = 15
    port = server.server_port

    redirect_uri = f"http://127.0.0.1:{port}/callback"
    auth_url = (
        f"{authorization_endpoint}"
        f"?client_id={urllib.parse.quote(oidc_config.client_id)}"
        f"&redirect_uri={urllib.parse.quote(redirect_uri)}"
        f"&response_type=code"
        f"&scope=openid+email"
        f"&code_challenge={urllib.parse.quote(code_challenge)}"
        f"&code_challenge_method=S256"
    )

    print("Opening browser for OIDC login...")
    webbrowser.open(auth_url)

    server.handle_request()
    server.server_close()

    if not code_holder:
        raise client.exceptions.UI("OIDC callback did not receive an authorization code")
    code = code_holder[0]

    # Exchange code for id_token
    token_data: dict[str, typing.Any] = {
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": code_verifier,
        "redirect_uri": redirect_uri,
        "client_id": oidc_config.client_id,
    }
    if oidc_config.client_secret:
        token_data["client_secret"] = oidc_config.client_secret
    token_resp = requests.post(token_endpoint, data=token_data, timeout=10)
    if token_resp.status_code != 200:
        raise client.exceptions.UI(f"Unable to exchange code for token: {token_resp.text}")
    id_token = token_resp.json().get("id_token")
    if not id_token:
        raise client.exceptions.UI("Token response did not include id_token")

    # Generate session key and add to SSH agent
    try:
        ssh_agent = ssh.agent.Client()
    except Exception:
        raise client.exceptions.UI("Unable to connect to user's SSH agent")
    session_key = jwk.Private.generate_ed25519()
    ssh_agent.add(session_key, comment="pf-session", lifetime=1800)
    session_fingerprint = session_key.public().ssh_fingerprint()

    sc.login_oidc(auth_name, id_token, session_key.public().to_dict(), session_fingerprint)
    return session_fingerprint


def oauth2_login(c: client.Config, sc: client.sync.Client, auth_name: str) -> str:
    """OAuth2 login. Returns session fingerprint. Caller updates config."""
    auth_public = sc.get_public_auth(auth_name)
    if not isinstance(auth_public.config, client.schemas.OAuth2Config):
        raise client.exceptions.UI(f"Auth '{auth_name}' is not OAuth2")

    # Generate session key and add to SSH agent
    try:
        ssh_agent = ssh.agent.Client()
    except Exception:
        raise client.exceptions.UI("Unable to connect to user's SSH agent")
    session_key = jwk.Private.generate_ed25519()
    ssh_agent.add(session_key, comment="pf-session", lifetime=1800)
    session_fingerprint = session_key.public().ssh_fingerprint()

    # Bind a free local port for the completion redirect
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    client_redirect_uri = f"http://127.0.0.1:{port}/done"

    # Start OAuth2 flow on server
    auth_url = sc.login_oauth2_start(
        auth_name, session_key.public().to_dict(), session_fingerprint, client_redirect_uri
    )

    print("Opening browser for OAuth2 login...")
    webbrowser.open(auth_url)

    # Wait for server to redirect browser back after completing the exchange
    result_holder: list[dict[str, str]] = []

    class DoneHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(parsed.query)
            status = qs.get("status", ["error"])[0]
            reason = qs.get("reason", ["Unknown error"])[0]
            result_holder.append({"status": status, "reason": reason})
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            if status == "ok":
                self.wfile.write(b"Login successful. You may close this tab.")
            else:
                self.wfile.write(b"Login failed: " + reason.encode() + b". You may close this tab.")

        def log_message(self, format: str, *args: typing.Any) -> None:
            pass

    http.server.HTTPServer(("127.0.0.1", port), DoneHandler).handle_request()

    if result_holder[0]["status"] != "ok":
        raise client.exceptions.UI(f"OAuth2 login failed: {result_holder[0]['reason']}")

    return session_fingerprint


def login(c: client.Config, sc: client.sync.Client, auth_name: str, session_key_path: str | None = None) -> str:
    """Perform login based on server auth config. Returns session fingerprint. Caller updates config."""
    auth_public = sc.get_public_auth(auth_name)
    match auth_public.config.type:
        case "http_sig":
            return http_sig_login(c, sc, session_key_path)
        case "oidc":
            return oidc_login(c, sc, auth_name)
        case "oauth2-github":
            return oauth2_login(c, sc, auth_name)
        case _:
            raise client.exceptions.UI(f"Unsupported auth type: {auth_public.config.type}")
