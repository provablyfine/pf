import hashlib
import http.server
import secrets
import urllib.parse
import webbrowser

import requests

from .. import base64url, client, jwk, ssh


def has_valid_session(c: client.Config) -> bool:
    if not c.session_key:
        return False
    try:
        agent = ssh.agent.Client()
        for identity in agent.list_identities():
            if identity.public_key.match_ssh_fingerprint(c.session_key):
                return True
    except Exception:
        pass
    return False


def http_sig_login(
    api: client.Client, config: client.Config, account_key: str | None, session_key_path: str | None = None
):
    """Perform HTTP signature login.

    Args:
        api: Client API instance
        config: Config to update with session key
        account_key: Account key (filename or fingerprint) for signing
        session_key_path: Optional path to session key file. If None, generates new one in SSH agent.

    Returns:
        The session key fingerprint that was stored in config
    """
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

    auth = api.login_auth(account=account_key, session=session_fingerprint)
    response = auth.post(url=auth.directory.login, json={"session_public_key": session_key.public().to_dict()})
    if response.status_code != 204:
        raise client.exceptions.UI(f"Unable to login successfully: {response.text}")

    config.session_key = session_fingerprint
    return session_fingerprint


def oidc_login(api: client.Client, config: client.Config, auth_name: str):
    """Perform OIDC login.

    Args:
        api: Client API instance
        config: Config to update with session key
        auth_name: Name of the auth configuration to use

    Returns:
        The session key fingerprint that was stored in config
    """
    # Fetch auth config
    response = api.no_auth.get(f"{api.directory.public_auth}/{auth_name}")
    if response.status_code != 200:
        raise client.exceptions.UI(f"Unable to read auth config: {response.text}")
    auth_public = response.json()
    params = auth_public["params"]

    # Fetch OIDC discovery
    discovery_resp = requests.get(f"{params['issuer']}/.well-known/openid-configuration", timeout=10)
    if discovery_resp.status_code != 200:
        raise client.exceptions.UI("Unable to fetch OIDC discovery document")
    discovery = discovery_resp.json()
    authorization_endpoint = discovery["authorization_endpoint"]
    token_endpoint = discovery["token_endpoint"]

    # Generate PKCE code verifier and challenge
    code_verifier = base64url.encode(secrets.token_bytes(32))
    code_challenge = base64url.encode(hashlib.sha256(code_verifier.encode()).digest())

    # Bind a free local port for the redirect
    import socket

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    redirect_uri = f"http://127.0.0.1:{port}/callback"
    auth_url = (
        f"{authorization_endpoint}"
        f"?client_id={urllib.parse.quote(params['client_id'])}"
        f"&redirect_uri={urllib.parse.quote(redirect_uri)}"
        f"&response_type=code"
        f"&scope=openid+email"
        f"&code_challenge={urllib.parse.quote(code_challenge)}"
        f"&code_challenge_method=S256"
    )

    print("Opening browser for OIDC login...")
    webbrowser.open(auth_url)

    # Start local HTTP server to capture the authorization code
    code_holder: list[str] = []

    class CallbackHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)
            if "code" in params:
                code_holder.append(params["code"][0])
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Login successful. You may close this tab.")

        def log_message(self, format, *args):
            pass  # suppress server log output

    server = http.server.HTTPServer(("127.0.0.1", port), CallbackHandler)
    server.handle_request()
    server.server_close()

    if not code_holder:
        raise client.exceptions.UI("OIDC callback did not receive an authorization code")
    code = code_holder[0]

    # Exchange code for id_token
    token_data: dict = {
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": code_verifier,
        "redirect_uri": redirect_uri,
        "client_id": params["client_id"],
    }
    if params.get("client_secret"):
        token_data["client_secret"] = params["client_secret"]
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

    # POST /auth/oidc/login signed with the new session key
    oidc_auth = api.session_auth(session=session_fingerprint)
    response = oidc_auth.post(
        url=oidc_auth.directory.login_oidc,
        json={
            "auth_name": auth_public["name"],
            "id_token": id_token,
            "session_public_key": session_key.public().to_dict(),
        },
    )
    if response.status_code != 204:
        raise client.exceptions.UI(f"Unable to login via OIDC: {response.text}")

    config.session_key = session_fingerprint
    return session_fingerprint


def oauth2_login(api: client.Client, config: client.Config, auth_name: str):
    """Perform OAuth2 login (e.g., GitHub).

    Args:
        api: Client API instance
        config: Config to update with session key
        auth_name: Name of the auth configuration to use

    Returns:
        The session key fingerprint that was stored in config
    """
    import socket

    # Fetch auth config first
    response = api.no_auth.get(f"{api.directory.public_auth}/{auth_name}")
    if response.status_code != 200:
        raise client.exceptions.UI(f"Unable to read auth config: {response.text}")
    auth_public = response.json()

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
    oauth2_auth = api.session_auth(session=session_fingerprint)
    response = oauth2_auth.post(
        url=oauth2_auth.directory.login_oauth2_start,
        json={
            "auth_name": auth_public["name"],
            "session_public_key": session_key.public().to_dict(),
            "client_redirect_uri": client_redirect_uri,
        },
    )
    if response.status_code != 200:
        raise client.exceptions.UI(f"Unable to start OAuth2 login: {response.text}")

    print("Opening browser for OAuth2 login...")
    webbrowser.open(response.json()["auth_url"])

    # Wait for server to redirect browser back after completing the exchange
    result_holder: list[dict] = []

    class DoneHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
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

        def log_message(self, format, *args):
            pass

    http.server.HTTPServer(("127.0.0.1", port), DoneHandler).handle_request()

    if result_holder[0]["status"] != "ok":
        raise client.exceptions.UI(f"OAuth2 login failed: {result_holder[0]['reason']}")

    config.session_key = session_fingerprint
    return session_fingerprint


def login(
    api: client.Client, config: client.Config, auth_name: str, config_path: str, session_key_path: str | None = None
):
    """Perform login based on server auth config.

    Args:
        api: Client API instance
        config: Config to update with session key
        auth_name: Name of the auth configuration to use
        config_path: Path to save config after login
        session_key_path: Optional path to session key file (for http_sig only)

    Returns:
        The session key fingerprint
    """
    # Discover auth config type
    response = api.no_auth.get(f"{api.directory.public_auth}/{auth_name}")
    if response.status_code == 404:
        raise client.exceptions.UI(f"Auth config '{auth_name}' not found")
    if response.status_code != 200:
        raise client.exceptions.UI(f"Unable to read auth config: {response.text}")
    auth_public = response.json()

    match auth_public["config"]["type"]:
        case "http_sig":
            session_fingerprint = http_sig_login(api, config, config.account_key, session_key_path)
        case "oidc":
            session_fingerprint = oidc_login(api, config, auth_name)
        case "oauth2-github":
            session_fingerprint = oauth2_login(api, config, auth_name)
        case _:
            raise client.exceptions.UI(f"Unsupported auth type: {auth_public['type']}")

    config.save(config_path)
    return session_fingerprint
