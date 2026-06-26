import hashlib
import http.server
import secrets
import time
import typing
import urllib.parse
import webbrowser

import provablyfine_client as pfc
import requests

from . import base64url, client, jwk, ssh


def has_valid_session(config: client.Config) -> bool:
    if config.session_key_file is not None or config.session_key_pem is not None:
        return True
    if not config.session_key_fingerprint:
        return False
    try:
        agent = ssh.agent.Client()
        for identity in agent.list_identities():
            if identity.public_key.match_ssh_fingerprint(config.session_key_fingerprint):
                return True
    except Exception:
        pass
    return False


def generate_session_key() -> tuple[jwk.Private, str]:
    try:
        agent = ssh.agent.Client()
    except Exception:
        raise pfc.exceptions.UI("Unable to connect to user's SSH agent")
    session_key = jwk.Private.generate_ed25519()
    agent.add(session_key, comment="pf-session", lifetime=1800)
    return session_key, session_key.public().ssh_fingerprint()


def oidc_flow(oidc_config: pfc.schemas.OidcConfig) -> str:
    """Run OIDC browser flow. Returns id_token. Caller opens browser message if desired."""
    discovery_resp = requests.get(f"{oidc_config.issuer}/.well-known/openid-configuration", timeout=10)
    if discovery_resp.status_code != 200:
        raise pfc.exceptions.UI("Unable to fetch OIDC discovery document")
    discovery = discovery_resp.json()

    code_verifier = base64url.encode(secrets.token_bytes(32))
    code_challenge = base64url.encode(hashlib.sha256(code_verifier.encode()).digest())

    code_holder: list[str] = []

    class _CallbackHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            if "code" in qs:
                code_holder.append(qs["code"][0])
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Login successful. You may close this tab.")

        def log_message(self, format: str, *args: typing.Any) -> None:
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), _CallbackHandler)
    server.timeout = 15
    port = server.server_port

    redirect_uri = f"http://127.0.0.1:{port}/callback"
    auth_url = (
        f"{discovery['authorization_endpoint']}"
        f"?client_id={urllib.parse.quote(oidc_config.client_id)}"
        f"&redirect_uri={urllib.parse.quote(redirect_uri)}"
        f"&response_type=code&scope=openid+email"
        f"&code_challenge={urllib.parse.quote(code_challenge)}&code_challenge_method=S256"
    )
    webbrowser.open(auth_url)

    server.handle_request()
    server.server_close()

    if not code_holder:
        raise pfc.exceptions.UI("OIDC callback did not receive an authorization code")

    token_data: dict[str, str] = {
        "grant_type": "authorization_code",
        "code": code_holder[0],
        "code_verifier": code_verifier,
        "redirect_uri": redirect_uri,
        "client_id": oidc_config.client_id,
    }
    if oidc_config.client_secret:
        token_data["client_secret"] = oidc_config.client_secret
    token_resp = requests.post(discovery["token_endpoint"], data=token_data, timeout=10)
    if token_resp.status_code != 200:
        raise pfc.exceptions.UI(f"Unable to exchange code for token: {token_resp.text}")
    id_token = token_resp.json().get("id_token")
    if not id_token:
        raise pfc.exceptions.UI("Token response did not include id_token")
    return id_token


def oidc_device_code_flow(
    config: pfc.schemas.OidcDeviceCodeConfig,
    display: typing.Callable[[str, str], None] | None = None,
) -> str:
    """Run OIDC device code flow. Returns id_token."""
    discovery_resp = requests.get(f"{config.issuer}/.well-known/openid-configuration", timeout=10)
    if discovery_resp.status_code != 200:
        raise pfc.exceptions.UI("Unable to fetch OIDC discovery document")
    discovery = discovery_resp.json()

    device_endpoint = discovery.get("device_authorization_endpoint")
    if not device_endpoint:
        raise pfc.exceptions.UI("OIDC provider does not support device code flow")

    data: dict[str, str] = {"client_id": config.client_id, "scope": "openid email"}
    if config.client_secret:
        data["client_secret"] = config.client_secret
    device_resp = requests.post(device_endpoint, data=data, timeout=10)
    if device_resp.status_code != 200:
        raise pfc.exceptions.UI(f"Device authorization failed: {device_resp.text}")
    device = device_resp.json()

    user_code: str = device["user_code"]
    verification_uri: str = device.get("verification_uri_complete") or device["verification_uri"]
    expires_in = int(device.get("expires_in", 300))
    interval = int(device.get("interval", 5))

    if display:
        display(user_code, verification_uri)
    else:
        print(f"Open {verification_uri}")
        print(f"Enter code: {user_code}")

    token_data: dict[str, str] = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": device["device_code"],
        "client_id": config.client_id,
    }
    if config.client_secret:
        token_data["client_secret"] = config.client_secret

    deadline = time.time() + expires_in
    while time.time() < deadline:
        time.sleep(interval)
        token_resp = requests.post(discovery["token_endpoint"], data=token_data, timeout=10)
        if token_resp.status_code == 200:
            id_token = token_resp.json().get("id_token")
            if not id_token:
                raise pfc.exceptions.UI("Token response did not include id_token")
            return id_token
        error = token_resp.json().get("error", "")
        if error == "slow_down":
            interval += 5
        elif error != "authorization_pending":
            raise pfc.exceptions.UI(f"Device code flow failed: {error}")
    raise pfc.exceptions.UI("Device code flow timed out")
