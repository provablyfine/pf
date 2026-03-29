import argparse
import hashlib
import http.server
import logging
import os
import os.path
import secrets
import sys
import traceback
import urllib.parse
import webbrowser

import requests
import requests.auth

from .. import base64url, client, jwk, ssh
from . import admin_cli, openssh_cli

logger = logging.getLogger(__name__)

_DEFAULT_CONFIG = os.path.join(os.path.expanduser("~"), ".config", "pf", "config.json")


def _config_function(args):
    response = requests.get(args.directory)
    if response.status_code != 200:
        raise client.exceptions.UI(f"Unable to read directory: {response.text}")
    c = client.Config(
        directory_url=args.directory,
        directory=response.json(),
    )
    c.save(args.config)


def _accept_function(args):
    c = client.Config.load(args.config)
    api = client.Client(c)
    auth = api.invitation_auth(account=args.key, invitation=args.invitation)
    response = auth.post(url=auth.directory.accept_invitation, json={"account_public_key": auth.public_key})
    if response.status_code != 204:
        raise client.exceptions.UI(f"Unable to accept invitation successfully: {response.text}")
    c.account_key = args.key
    c.save(args.config)


@client.ssh_utils.exception
def _do_http_sig_login(args, c, api):
    if args.session_key is None:
        try:
            ssh_agent = ssh.agent.Client()
        except Exception:
            raise client.exceptions.UI("Unable to connect to user's SSH agent")
        session_key = jwk.Private.generate_ed25519()
        ssh_agent.add(session_key, comment="pf-session", lifetime=1800)
        c.session_key = session_key.public().ssh_fingerprint()
    else:
        with open(args.session_key, "rb") as f:
            data = f.read()
        try:
            session_key = client.ssh_utils.load_private_key(data)
        except ValueError:
            raise client.exceptions.UI("Unable to parse data either as PEM or SSH format")
        c.session_key = args.session_key

    auth = api.login_auth(account=c.account_key, session=c.session_key)
    response = auth.post(url=auth.directory.login, json={"session_public_key": session_key.public().to_dict()})
    if response.status_code != 204:
        raise client.exceptions.UI(f"Unable to login successfully: {response.text}")
    c.save(args.config)


def _do_oidc_login(args, c, api, auth_public):
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
    c.session_key = session_key.public().ssh_fingerprint()

    # POST /auth/oidc/login signed with the new session key
    oidc_auth = api.session_auth(session=c.session_key)
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
    c.save(args.config)


def _do_oauth2_login(args, c, api, auth_public):
    import socket

    # Generate session key and add to SSH agent
    try:
        ssh_agent = ssh.agent.Client()
    except Exception:
        raise client.exceptions.UI("Unable to connect to user's SSH agent")
    session_key = jwk.Private.generate_ed25519()
    ssh_agent.add(session_key, comment="pf-session", lifetime=1800)
    c.session_key = session_key.public().ssh_fingerprint()

    # Bind a free local port for the completion redirect
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    client_redirect_uri = f"http://127.0.0.1:{port}/done"

    # Start OAuth2 flow on server
    oauth2_auth = api.session_auth(session=c.session_key)
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
    c.save(args.config)


@client.ssh_utils.exception
def _login_function(args):
    c = client.Config.load(args.config)
    api = client.Client(c)
    auth_name = args.auth or "default"

    # Discover auth config type
    response = api.no_auth.get(f"{api.directory.auth}/{auth_name}")
    if response.status_code == 404:
        raise client.exceptions.UI(f"Auth config '{auth_name}' not found")
    if response.status_code != 200:
        raise client.exceptions.UI(f"Unable to read auth config: {response.text}")
    auth_public = response.json()

    match auth_public["type"]:
        case "http_sig":
            _do_http_sig_login(args, c, api)
        case "oidc":
            _do_oidc_login(args, c, api, auth_public)
        case "oauth2-github":
            _do_oauth2_login(args, c, api, auth_public)
        case _:
            raise client.exceptions.UI(f"Unsupported auth type: {auth_public['type']}")


def _do_main(args):
    if args.debug > 0:
        match args.debug:
            case 3:
                level = logging.DEBUG
            case 2:
                level = logging.INFO
            case 1:
                level = logging.WARN
            case _:
                assert args.debug > 3
                level = logging.DEBUG

        logging.basicConfig(stream=sys.stdout, level=level)

    try:
        args.func(args)
        exitcode = 0
    except client.exceptions.UI as e:
        sys.stderr.write(f"{e!s}\n")
        exitcode = 2
    except Exception:
        traceback.print_exc()
        exitcode = 1

    sys.exit(exitcode)


def pfa():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--debug", help="Increase debugging level", action="count", default=0)
    parser.add_argument("-c", "--config", help="configuration file", default=_DEFAULT_CONFIG)
    admin_cli.add_subparsers(parser)

    args = parser.parse_args()

    _do_main(args)


def pf():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--debug", help="Increase debugging level", action="count", default=0)
    parser.add_argument("-c", "--config", help="configuration file", default=_DEFAULT_CONFIG)
    subparsers = parser.add_subparsers(required=True)

    config_parser = subparsers.add_parser("config", help="Create a configuration file")
    config_parser.add_argument(
        "--directory",
        default=os.getenv("PF_DIRECTORY_URL", "https://pf.provablyfine.net/pf/directory"),
        help="Directory to connect to. Default: %(default)s",
    )
    config_parser.set_defaults(func=_config_function)

    register_parser = subparsers.add_parser("accept", help="Accept an invitation")
    register_parser.add_argument("--key", help="Private key to register", required=True)
    register_parser.add_argument("--invitation", help="Invitation you were given", required=True)
    register_parser.set_defaults(func=_accept_function)

    login_parser = subparsers.add_parser("login", help="Login")
    login_parser.add_argument(
        "--session-key",
        default=None,
        help="Session key to associate with account. "
        "If none is provided, a new one is generated, "
        "stored in the user' SSH agent and its hash is "
        "saved in the configuration file",
    )
    login_parser.add_argument(
        "--auth",
        default=None,
        help="Auth config name to use for login. Defaults to 'default'.",
    )
    login_parser.set_defaults(func=_login_function)

    openssh_parser = subparsers.add_parser("openssh", help="OpenSSH integration")
    openssh_cli.add_subparsers(openssh_parser)

    args = parser.parse_args()

    _do_main(args)
