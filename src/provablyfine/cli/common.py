import argparse
import dataclasses
import getpass
import importlib.resources
import os
import os.path
import pathlib
import sys
import traceback
import urllib.parse

import provablyfine_client as pfc

from .. import __version__, client, jwk, log, ssh
from . import login

DEFAULT_CONFIG = os.path.join(os.path.expanduser("~"), ".config", "provablyfine", "config.json")


def generate_and_save_key() -> tuple[jwk.Private, str]:
    """Generate ed25519 key, prompt passphrase, save encrypted to ~/.ssh/, add to agent for 60s."""
    key = jwk.Private.generate_ed25519()
    fingerprint = key.public().ssh_fingerprint()

    safe = fingerprint.removeprefix("SHA256:").replace("/", "-").replace("+", "_")[:16]
    path = os.path.expanduser(f"~/.ssh/pf_{safe}")

    while True:
        pw = getpass.getpass(f"Passphrase for new key ({path}): ")
        pw2 = getpass.getpass("Confirm passphrase: ")
        if pw == pw2:
            break
        print("Passphrases do not match, try again.", flush=True)

    passphrase = pw.encode() if pw else None
    data = key.to_openssh(passphrase)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)

    print(f"Account key saved to {path}", flush=True)

    try:
        ssh_agent = ssh.agent.Client()
        ssh_agent.add(key, comment="pf-account", lifetime=60)
    except Exception:
        print(f"SSH agent unavailable; run: ssh-add {path}", flush=True)

    return key, fingerprint


def add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-c", "--config", help="configuration file. Default: %(default)s", default=DEFAULT_CONFIG)
    parser.add_argument("--timeout", default=1.0, help="Timeout for HTTP requests. Default: %(default)s")
    parser.add_argument("-d", "--debug", help="Debug level", action="count", default=0)
    parser.add_argument("--log-filename", help="Filename where logs will be written", default=None)
    parser.add_argument("--version", action="version", version=__version__)


def version_function(args: argparse.Namespace) -> None:
    print(__version__)


def _print_frpc_license() -> None:
    licenses = importlib.resources.files("provablyfine").joinpath("licenses")
    for filename, label in [("frpc-NOTICE", "NOTICE"), ("frpc-LICENSE", "LICENSE")]:
        p = pathlib.Path(str(licenses.joinpath(filename)))
        if p.is_file():
            print(f"--- frpc ({label}) ---")
            print(p.read_text())


def license_function(args: argparse.Namespace) -> None:
    print("provablyfine")
    print("Copyright (C) 2024 Mathieu Lacage <mathieu.lacage@cutebugs.net>")
    print("License: GNU Affero General Public License v3 (AGPL-3.0-only)")
    print("Full text: https://www.gnu.org/licenses/agpl-3.0.txt")
    print()
    print("This distribution includes frpc from fatedier/frp (Apache 2.0).")
    _print_frpc_license()


def setup_license_subparser(parser: argparse.ArgumentParser) -> None:
    parser.set_defaults(func=license_function)


def _ping_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.Factory(c, timeout=args.timeout).session()
    sc.ping()
    print("pong")


def setup_ping_subparser(parser: argparse.ArgumentParser) -> None:
    parser.set_defaults(func=_ping_function)


def _whoami_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.Factory(c, timeout=args.timeout).session()
    identity = sc.get_self()
    print(identity.name)


def setup_whoami_subparser(parser: argparse.ArgumentParser) -> None:
    parser.set_defaults(func=_whoami_function)


@dataclasses.dataclass
class Invitation:
    directory_url: str
    key: str | None
    auth_name: str | None
    role_id: int | None


def parse_invitation(invitation_url: str) -> Invitation:
    url = urllib.parse.urlsplit(invitation_url)
    qs = urllib.parse.parse_qs(url.query)
    invitation = qs.get("invitation")
    auth = qs.get("auth")
    auth_name = auth[0] if auth else None
    role = qs.get("role")
    role_id = int(role[0]) if role else None
    url_no_qs = url._replace(query="")
    directory_url = urllib.parse.urlunsplit(url_no_qs)
    return Invitation(
        directory_url=directory_url,
        key=None if not invitation else invitation[0],
        auth_name=auth_name,
        role_id=role_id,
    )


def _accept_function(args: argparse.Namespace) -> None:
    invitation = parse_invitation(args.invitation)
    c = client.Config(
        directory_url=invitation.directory_url,
        auth_name=invitation.auth_name,
    )
    sc = client.Factory(c, timeout=args.timeout)
    auths = sc.public().list_public_auths(client_type="cli")
    if len(auths) == 0:
        raise pfc.exceptions.UI("No auth configured for tenant")
    if invitation.auth_name is not None:
        auths = [a for a in auths if a.name == invitation.auth_name]
        if len(auths) == 0:
            raise pfc.exceptions.UI(f"No auth found matching name='{invitation.auth_name}'")
    if len(auths) == 1:
        auth = auths[0]
    else:
        assert len(auths) > 1
        for i, a in enumerate(auths, 1):
            print(f"  {i}. {a.name}")
        raw = input(f"Choose auth method [1-{len(auths)}]: ")
        try:
            idx = int(raw)
            if idx < 1 or idx > len(auths):
                raise ValueError
        except ValueError:
            raise pfc.exceptions.UI(f"Invalid choice: {raw!r}")
        auth = auths[idx - 1]
    if auth.type == "http_sig":
        if invitation.key is None:
            raise pfc.exceptions.UI("No invitation key found in URL")
        if args.key is None:
            _, account_key_id = generate_and_save_key()
            c.account_key_fingerprint = account_key_id
            c.account_key_file = None
        else:
            account_key_id = os.path.expandvars(args.key) if "$" in args.key else args.key
            if os.path.exists(account_key_id):
                c.account_key_fingerprint = None
                c.account_key_file = args.key
            else:
                c.account_key_fingerprint = account_key_id
                c.account_key_file = None
        sc.invitation(invitation.key, account_key_id).accept_invitation()
    c.auth_name = auth.name
    c.role_id = invitation.role_id
    c.save(args.config)


def _login_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.Factory(c, timeout=args.timeout)
    auth_name = args.auth or c.auth_name or "default"
    login.login(c, sc, auth_name, session_key_path=args.session_key)
    c.save(args.config)


def setup_login_subparser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--auth", default=None, help="Auth config name to use for login")
    parser.add_argument(
        "--session-key",
        default=None,
        help="Session key file. If none is provided, a new one is generated in SSH agent.",
    )
    parser.set_defaults(func=_login_function)


def setup_accept_subparser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--key", help="Private key to register", default=None)
    parser.add_argument("--invitation", help="Invitation you were given", required=True)
    parser.set_defaults(func=_accept_function)


def do_main(binary_name: str, args: argparse.Namespace) -> None:
    log.setup(args.debug, log.filename(binary_name, args))

    try:
        args.func(args)
        exitcode = 0
    except pfc.exceptions.KeyExpired:
        sys.stderr.write(f'Your session has expired. You must "{binary_name} login".\n')
        exitcode = 2
    except pfc.exceptions.UI as e:
        sys.stderr.write(f"{e!s}\n")
        exitcode = 2
    except Exception:
        traceback.print_exc()
        exitcode = 1

    sys.exit(exitcode)
