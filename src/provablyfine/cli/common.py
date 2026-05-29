import argparse
import getpass
import os
import os.path
import sys
import traceback

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


def version_function(args: argparse.Namespace) -> None:
    print(__version__)


def _login_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.sync.Client(c, timeout=args.timeout)
    auth_name = args.auth or c.auth_name or "default"
    c.session_key = login.login(c, sc, auth_name, session_key_path=args.session_key)
    c.save(args.config)


def setup_login_subparser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--auth", default=None, help="Auth config name to use for login")
    parser.add_argument(
        "--session-key",
        default=None,
        help="Session key file. If none is provided, a new one is generated in SSH agent.",
    )
    parser.set_defaults(func=_login_function)


def do_main(binary_name: str, args: argparse.Namespace) -> None:
    log.setup(args.debug, log.filename(binary_name, args))

    try:
        args.func(args)
        exitcode = 0
    except client.exceptions.KeyExpired:
        sys.stderr.write(f'Your session has expired. You must "{binary_name} login".\n')
        exitcode = 2
    except client.exceptions.UI as e:
        sys.stderr.write(f"{e!s}\n")
        exitcode = 2
    except Exception:
        traceback.print_exc()
        exitcode = 1

    sys.exit(exitcode)
