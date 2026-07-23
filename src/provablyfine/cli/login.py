# Login policy
# ------------
# 'pf login' (and http_sig_login) is the authoritative auth path: it authenticates
# and saves the result to disk. Use it for interactive users (OIDC or http_sig).
#
# ensure_session() is the ephemeral auth path: it authenticates using an on-disk
# account key without saving anything. Use it for service-mode commands that
# re-login on every start. Callers must not call c.save() after ensure_session();
# Config.save() enforces this at runtime by raising if the config is marked ephemeral.

import getpass
import glob
import os
import sys

import provablyfine_client as pfc

from .. import browser_login, client, jwk, ssh


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
    raise pfc.exceptions.UI(
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
        raise pfc.exceptions.UI(f"Failed to load account key {private_path}: {e}") from e


def has_valid_session(c: client.Config) -> bool:
    return browser_login.has_valid_session(c)


def _select_role(
    roles: list[pfc.schemas.LoginRoleInfo],
    session_client: pfc.SessionClient,
    role: str | None = None,
) -> None:
    if len(roles) == 0:
        return
    if role is not None:
        try:
            role_id = int(role)
            matched = next((r for r in roles if r.id == role_id), None)
        except ValueError:
            matched = next((r for r in roles if r.name == role), None)
        if matched is None:
            available = ", ".join(r.name for r in roles)
            raise pfc.exceptions.UI(f"Role {role!r} not found. Available: {available}")
        session_client.update_session(matched.id)
        return
    if len(roles) == 1:
        session_client.update_session(roles[0].id)
        return
    for i, r in enumerate(roles, 1):
        print(f"  {i}. {r.name}")
    raw = input(f"Select role [1-{len(roles)}]: ").strip()
    try:
        idx = int(raw)
        if not 1 <= idx <= len(roles):
            raise ValueError
    except ValueError:
        raise pfc.exceptions.UI(f"Invalid choice: {raw!r}")
    session_client.update_session(roles[idx - 1].id)


def ensure_session(c: client.Config, factory: client.Factory) -> None:
    """Attempt an ephemeral http_sig login using the on-disk account key.

    Marks the config as ephemeral so c.save() will raise if called.
    For persistent login (interactive users), use 'pf login' instead.
    """
    if has_valid_session(c):
        return
    if not c.account_key_file:
        raise pfc.exceptions.UI("Not logged in. Run 'pf login' first.")
    key_file = c.account_key_file
    if "$" in key_file:
        key_file = os.path.expandvars(key_file)
    with open(key_file, "rb") as f:
        account_key = client.ssh_utils.load_private_key(f.read())
    session_key = jwk.Private.generate_ed25519()
    result = factory.account_from_keys(account_key, session_key).login_http_sig(session_key.public().to_dict())
    c.session_key_pem = session_key.to_openssh(passphrase=None).decode()
    c.session_key_fingerprint = None
    c.session_key_file = None
    c.session_expires_at = result.expires_at
    c.ephemeral = True
    session_client = factory.session_with_private_key(session_key)
    if c.role_id is not None:
        session_client.update_session(c.role_id)
    elif len(result.roles) == 1:
        session_client.update_session(result.roles[0].id)
    elif len(result.roles) > 1:
        raise pfc.exceptions.UI(
            "Unable to auto-select role for headless login: "
            f"{len(result.roles)} roles available. Set role_id in config."
        )


def http_sig_login(
    c: client.Config, sc: client.Factory, session_key_path: str | None = None, role: str | None = None
) -> None:
    """HTTP signature login. Mutates c with new session key fields."""
    if c.account_key_fingerprint is not None and not _agent_has_key(c.account_key_fingerprint):
        _agent_load_key(c.account_key_fingerprint)

    if session_key_path is not None:
        with open(session_key_path, "rb") as f:
            session_key = client.ssh_utils.load_private_key(f.read())
        c.session_key_fingerprint = None
        c.session_key_file = session_key_path
        c.session_key_pem = None
        result = sc.account_with_session_key(c, session_key).login_http_sig(session_key.public().to_dict())
        _select_role(result.roles, sc.session_with_private_key(session_key), role)
        return

    try:
        session_key, fingerprint = browser_login.generate_session_key()
        result = sc.account_with_session_key(c, session_key).login_http_sig(session_key.public().to_dict())
        c.session_key_fingerprint = fingerprint
        c.session_key_file = None
        c.session_key_pem = None
        _select_role(result.roles, sc.session_with_private_key(session_key), role)
        return
    except pfc.exceptions.UI:
        pass

    print("Warning: no SSH agent available. Session key will be stored as cleartext in the config file.")
    print("Store session key as cleartext? [Y/n]:", flush=True)
    answer = sys.stdin.readline().strip().lower()
    if answer not in ("", "y", "yes"):
        raise pfc.exceptions.UI("Aborted. Start an SSH agent and retry.")

    session_key = jwk.Private.generate_ed25519()
    pem = session_key.to_openssh(passphrase=None).decode()
    result = sc.account_with_session_key(c, session_key).login_http_sig(session_key.public().to_dict())
    c.session_key_fingerprint = None
    c.session_key_file = None
    c.session_key_pem = pem
    _select_role(result.roles, sc.session_with_private_key(session_key), role)


def oidc_login(c: client.Config, sc: client.Factory, auth_name: str, role: str | None = None) -> None:
    """OIDC login. Mutates c with new session key fields."""
    auth_public = sc.public().get_public_auth(auth_name, "cli")
    if not isinstance(auth_public.config, pfc.schemas.OidcConfig):
        raise pfc.exceptions.UI(f"Auth '{auth_name}' is not OIDC")

    session_key, session_fingerprint = browser_login.generate_session_key()
    print("Opening browser for OIDC login...")
    id_token = browser_login.oidc_flow(auth_public.config)
    result = sc.session_with_key(session_fingerprint).login_oidc(
        auth_name, "cli", id_token, session_key.public().to_dict()
    )
    c.session_key_fingerprint = session_fingerprint
    c.session_key_file = None
    c.session_key_pem = None
    _select_role(result.roles, sc.session_with_private_key(session_key), role)


def oidc_device_code_login(c: client.Config, sc: client.Factory, auth_name: str, role: str | None = None) -> None:
    """OIDC device code login. Mutates c with new session key fields."""
    auth_public = sc.public().get_public_auth(auth_name, "cli")
    if not isinstance(auth_public.config, pfc.schemas.OidcDeviceCodeConfig):
        raise pfc.exceptions.UI(f"Auth '{auth_name}' is not OIDC device code")
    session_key, session_fingerprint = browser_login.generate_session_key()
    id_token = browser_login.oidc_device_code_flow(auth_public.config)
    result = sc.session_with_key(session_fingerprint).login_oidc(
        auth_name, "cli", id_token, session_key.public().to_dict()
    )
    c.session_key_fingerprint = session_fingerprint
    c.session_key_file = None
    c.session_key_pem = None
    _select_role(result.roles, sc.session_with_private_key(session_key), role)


def login(
    c: client.Config,
    sc: client.Factory,
    auth_name: str,
    session_key_path: str | None = None,
    role: str | None = None,
) -> None:
    """Perform login based on server auth config. Mutates c with new session key fields."""
    auth_public = sc.public().get_public_auth(auth_name, "cli")
    match auth_public.config.type:
        case "http_sig":
            http_sig_login(c, sc, session_key_path, role)
        case "oidc":
            oidc_login(c, sc, auth_name, role)
        case "oidc-device-code":
            oidc_device_code_login(c, sc, auth_name, role)
        case _:
            raise pfc.exceptions.UI(f"Unsupported auth type: {auth_public.config.type}")
