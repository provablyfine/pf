import getpass
import glob
import os

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


def http_sig_login(c: client.Config, sc: client.Factory, session_key_path: str | None = None) -> str:
    """HTTP signature login. Returns session fingerprint. Caller updates config."""
    if c.account_key is not None and not os.path.exists(c.account_key) and not _agent_has_key(c.account_key):
        _agent_load_key(c.account_key)

    if session_key_path is None:
        session_key, session_fingerprint = browser_login.generate_session_key()
    else:
        with open(session_key_path, "rb") as f:
            data = f.read()
        try:
            session_key = client.ssh_utils.load_private_key(data)
        except ValueError:
            raise pfc.exceptions.UI("Unable to parse data either as PEM or SSH format")
        session_fingerprint = session_key_path

    sc.account(c.account_key, session_fingerprint).login_http_sig(session_key.public().to_dict())
    return session_fingerprint


def oidc_login(c: client.Config, sc: client.Factory, auth_name: str) -> str:
    """OIDC login. Returns session fingerprint. Caller updates config."""
    auth_public = sc.public().get_public_auth(auth_name)
    if not isinstance(auth_public.config, pfc.schemas.OidcConfig):
        raise pfc.exceptions.UI(f"Auth '{auth_name}' is not OIDC")

    session_key, session_fingerprint = browser_login.generate_session_key()
    print("Opening browser for OIDC login...")
    id_token = browser_login.oidc_flow(auth_public.config)
    sc.session_with_key(session_fingerprint).login_oidc(auth_name, id_token, session_key.public().to_dict())
    return session_fingerprint


def oidc_device_code_login(c: client.Config, sc: client.Factory, auth_name: str) -> str:
    """OIDC device code login. Returns session fingerprint. Caller updates config."""
    auth_public = sc.public().get_public_auth(auth_name)
    if not isinstance(auth_public.config, pfc.schemas.OidcDeviceCodeConfig):
        raise pfc.exceptions.UI(f"Auth '{auth_name}' is not OIDC device code")
    session_key, session_fingerprint = browser_login.generate_session_key()
    id_token = browser_login.oidc_device_code_flow(auth_public.config)
    sc.session_with_key(session_fingerprint).login_oidc(auth_name, id_token, session_key.public().to_dict())
    return session_fingerprint


def login(c: client.Config, sc: client.Factory, auth_name: str, session_key_path: str | None = None) -> str:
    """Perform login based on server auth config. Returns session fingerprint. Caller updates config."""
    auth_public = sc.public().get_public_auth(auth_name)
    match auth_public.config.type:
        case "http_sig":
            return http_sig_login(c, sc, session_key_path)
        case "oidc":
            return oidc_login(c, sc, auth_name)
        case "oidc-device-code":
            return oidc_device_code_login(c, sc, auth_name)
        case _:
            raise pfc.exceptions.UI(f"Unsupported auth type: {auth_public.config.type}")
