from __future__ import annotations

import abc
import getpass
import glob
import logging
import os.path
import typing

import cryptography.hazmat.primitives.asymmetric.ed25519
import provablyfine_client as pfc
import requests

from .. import base64url, jwk, ssh
from . import configuration, ssh_utils

logger = logging.getLogger(__name__)

Signer = pfc.Signer
HmacSigner = pfc.HmacSigner


class PrivateSigner(pfc.Signer):
    @abc.abstractmethod
    def public_key(self) -> jwk.Public:
        pass


class FileSigner(PrivateSigner):
    def __init__(self, prefix: str, key: jwk.Private) -> None:
        super().__init__(prefix)
        self._key = key

    def public_key(self) -> jwk.Public:
        return self._key.public()

    def thumbprint(self) -> str:
        return self._key.thumbprint()

    def sign(self, data: bytes) -> bytes:
        key = self._key.to_crypto()
        assert isinstance(key, cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey)
        return key.sign(data)


class AgentSigner(PrivateSigner):
    def __init__(self, prefix: str, key: jwk.Public, path: str | None = None) -> None:
        super().__init__(prefix)
        self._key = key
        self._path = path

    def public_key(self) -> jwk.Public:
        return self._key

    def thumbprint(self) -> str:
        return self._key.thumbprint()

    def sign(self, data: bytes) -> bytes:
        fingerprint = self._key.ssh_fingerprint()
        ssh_agent = ssh.agent.Client(self._path)
        for identity in ssh_agent.list_identities():
            if identity.public_key.match_ssh_fingerprint(fingerprint):
                assert identity.public_key.type == jwk.KeyType.ED25519
                return ssh_agent.sign(identity, data, 0)
        raise pfc.exceptions.UI(f"Unable to find requested key={fingerprint}")


def hmac_signer(prefix: str, key: str) -> pfc.Signer:
    return pfc.HmacSigner(prefix, base64url.decode(key))


def _find_account_key_path(fingerprint: str) -> str | None:
    """Locate an on-disk private key file matching an account key fingerprint.

    Returns None if no matching file is found (e.g. --transient-key, whose
    key lives only in the real ssh-agent by design).
    """
    ssh_dir = os.path.expanduser("~/.ssh")
    for pub_path in sorted(glob.glob(os.path.join(ssh_dir, "*.pub"))):
        try:
            with open(pub_path, "rb") as f:
                pub = jwk.Public.from_openssh(f.read())
        except Exception:
            # Not every *.pub file in ~/.ssh is one of ours (or even parseable
            # by us, e.g. RSA/ECDSA keys) -- skip anything we can't read.
            logger.debug("Skipping unreadable/unparsable public key %s", pub_path, exc_info=True)
            continue
        if not pub.match_ssh_fingerprint(fingerprint):
            continue
        private_path = pub_path.removesuffix(".pub")
        if os.path.isfile(private_path):
            return private_path
    return None


def _lookup_agent_identity(fingerprint: str, path: str | None) -> jwk.Public | None:
    """Look up `fingerprint` among the identities served at `path` (the real
    ssh-agent when `path` is None). Returns None if reachable but the
    fingerprint isn't listed there.

    A connection failure (nothing listening at `path` at all) propagates as
    a raw `OSError` rather than being turned into a message here: `path`
    points at two very differently-behaved endpoints depending on the
    caller -- the real, always-there host ssh-agent for an account key, or
    pf's own session oracle, whose absence specifically means "log in
    again" -- and only the caller (`account_key_signer`/`session_key_signer`
    below) knows which, and so what to actually tell the user.
    """
    ssh_agent = ssh.agent.Client(path)
    for identity in ssh_agent.list_identities():
        if identity.comment == fingerprint or identity.public_key.match_ssh_fingerprint(fingerprint):
            if identity.public_key.type != jwk.KeyType.ED25519:
                raise pfc.exceptions.UI(f"Unsupported: {identity.public_key.type}")
            return identity.public_key
    return None


@ssh_utils.exception
def account_key_signer(identifier: str | None) -> PrivateSigner:
    """Resolve the account key from `identifier`: a config-supplied file
    path, or (if that's not a real path) a fingerprint to look up.
    """
    if identifier is None:
        raise pfc.exceptions.UI("Did you forget to login ?")
    if os.path.exists(identifier):
        return account_file_signer(identifier)
    key_path = _find_account_key_path(identifier)
    if key_path is not None:
        return account_file_signer(key_path)
    unreachable: OSError | None = None
    try:
        key = _lookup_agent_identity(identifier, path=None)
    except OSError as e:
        key, unreachable = None, e
    if key is None:
        raise pfc.exceptions.UI(
            f"Account key {identifier} not found on disk or in your ssh-agent."
            "If you lost it, you need to accept a new invitation."
        ) from unreachable
    return AgentSigner("account", key, path=None)


@ssh_utils.exception
def session_key_signer(identifier: str | None) -> PrivateSigner:
    """Resolve the session key from `identifier`: a config-supplied file
    path, or (if that's not a real path) a fingerprint to look up in pf's
    own peer-credential-gated oracle.
    """
    if identifier is None:
        raise pfc.exceptions.UI("Did you forget to login ?")
    if os.path.exists(identifier):
        return session_file_signer(identifier)
    path = ssh.oracle.session.current_socket_path()
    unreachable: OSError | None = None
    try:
        key = _lookup_agent_identity(identifier, path)
    except OSError as e:
        key, unreachable = None, e
    if key is None:
        raise pfc.exceptions.KeyExpired("session") from unreachable
    return AgentSigner("session", key, path)


def account_file_signer(path: str) -> PrivateSigner:
    """Load the account key from an on-disk file, prompting for a
    passphrase if it's encrypted.
    """
    with open(path, "rb") as f:
        data = f.read()
    try:
        key = ssh_utils.load_private_key(data, password=None)
    except TypeError:
        passphrase = getpass.getpass(f"Passphrase for {path}: ").encode()
        key = ssh_utils.load_private_key(data, password=passphrase)
    except pfc.exceptions.UI:
        raise pfc.exceptions.UI("Unable to parse data either as PEM or SSH format")
    if key.type != jwk.KeyType.ED25519:
        raise pfc.exceptions.UI(f"Unsupported: {key.type}")
    return FileSigner("account", key)


def session_file_signer(path: str) -> PrivateSigner:
    """Load the session key from an on-disk file."""
    with open(path, "rb") as f:
        data = f.read()
    try:
        key = ssh_utils.load_private_key(data, password=None)
    except TypeError as e:
        raise pfc.exceptions.UI(f"Session key {path} is passphrase-protected; session keys must not be") from e
    except pfc.exceptions.UI:
        raise pfc.exceptions.UI("Unable to parse data either as PEM or SSH format")
    if key.type != jwk.KeyType.ED25519:
        raise pfc.exceptions.UI(f"Unsupported: {key.type}")
    return FileSigner("session", key)


def pem_signer(prefix: str, pem: str) -> PrivateSigner:
    key = ssh_utils.load_private_key(pem.encode(), password=None)
    if key.type != jwk.KeyType.ED25519:
        raise pfc.exceptions.UI(f"Unsupported: {key.type}")
    return FileSigner(prefix, key)


class HttpClient:
    """Backward-compat HTTP wrapper used by TUI and CLI (raw URL-based access)."""

    def __init__(
        self,
        session: pfc.HttpSession,
        directory: pfc.Directory,
        auth: pfc.Auth | None = None,
    ) -> None:
        self._pf_session = session
        self._directory = directory
        self._auth = auth

    @property
    def directory(self) -> pfc.Directory:
        return self._directory

    def get(self, url: str, *, params: dict[str, typing.Any] | None = None) -> requests.Response:
        return self._pf_session.get(url, auth=self._auth, params=params)

    def post(self, url: str, *, json: typing.Any = None) -> requests.Response:
        return self._pf_session.post(url, auth=self._auth, json=json)

    def patch(self, url: str, *, json: typing.Any = None) -> requests.Response:
        return self._pf_session.patch(url, auth=self._auth, json=json)

    def delete(self, url: str) -> requests.Response:
        return self._pf_session.delete(url, auth=self._auth)

    def put(self, url: str, *, json: typing.Any = None) -> requests.Response:
        return self._pf_session.put(url, auth=self._auth, json=json)


class InvitationHttpClient(HttpClient):
    def __init__(
        self,
        session: pfc.HttpSession,
        directory: pfc.Directory,
        auth: pfc.Auth | None,
        account_public_key: jwk.Public,
    ) -> None:
        super().__init__(session, directory, auth)
        self._account_public_key = account_public_key

    @property
    def account_public_key(self) -> jwk.Public:
        return self._account_public_key


class Client:
    """HTTP client factory for JWK-based auth (used by CLI)."""

    def __init__(self, config: configuration.Config, timeout: float = 1.0) -> None:
        self._config = config
        self._pf_session = pfc.HttpSession(requests.Session(), timeout)
        self._pf_directory = pfc.Directory(config.directory_url, timeout)

    @property
    def config(self) -> configuration.Config:
        return self._config

    def session_auth(self, session: str | None) -> HttpClient:
        signer = session_key_signer(session)
        return HttpClient(self._pf_session, self._pf_directory, pfc.Auth([signer]))

    def session_auth_with_key(self, session: jwk.Private) -> HttpClient:
        auth = pfc.Auth([FileSigner("session", session)])
        return HttpClient(self._pf_session, self._pf_directory, auth)

    def login_auth(self, account: str | None, session: str | None) -> HttpClient:
        signers: list[pfc.Signer] = [
            account_key_signer(account),
            session_key_signer(session),
        ]
        return HttpClient(self._pf_session, self._pf_directory, pfc.Auth(signers))

    def invitation_auth_with_key(self, account: jwk.Private, invitation: str) -> InvitationHttpClient:
        account_signer = FileSigner("account", account)
        inv_signer = pfc.HmacSigner("invitation", base64url.decode(invitation))
        auth = pfc.Auth([inv_signer, account_signer])
        return InvitationHttpClient(self._pf_session, self._pf_directory, auth, account.public())
