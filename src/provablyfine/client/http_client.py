from __future__ import annotations

import abc
import getpass
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
    def __init__(self, prefix: str, key: jwk.Public) -> None:
        super().__init__(prefix)
        self._key = key

    def public_key(self) -> jwk.Public:
        return self._key

    def thumbprint(self) -> str:
        return self._key.thumbprint()

    def sign(self, data: bytes) -> bytes:
        fingerprint = self._key.ssh_fingerprint()
        ssh_agent = ssh.agent.Client()
        for identity in ssh_agent.list_identities():
            if identity.public_key.match_ssh_fingerprint(fingerprint):
                assert identity.public_key.type == jwk.KeyType.ED25519
                return ssh_agent.sign(identity, data, 0)
        raise pfc.exceptions.UI(f"Unable to find requested key={fingerprint}")


def hmac_signer(prefix: str, key: str) -> pfc.Signer:
    return pfc.HmacSigner(prefix, base64url.decode(key))


@ssh_utils.exception
def private_key_signer(prefix: str, filename: str | None) -> PrivateSigner:
    if filename is None:
        raise pfc.exceptions.UI("Did you forget to login ?")

    if os.path.exists(filename):
        with open(filename, "rb") as f:
            data = f.read()
        try:
            key = ssh_utils.load_private_key(data, password=None)
        except TypeError:
            passphrase = getpass.getpass(f"Passphrase for {filename}: ").encode()
            key = ssh_utils.load_private_key(data, password=passphrase)
            lifetime = 60 if prefix == "account" else 1800
            try:
                ssh_agent = ssh.agent.Client()
                ssh_agent.add(key, comment=f"pf-{prefix}", lifetime=lifetime)
            except Exception:
                pass
        except pfc.exceptions.UI:
            raise pfc.exceptions.UI("Unable to parse data either as PEM or SSH format")
        if key.type != jwk.KeyType.ED25519:
            raise pfc.exceptions.UI(f"Unsupported: {key.type}")
        return FileSigner(prefix, key)

    ssh_agent = ssh.agent.Client()
    for identity in ssh_agent.list_identities():
        if identity.comment == filename or identity.public_key.match_ssh_fingerprint(filename):
            if identity.public_key.type != jwk.KeyType.ED25519:
                raise pfc.exceptions.UI(f"Unsupported: {identity.public_key.type}")
            return AgentSigner(prefix, identity.public_key)

    raise pfc.exceptions.KeyExpired(prefix)


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
        signer = private_key_signer("session", session)
        return HttpClient(self._pf_session, self._pf_directory, pfc.Auth([signer]))

    def session_auth_with_key(self, session: jwk.Private) -> HttpClient:
        auth = pfc.Auth([FileSigner("session", session)])
        return HttpClient(self._pf_session, self._pf_directory, auth)

    def login_auth(self, account: str | None, session: str | None) -> HttpClient:
        signers: list[pfc.Signer] = [
            private_key_signer("account", account),
            private_key_signer("session", session),
        ]
        return HttpClient(self._pf_session, self._pf_directory, pfc.Auth(signers))

    def invitation_auth_with_key(self, account: jwk.Private, invitation: str) -> InvitationHttpClient:
        account_signer = FileSigner("account", account)
        inv_signer = pfc.HmacSigner("invitation", base64url.decode(invitation))
        auth = pfc.Auth([inv_signer, account_signer])
        return InvitationHttpClient(self._pf_session, self._pf_directory, auth, account.public())
