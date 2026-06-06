from __future__ import annotations

import provablyfine_client as pfc
import requests

from .. import base64url, jwk
from . import configuration, http_client


class Factory:
    def __init__(self, config: configuration.Config, timeout: float = 1.0) -> None:
        self._config = config
        self._http = pfc.HttpSession(requests.Session(), timeout)
        self._directory = pfc.Directory(config.directory_url, timeout)

    def session(self) -> pfc.SessionClient:
        signer = http_client.private_key_signer("session", self._config.session_key)
        return pfc.SessionClient(self._http, self._directory, signer)

    def session_with_key(self, session_key: str) -> pfc.SessionClient:
        signer = http_client.private_key_signer("session", session_key)
        return pfc.SessionClient(self._http, self._directory, signer)

    def public(self) -> pfc.PublicClient:
        return pfc.PublicClient(self._http, self._directory)

    def account(self, account_key: str | None, session_key: str) -> pfc.AccountClient:
        account_signer = http_client.private_key_signer("account", account_key)
        session_signer = http_client.private_key_signer("session", session_key)
        return pfc.AccountClient(self._http, self._directory, account_signer, session_signer)

    def account_from_keys(self, account: jwk.Private, session: jwk.Private) -> pfc.AccountClient:
        return pfc.AccountClient(
            self._http,
            self._directory,
            http_client.FileSigner("account", account),
            http_client.FileSigner("session", session),
        )

    def invitation(self, invitation_key: str, account_key: str) -> pfc.InvitationClient:
        account_signer = http_client.private_key_signer("account", account_key)
        inv_signer = pfc.HmacSigner("invitation", base64url.decode(invitation_key))
        return pfc.InvitationClient(
            self._http, self._directory, inv_signer, account_signer, account_signer.public_key().to_dict()
        )

    def async_session(self) -> pfc.AsyncSessionClient:
        return pfc.AsyncSessionClient(self.session())

    def async_session_with_key(self, session_key: str) -> pfc.AsyncSessionClient:
        return pfc.AsyncSessionClient(self.session_with_key(session_key))

    def async_public(self) -> pfc.AsyncPublicClient:
        return pfc.AsyncPublicClient(self.public())
