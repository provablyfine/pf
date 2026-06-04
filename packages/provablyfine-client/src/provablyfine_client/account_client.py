from __future__ import annotations

import typing

from . import directory, exceptions, http_session, http_signatures, signer


class AccountClient:
    """API methods that require account + session authentication."""

    def __init__(
        self,
        session: http_session.HttpSession,
        _directory: directory.Directory,
        account_signer: signer.Signer,
        session_signer: signer.Signer,
    ) -> None:
        self._session = session
        self._directory = _directory
        self._account_signer = account_signer
        self._session_signer = session_signer

    def login_http_sig(self, session_public_key: dict[str, typing.Any]) -> None:
        auth = http_signatures.Auth([self._account_signer, self._session_signer])
        response = self._session.post(
            self._directory.login,
            auth=auth,
            json={"session_public_key": session_public_key},
        )
        if response.status_code != 204:
            raise exceptions.UI(f"Unable to login successfully: {response.text}")
