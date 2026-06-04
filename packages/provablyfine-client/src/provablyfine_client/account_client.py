from __future__ import annotations

import typing

from . import exceptions
from .directory import Directory
from .http_session import HttpSession
from .http_signatures import Auth
from .signer import Signer


class AccountClient:
    """API methods that require account + session authentication."""

    def __init__(
        self, session: HttpSession, directory: Directory, account_signer: Signer, session_signer: Signer
    ) -> None:
        self._session = session
        self._directory = directory
        self._account_signer = account_signer
        self._session_signer = session_signer

    def login_http_sig(self, session_public_key: dict[str, typing.Any]) -> None:
        auth = Auth([self._account_signer, self._session_signer])
        response = self._session.post(
            self._directory.login,
            auth=auth,
            json={"session_public_key": session_public_key},
        )
        if response.status_code != 204:
            raise exceptions.UI(f"Unable to login successfully: {response.text}")
