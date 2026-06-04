from __future__ import annotations

import typing

from . import exceptions
from .directory import Directory
from .http_session import HttpSession
from .http_signatures import Auth
from .signer import Signer


class InvitationClient:
    """API methods that require invitation + account authentication."""

    def __init__(
        self, session: HttpSession, directory: Directory, invitation_signer: Signer, account_signer: Signer
    ) -> None:
        self._session = session
        self._directory = directory
        self._invitation_signer = invitation_signer
        self._account_signer = account_signer

    def connect(self, account_public_key: dict[str, typing.Any]) -> None:
        """Accept an invitation and register the account public key."""
        auth = Auth([self._invitation_signer, self._account_signer])
        response = self._session.post(
            self._directory.accept_invitation,
            auth=auth,
            json={"account_public_key": account_public_key},
        )
        if response.status_code != 204:
            raise exceptions.UI(f"Unable to accept invitation: {response.text}")
