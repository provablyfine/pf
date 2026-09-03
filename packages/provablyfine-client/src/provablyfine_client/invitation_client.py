from __future__ import annotations

import typing

from . import directory, exceptions, http_session, http_signatures, signer


class InvitationClient:
    """API methods that require invitation + account authentication."""

    def __init__(
        self,
        session: http_session.HttpSession,
        _directory: directory.Directory,
        invitation_signer: signer.Signer,
        account_signer: signer.Signer,
        account_public_key: dict[str, typing.Any],
    ) -> None:
        self._session = session
        self._directory = _directory
        self._invitation_signer = invitation_signer
        self._account_signer = account_signer
        self._account_public_key = account_public_key

    def accept_invitation(self) -> None:
        auth = http_signatures.Auth([self._invitation_signer, self._account_signer])
        response = self._session.post(
            self._directory.accept_invitation,
            auth=auth,
            json={"account_public_key": self._account_public_key},
        )
        if response.status_code != 204:
            raise exceptions.UI(f"Unable to accept invitation: {response.text}")
