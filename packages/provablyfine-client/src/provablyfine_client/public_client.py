from __future__ import annotations

import typing

from . import _base64url, directory, exceptions, http_session, http_signatures, schemas, signer


def _problem_title(response: typing.Any, default: str) -> str:
    try:
        title = response.json().get("title")
        if title:
            return str(title)
    except Exception:
        pass
    return default


class PublicClient:
    """API methods that require no authentication."""

    def __init__(self, session: http_session.HttpSession, _directory: directory.Directory) -> None:
        self._session = session
        self._directory = _directory

    def get_user_trusted_keys_public(self) -> str:
        response = self._session.get(f"{self._directory.ssh}/user/trusted-keys")
        if response.status_code != 200:
            raise exceptions.UI(_problem_title(response, "Failed to get user trusted keys"))
        return response.text

    def get_public_auth(self, auth_name: str) -> schemas.AuthPublic:
        response = self._session.get(f"{self._directory.public_auth}/{auth_name}")
        if response.status_code == 404:
            raise exceptions.UI(f"Auth config '{auth_name}' not found")
        if response.status_code != 200:
            raise exceptions.UI(_problem_title(response, "Unable to read auth config"))
        return schemas.AuthPublic.model_validate(response.json())

    def list_public_auths(self) -> list[schemas.AuthPublicSummary]:
        response = self._session.get(self._directory.public_auth)
        if response.status_code != 200:
            raise exceptions.UI("Unable to list auth methods")
        return [schemas.AuthPublicSummary.model_validate(a) for a in response.json().get("auths", [])]

    def initialize(self, account_signer: signer.Signer, account_public_key: dict[str, typing.Any]) -> None:
        """Bootstrap a new server: fetch invitation, then register account public key."""
        response = self._session.post(self._directory.initialize)
        if response.status_code == 204:
            raise exceptions.UI("Unable to initialize app: it is already initialized.")
        if response.status_code != 200:
            raise exceptions.UI(f"Unable to initialize app. Unexpected error: {response.status_code}.")
        invitation_key = response.json()["key"]["k"]
        inv_signer = signer.HmacSigner("invitation", _base64url.decode(invitation_key))
        auth = http_signatures.Auth([inv_signer, account_signer])
        response = self._session.post(
            self._directory.accept_invitation,
            auth=auth,
            json={"account_public_key": account_public_key},
        )
        if response.status_code != 204:
            raise exceptions.UI(f"Unable to accept invitation: {response.text}")
