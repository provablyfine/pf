from __future__ import annotations

import requests

from . import exceptions


class Directory:
    """Fetches and caches the server's endpoint URL map from a well-known URL."""

    def __init__(self, url: str, timeout: float = 5.0) -> None:
        self._url = url
        self._timeout = timeout
        self._data: dict[str, str] | None = None

    def _load(self) -> dict[str, str]:
        if self._data is None:
            try:
                response = requests.get(self._url, timeout=self._timeout)
            except requests.exceptions.ConnectionError:
                raise exceptions.UI("Unable to connect to server")
            except requests.exceptions.ReadTimeout:
                raise exceptions.UI("Request timed out")
            if response.status_code != 200:
                raise exceptions.UI("Unable to read directory from server")
            self._data = response.json()
        assert self._data is not None
        return self._data

    @property
    def accept_invitation(self) -> str:
        return self._load()["accept_invitation"]

    @property
    def audit_log(self) -> str:
        return self._load()["audit_log"]

    @property
    def auth(self) -> str:
        return self._load()["auth"]

    @property
    def bastion(self) -> str:
        return self._load()["bastion"]

    @property
    def boundary(self) -> str:
        return self._load()["boundary"]

    @property
    def identity(self) -> str:
        return self._load()["identity"]

    @property
    def initialize(self) -> str:
        return self._load()["initialize"]

    @property
    def login(self) -> str:
        return self._load()["login"]

    @property
    def login_oidc(self) -> str:
        return self._load()["login_oidc"]

    @property
    def public_auth(self) -> str:
        return self._load()["public_auth"]

    @property
    def role(self) -> str:
        return self._load()["role"]

    @property
    def ssh(self) -> str:
        return self._load()["ssh"]

    @property
    def tag(self) -> str:
        return self._load()["tag"]

    @property
    def tenant(self) -> str:
        return self._load()["tenant"]
