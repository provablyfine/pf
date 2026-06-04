from __future__ import annotations

import logging
import typing

import requests

from . import exceptions
from .http_signatures import Auth

logger = logging.getLogger(__name__)


class HttpSession:
    """Thin wrapper around requests.Session: logging, 400/422 error handling, per-request auth."""

    def __init__(self, session: requests.Session, timeout: float = 5.0) -> None:
        self._session = session
        self._timeout = timeout

    def request(
        self,
        method: str,
        url: str,
        *,
        auth: Auth | None = None,
        json: typing.Any = None,
        data: typing.Any = None,
        headers: dict[str, str] | None = None,
        params: dict[str, typing.Any] | None = None,
        timeout: float | None = None,
    ) -> requests.Response:
        req = requests.Request(method=method, url=url, json=json, data=data, headers=headers, params=params)
        prepared = req.prepare()
        if auth is not None:
            prepared = auth(prepared)

        effective_timeout = timeout if timeout is not None else self._timeout
        logger.info(f"tx {prepared.method} {prepared.url}")
        logger.debug(f"tx headers: {prepared.headers}")
        logger.debug(f"tx body: {prepared.body}")
        try:
            response = self._session.send(prepared, timeout=effective_timeout)
        except requests.exceptions.ConnectionError:
            raise exceptions.UI("Unable to connect to server")
        except requests.exceptions.ReadTimeout:
            raise exceptions.UI("Request timed out")
        logger.info(f"rx {response.status_code}")
        logger.debug(f"rx headers: {response.headers}")
        logger.debug(f"rx body: {response.content}")

        if response.status_code in (400, 422):
            try:
                problem = response.json()
                title = problem.get("title", "")
                detail = problem.get("detail")
                msg = f"{title} {detail}" if detail else title
            except Exception:
                msg = response.text
            raise exceptions.UI(msg or response.text)

        return response

    def get(
        self,
        url: str,
        *,
        auth: Auth | None = None,
        params: dict[str, typing.Any] | None = None,
    ) -> requests.Response:
        return self.request("GET", url, auth=auth, params=params)

    def post(
        self,
        url: str,
        *,
        auth: Auth | None = None,
        json: typing.Any = None,
    ) -> requests.Response:
        return self.request("POST", url, auth=auth, json=json)

    def patch(
        self,
        url: str,
        *,
        auth: Auth | None = None,
        json: typing.Any = None,
    ) -> requests.Response:
        return self.request("PATCH", url, auth=auth, json=json)

    def delete(
        self,
        url: str,
        *,
        auth: Auth | None = None,
    ) -> requests.Response:
        return self.request("DELETE", url, auth=auth)

    def put(
        self,
        url: str,
        *,
        auth: Auth | None = None,
        json: typing.Any = None,
    ) -> requests.Response:
        return self.request("PUT", url, auth=auth, json=json)
