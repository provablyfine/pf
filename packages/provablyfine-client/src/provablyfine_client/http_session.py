from __future__ import annotations

import logging
import time
import typing

import requests
import urllib3.exceptions

from . import exceptions, http_signatures

logger = logging.getLogger(__name__)

# The 401 titles that mean "this session cannot be used any more, log in again".
_SESSION_ENDED_TITLES = (
    "Session key is expired",
    "Session key is logged out",
    "Session key is revoked",
    "Session does not exist",
)


def _server_dropped_connection(error: requests.exceptions.ConnectionError) -> bool:
    """True if the server closed a pooled connection that the client had kept open.

    Servers close idle keep-alive connections after a few seconds.
    The client only notices when it sends the next request on that connection.
    This is different from a server that cannot be reached at all.
    """
    return bool(error.args) and isinstance(error.args[0], urllib3.exceptions.ProtocolError)


def _parse_retry_after(value: str | None) -> float | None:
    """Parse a `Retry-After` header given as a number of seconds.

    Returns None if there is no header or it is not a plain number (for example an HTTP-date):
    nothing in this codebase's server ever sends anything but a plain integer, so that is the
    only form worth understanding here. None means "do not retry on this".
    """
    if value is None:
        return None
    try:
        return float(value)
    except ValueError:
        return None


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
        auth: http_signatures.Auth | None = None,
        json: typing.Any = None,
        data: typing.Any = None,
        headers: dict[str, str] | None = None,
        params: dict[str, typing.Any] | None = None,
        timeout: float | None = None,
    ) -> requests.Response:
        req = requests.Request(method=method, url=url, json=json, data=data, headers=headers, params=params)
        effective_timeout = timeout if timeout is not None else self._timeout
        start = time.monotonic()

        while True:
            # Rebuilt and re-signed on every attempt in case there is
            # a nonce in the auth.
            prepared = req.prepare()
            if auth is not None:
                prepared = auth(prepared)

            remaining = effective_timeout - (time.monotonic() - start)
            logger.info(f"tx {prepared.method} {prepared.url}")
            logger.debug(f"tx headers: {prepared.headers}")
            logger.debug(f"tx body: {prepared.body}")
            try:
                response = self._send(prepared, max(remaining, 0.001))
            except requests.exceptions.ConnectionError:
                raise exceptions.UI("Unable to connect to server")
            except requests.exceptions.ReadTimeout:
                raise exceptions.UI("Request timed out")
            logger.info(f"rx {response.status_code}")
            logger.debug(f"rx headers: {response.headers}")
            logger.debug(f"rx body: {response.content}")

            if response.status_code == 503:
                retry_after = _parse_retry_after(response.headers.get("Retry-After"))
                elapsed = time.monotonic() - start
                if retry_after is not None and elapsed + retry_after < effective_timeout:
                    logger.debug(f"503, retrying in {retry_after}s")
                    time.sleep(retry_after)
                    continue
            break

        if response.status_code in (400, 422):
            try:
                problem = response.json()
                title = problem.get("title", "")
                detail = problem.get("detail")
                msg = f"{title} {detail}" if detail else title
            except Exception:
                msg = response.text
            raise exceptions.UI(msg or response.text)

        if response.status_code == 401:
            try:
                title = response.json().get("title", "")
            except Exception:
                title = ""
            if title in _SESSION_ENDED_TITLES:
                raise exceptions.SessionExpired(title)

        return response

    def _send(self, prepared: requests.PreparedRequest, timeout: float) -> requests.Response:
        """Send `prepared`, once more if the server had closed a kept-alive connection.

        The second attempt sends the same signed request on a new connection.
        The server rejects a signature nonce it has already seen.
        So the request cannot be executed twice, even if the first attempt did reach the server.
        """
        try:
            return self._session.send(prepared, timeout=timeout)
        except requests.exceptions.ConnectionError as e:
            if not _server_dropped_connection(e):
                raise
            logger.debug("server closed a kept-alive connection, retrying once")
        return self._session.send(prepared, timeout=timeout)

    def get(
        self,
        url: str,
        *,
        auth: http_signatures.Auth | None = None,
        params: dict[str, typing.Any] | None = None,
    ) -> requests.Response:
        return self.request("GET", url, auth=auth, params=params)

    def post(
        self,
        url: str,
        *,
        auth: http_signatures.Auth | None = None,
        json: typing.Any = None,
    ) -> requests.Response:
        return self.request("POST", url, auth=auth, json=json)

    def patch(
        self,
        url: str,
        *,
        auth: http_signatures.Auth | None = None,
        json: typing.Any = None,
    ) -> requests.Response:
        return self.request("PATCH", url, auth=auth, json=json)

    def delete(
        self,
        url: str,
        *,
        auth: http_signatures.Auth | None = None,
    ) -> requests.Response:
        return self.request("DELETE", url, auth=auth)

    def put(
        self,
        url: str,
        *,
        auth: http_signatures.Auth | None = None,
        json: typing.Any = None,
    ) -> requests.Response:
        return self.request("PUT", url, auth=auth, json=json)
