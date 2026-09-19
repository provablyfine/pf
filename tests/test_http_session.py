import contextlib
import socket
import threading
import typing

import provablyfine_client as pfc
import pytest
import requests

_RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nok"


class _DroppingServer:
    """A server that closes a kept-alive connection after reading its next request.

    That is what a client sees when the server times out an idle connection
    at the same moment the client sends a request on it.
    Connections are numbered from 1.
    `drop_after` gives, per connection number, how many requests to answer before dropping.
    Connections without an entry answer every request.
    """

    def __init__(self, drop_after: dict[int, int]) -> None:
        self._drop_after = drop_after
        self.connections = 0
        self._listener = socket.socket()
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen()
        self.url = f"http://127.0.0.1:{self._listener.getsockname()[1]}/"
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def close(self) -> None:
        self._listener.close()

    def _accept_loop(self) -> None:
        with contextlib.suppress(OSError):
            while True:
                conn, _ = self._listener.accept()
                self.connections += 1
                threading.Thread(target=self._serve, args=(conn, self.connections), daemon=True).start()

    def _serve(self, conn: socket.socket, number: int) -> None:
        answered = 0
        with conn, contextlib.suppress(OSError):
            while conn.recv(65536):
                if answered == self._drop_after.get(number):
                    return
                conn.sendall(_RESPONSE)
                answered += 1


@pytest.fixture
def dropping_server() -> typing.Iterator[typing.Callable[[dict[int, int]], _DroppingServer]]:
    servers: list[_DroppingServer] = []

    def make(drop_after: dict[int, int]) -> _DroppingServer:
        servers.append(_DroppingServer(drop_after))
        return servers[-1]

    yield make
    for server in servers:
        server.close()


def test_request_is_retried_when_server_drops_a_kept_alive_connection(dropping_server) -> None:
    server = dropping_server({1: 1})
    session = pfc.HttpSession(requests.Session())
    assert session.get(server.url).status_code == 200
    assert session.post(server.url, json={}).status_code == 200
    assert server.connections == 2


def test_request_is_retried_only_once(dropping_server) -> None:
    server = dropping_server({1: 1, 2: 0})
    session = pfc.HttpSession(requests.Session())
    assert session.get(server.url).status_code == 200
    with pytest.raises(pfc.exceptions.UI, match="Unable to connect to server"):
        session.post(server.url, json={})
    assert server.connections == 2


def test_unreachable_server_is_not_retried() -> None:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.close()
    session = pfc.HttpSession(requests.Session())
    with pytest.raises(pfc.exceptions.UI, match="Unable to connect to server"):
        session.get(f"http://127.0.0.1:{port}/")
