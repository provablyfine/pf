"""Control HTTP server on a Unix stream socket."""

from __future__ import annotations

import asyncio
import logging
import os
import socket
import typing

from .. import anet

logger = logging.getLogger(__name__)


class ControlApp:
    def __init__(
        self,
        sock_path: str,
        reload: typing.Callable[[], typing.Awaitable[None]],
    ) -> None:
        self._sock_path = sock_path
        self._reload = reload
        self._raw_sock: socket.socket | None = None

    def stop(self) -> None:
        if self._raw_sock is not None:
            self._raw_sock.close()

    async def run(self) -> None:
        self._raw_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            os.unlink(self._sock_path)
        except FileNotFoundError:
            pass
        self._raw_sock.setblocking(False)
        self._raw_sock.bind(self._sock_path)
        sock = anet.socket.Socket(self._raw_sock, loop=None)
        await sock.listen(5)
        background_tasks: set[asyncio.Task[None]] = set()
        while True:
            try:
                client_sock, _ = await sock.accept()
                task = asyncio.create_task(self._handle(client_sock))
                background_tasks.add(task)
                task.add_done_callback(background_tasks.discard)
            except OSError:
                break

    async def _handle(self, sock: anet.base.Socket) -> None:
        try:
            request = await anet.http.Request.deserialize(sock)
            if request.method == "POST" and request.resource_target == "/reload":
                await self._reload()
                body = b'{"status":"ok"}'
                response = anet.http.Response(
                    version="HTTP/1.1",
                    status_code=200,
                    reason="OK",
                    headers={
                        "Content-Type": "application/json",
                        "Content-Length": str(len(body)),
                    },
                    body=body,
                )
            else:
                response = anet.http.Response(
                    version="HTTP/1.1",
                    status_code=404,
                    reason="Not Found",
                    headers={"Content-Length": "0"},
                    body=b"",
                )
            await response.serialize(sock)
        except Exception:
            logger.exception("Control request failed")
        finally:
            await sock.close()
