from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import traceback
import typing

from .. import anet

T = typing.TypeVar("T")

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class Response:
    status_code: int
    title: str | None = None

    def _reason(self) -> str:
        mapping = {
            200: "OK",
            400: "Bad Request",
            403: "Forbidden",
            404: "Not Found",
            500: "Internal Server Error",
        }
        return mapping.get(self.status_code, "Unexpected")

    async def serialize(self, sock: anet.base.Socket):
        if self.title is not None:
            response_body = json.dumps({"title": self.title}).encode("utf-8")
            response_headers = {
                "Content-Type": "application/json",
                "Content-Length": str(len(response_body)),
            }
        else:
            response_headers = {}
            response_body = b""
        response = anet.http.Response(
            status_code=self.status_code,
            reason=self._reason(),
            version="HTTP/1.1",
            headers=response_headers,
            body=response_body,
        )
        await response.serialize(sock)


RouteHandler = typing.Callable[[T, anet.http.Request, anet.base.Socket], typing.Awaitable[None]]


@dataclasses.dataclass
class Route[T]:
    handler: RouteHandler[T]
    method: str | None = None
    host: str | None = None
    resource: str | None = None


class Application[T]:
    def __init__(self, state: T, sock: anet.socket.Socket):
        self._state = state
        self._sock = sock
        self._tasks: list[asyncio.Task[None]] = []
        self._accept_task: asyncio.Task[None] | None = None
        self._routes: list[Route[T]] = []

    def add_route(self, route: Route[T]):
        self._routes.append(route)

    async def _handle_new_client(self, sock: anet.base.Socket) -> None:
        try:
            request = await anet.http.Request.deserialize(sock)
        except anet.exceptions.Error:
            await Response(status_code=400, title="Invalid HTTP request").serialize(sock)
            await sock.close()
            return

        if request.version != "HTTP/1.1":
            await Response(status_code=400, title="Invalid HTTP version").serialize(sock)
            await sock.close()
            return

        for route in self._routes:
            if route.method is not None:
                if request.method != route.method:
                    continue
            if route.host is not None:
                if request.headers["host"] != route.host:
                    continue
            if route.resource is not None:
                if request.resource_target != route.resource:
                    continue
            try:
                await route.handler(self._state, request, sock)
            except Exception:
                logger.error(traceback.format_exc())
                await Response(status_code=500, title="Error while executing request").serialize(sock)
                await sock.close()
            return

        logger.error(f"Unable to find route for host: {request.headers['host']}")
        await Response(status_code=404, title="Unable to find matching route").serialize(sock)
        await sock.close()

    async def _loop(self) -> None:
        await self._sock.listen(10)
        while True:
            try:
                sock, _address = await self._sock.accept()
                task = asyncio.create_task(self._handle_new_client(sock))
                self._tasks.append(task)
            except (OSError, asyncio.exceptions.CancelledError):
                break

    async def run(self):
        self._accept_task = asyncio.create_task(self._loop())
        await self._accept_task
        for task in self._tasks:
            task.cancel()

    def stop(self) -> None:
        if self._accept_task is not None:
            self._accept_task.cancel()
