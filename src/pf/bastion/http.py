from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import traceback
import typing

from .. import anet
from . import atomic

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


RouteHandler = typing.Callable[[T, anet.http.Request, str], typing.Awaitable[Response|None]]


@dataclasses.dataclass
class Route[T]:
    handler: RouteHandler[T]
    method: str | None = None
    host: str | None = None
    resource: str | None = None


class Application[T]:
    """
    This application is built around two sets of asyncio tasks:

    - the accept task's sole purpose is to call accept on the listening socket.
      Once accept returns, it hands over the socket to a "request task"

    - each request task processes a single incoming request over a single
      connection/socket. It first reads the request from the socket, writes back
      an error if needed. If it finds a matching handler, it invokes
      the handler in an atomic conteext with regard to task cancellation
      (the handler either does not run at all or runs to completion: if the task
      is cancelled while the handler runs, cancellation is propagated only when
      the handler completes)

    """
    def __init__(self, state: T, sock: anet.base.Socket):
        self._state = state
        self._accept_sock = sock
        self._request_tasks: list[asyncio.Task[None]] = []
        self._accept_task = asyncio.create_task(self._run())
        self._routes: list[Route[T]] = []
        self._read_request_timeout = 1.0
        self._is_stopped =  asyncio.Event()

    @property
    def accept_socket(self) -> anet.base.Socket:
        return self._accept_sock

    def add_route(self, route: Route[T]):
        self._routes.append(route)

    async def _handle_new_client(self, sock: anet.base.Socket) -> None:
        request = None
        try:
            request = await asyncio.wait_for(anet.http.Request.deserialize(sock), timeout=self._read_request_timeout)
        except asyncio.exceptions.TimeoutError:
            logger.info("Read request timeout: client did not send their request on time")
        except anet.exceptions.Error:
            logger.info("Read request: client sent an invalid HTTP request")
        except asyncio.CancelledError:
            logger.info("Read request: cancelled")
        finally:
            if request is None:
                # We protect ourselves against badly-behaving clients that are not able to send a valid http request
                logger.info("Close socket: unable to parse request")
                sock.close()
        if request is None:
            return

        sock_name = f"pf-bastion.{id(sock)}"
        anet.sockets.store.add(sock_name, sock)
        try:
            response = await self._do_handle_new_client(request, sock_name)
            if response is None:
                return
            request_sock = anet.sockets.store.remove(sock_name)
            assert request_sock is not None
            await response.serialize(request_sock)
            request_sock.close()
        except asyncio.CancelledError:
            request_sock = anet.sockets.store.remove(sock_name)
            assert request_sock is not None
            request_sock.close()

    async def _do_handle_new_client(self, request: anet.http.Request, sock_name: str) -> Response | None:
        if request.version != "HTTP/1.1":
            return Response(status_code=400, title="Invalid HTTP version")

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
                # We run the application handler in an atomic context with
                # regard to cancellation.
                response = await atomic.run(route.handler(self._state, request, sock_name))
            except Exception:
                logger.error(traceback.format_exc())
                return Response(status_code=500, title="Error while executing request")
            return response

        logger.error(f"Unable to find route for host: {request.headers['host']}")
        return Response(status_code=404, title="Unable to find matching route")

    async def _run(self) -> None:
        await self._accept_sock.listen(10)
        while True:
            try:
                sock, _address = await self._accept_sock.accept()
                logger.error(f"accepted: {sock} on {self._accept_sock}")
                task = asyncio.create_task(self._handle_new_client(sock))
                self._request_tasks.append(task)
                task.add_done_callback(self._request_tasks.remove)
            except (OSError, asyncio.exceptions.CancelledError):
                break
        # We do a small sleep to give time to self._request_tasks
        # to empty itself naturally. If we wanted to guarantee
        # that self._request_tasks is really empty, we would
        # need to sleep at least self._read_request_timeout
        await asyncio.sleep(self._read_request_timeout / 10.0)
        # It could be that are still incoming requests that have
        # not been fully processed so we could cancel a couple
        # of incoming requests. It's ok since the clients will
        # retry shortly later.
        for task in self._request_tasks:
            task.cancel()
        for task in self._request_tasks:
            # we wait to make sure the tasks are really cancelled
            await task
        self._request_tasks = []
        self._is_stopped.set()

    def stop(self) -> None:
        self._accept_task.cancel()

    async def wait_stop(self) -> None:
        """
        When wait_stop returns, the application is not able to accept new
        incoming requests: the listening socket is still open while the
        sockets for the requests that were still in flight are closed.
        """
        await self._is_stopped.wait()
