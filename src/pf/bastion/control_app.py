from __future__ import annotations

import logging

from .. import anet
from . import http

logger = logging.getLogger(__name__)


class AppState:
    pass


async def reload_handler(state: AppState, request: anet.http.Request, sock: anet.base.Socket) -> None:
    await http.Response(status_code=200).serialize(sock)
    await sock.close()


def create(sock: anet.socket.Socket) -> http.Application[AppState]:
    state = AppState()
    app = http.Application[AppState](state, sock)
    app.add_route(http.Route[AppState](reload_handler, method="POST", resource="/reload"))
    return app
