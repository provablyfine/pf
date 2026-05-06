from __future__ import annotations

import logging
import dataclasses

from .. import anet
from . import app, http

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class AppState:
    main: app.AppState


async def reload_handler(state: AppState, request: anet.http.Request, sock: anet.base.Socket) -> None:
    await http.Response(status_code=200).serialize(sock)
    await sock.close()


def create(state: AppState, sock: anet.socket.Socket) -> http.Application[AppState]:
    app = http.Application[AppState](state, sock)
    app.add_route(http.Route[AppState](reload_handler, method="POST", resource="/reload"))
    return app
