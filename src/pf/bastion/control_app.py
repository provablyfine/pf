from __future__ import annotations

import dataclasses
import logging

from .. import anet
from . import app, http

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class AppState:
    main: app.AppState


async def reload_handler(state: AppState, request: anet.http.Request, sock: anet.base.Socket) -> None:
    # 1. cancel accept task (task that does a while loop over the accept call)
    # 2. cancel relay tasks (tasks that are relaying data)
    # 3. cancel request tasks (tasks that process incoming requests after an accept call, and create relaying tasks)
    # 1. cancel all tasks in main app:
    #    - tasks in state
    #    - tasks in http handling ?
    # 2. snapshot main app state
    # 3. snapshot sockets
    # 4. restore sockets from snapshots (3)
    # 5. restore main app state from snapshot (2)
    # 6. create http main app from main state
    # 7. save main app state and main app in control state
    # 8. start main task(s)
    await http.Response(status_code=200).serialize(sock)
    sock.close()


def create(state: AppState, sock: anet.socket.Socket) -> http.Application[AppState]:
    app = http.Application[AppState](state, sock)
    app.add_route(http.Route[AppState](reload_handler, method="POST", resource="/reload"))
    return app
