from __future__ import annotations

import dataclasses
import logging

from .. import anet
from . import app, http

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class AppState:
    conf: app.Config
    main_state: app.AppState
    main_app: http.Application[app.AppState]


async def reload_handler(state: AppState, request: anet.http.Request, sock_name: str) -> None:
    # 1. cancel accept task and request tasks
    state.main_app.stop()
    # 2. wait until cancel is complete
    await state.main_app.wait_stop()
    # 3. cancel all relay tasks
    state.main_state.stop()
    # 4. wait until all relay tasks are done
    await state.main_state.wait_stop()
    # 5. snapshot main app state
    main_snapshot = state.main_state.snapshot()
    # 6. snapshot sockets
    sockets_snapshot = anet.sockets.store.snapshot()
    # 7. restore sockets from snapshot
    anet.sockets.store = anet.sockets.SocketStore.restore(sockets_snapshot)
    # 8. restore main app state from snapshot:
    state.main_state = app.AppState.restore(state.conf, main_snapshot)
    # 9. create http main app from main state
    state.main_app = http.Application[app.AppState](state.main_state, "main")

    # Now, we can return success to the client
    sock = anet.sockets.store.get(sock_name)
    assert sock is not None
    await http.Response(status_code=200).serialize(sock)
    sock.close()


def create(state: AppState, sock_name: str) -> http.Application[AppState]:
    a = http.Application[AppState](state, sock_name)
    a.add_route(http.Route[AppState](reload_handler, method="POST", resource="/reload"))
    return a
