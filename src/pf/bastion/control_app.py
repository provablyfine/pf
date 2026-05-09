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


async def reload_handler(state: AppState, request: anet.http.Request, sock_name: str) -> anet.http.Response | None:
    # 1. cancel accept task and request tasks
    state.main_app.stop()
    # 2. wait until cancel is complete
    await state.main_app.wait_stop()
    # 3. cancel all relay tasks
    state.main_state.stop()
    # 4. wait until all relay tasks are done
    await state.main_state.wait_stop()
    # 5. snapshot main app state (serialize/deserialize to verify round-trip integrity)
    main_snapshot = state.main_state.snapshot()
    main_snapshot_dump = main_snapshot.model_dump_json()
    main_snapshot_undump = app.AppSnapshot.model_validate_json(main_snapshot_dump)
    # 6. snapshot sockets
    sockets_snapshot = anet.sockets.store.snapshot()
    # 7. restore sockets from snapshot
    anet.sockets.store = anet.sockets.SocketStore.restore(sockets_snapshot)
    # 8. restore main app state from snapshot:
    state.main_state = app.AppState.restore(state.conf, main_snapshot_undump)
    # 9. create http main app from main state
    state.main_app = app.create(state.conf, state.main_state, state.main_app.accept_socket)

    return http.response(status_code=200)


async def ping_handler(state: AppState, request: anet.http.Request, sock_name: str) -> anet.http.Response | None:
    return http.response(status_code=200)


async def list_registered_handler(
    state: AppState, request: anet.http.Request, sock_name: str
) -> anet.http.Response | None:
    client_keys = [
        {
            "tenant_id": tenant_id,
            "name": name,
            "nconnections": relay.nconnections,
        }
        for (tenant_id, name), relay in state.main_state.relays.items()
    ]
    return http.json_response(status_code=200, json={"clients": client_keys})


def create(state: AppState, sock: anet.base.Socket) -> http.Application[AppState]:
    a = http.Application[AppState](state, sock)
    a.add_route(http.Route[AppState](reload_handler, method="POST", resource="/reload"))
    a.add_route(http.Route[AppState](ping_handler, method="POST", resource="/ping"))
    a.add_route(http.Route[AppState](list_registered_handler, method="GET", resource="/registered"))
    return a
