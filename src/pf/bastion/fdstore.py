"""systemd fdstore integration for transparent connection handover across restart."""

from __future__ import annotations

import os

import pydantic

from .. import anet
from . import app, control_app, systemd


class BastionState(pydantic.BaseModel):
    """Serializable bastion state for fdstore recovery."""

    app: app.AppSnapshot
    socket_names: dict[str, str]


async def save(ctrl_state: control_app.AppState) -> None:
    """Snapshot state and donate FDs to systemd fdstore."""
    app_snapshot = ctrl_state.main_state.snapshot()
    sockets_snapshot = anet.sockets.store.snapshot()

    socket_items = list(sockets_snapshot.sockets.items())
    fdname_map = {f"pf-bastion-sock-{i}": name for i, (name, _) in enumerate(socket_items)}

    state = BastionState(app=app_snapshot, socket_names=fdname_map)
    json_bytes = state.model_dump_json().encode()

    state_fd = os.memfd_create("pf-bastion-state")

    try:
        os.write(state_fd, json_bytes)
        os.lseek(state_fd, 0, os.SEEK_SET)
        # Donate the FD to systemd fdstore
        systemd.store_fd(state_fd, "pf-bastion-state")
        os.close(state_fd)
    except Exception:
        os.close(state_fd)
        raise

    for i, (_, raw_fd) in enumerate(socket_items):
        systemd.store_fd(raw_fd, f"pf-bastion-sock-{i}")
        os.close(raw_fd)


def load(
    named: dict[str, int],
) -> tuple[app.AppSnapshot, anet.sockets.SocketStoreSnapshot] | None:
    """Load state from systemd fdstore FDs (keyed by name). Returns None if no state found."""
    if "pf-bastion-state" not in named:
        return None

    state_fd = named["pf-bastion-state"]
    try:
        # Seek to the beginning in case the FD position was moved
        try:
            os.lseek(state_fd, 0, os.SEEK_SET)
        except OSError:
            # Continue anyway - might be a pipe or socket
            pass

        data = b""
        try:
            while chunk := os.read(state_fd, 65536):
                data += chunk
        except OSError:
            return None

        if not data:
            return None

        state = BastionState.model_validate_json(data)
    except Exception:
        return None

    sockets: dict[str, int] = {}
    for fdname, socket_store_name in state.socket_names.items():
        if fdname in named:
            sockets[socket_store_name] = named[fdname]
    return state.app, anet.sockets.SocketStoreSnapshot(sockets=sockets)
