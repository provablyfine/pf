from __future__ import annotations

import asyncio
import dataclasses
import logging
import typing

from .. import anet, log

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class RelayConnectionSnapshot:
    """Snapshot of a relay connection."""

    socket_name: str
    channel_id: int

    def to_dict(self) -> dict[str, typing.Any]:
        """Serialize to dict."""
        return {"socket_name": self.socket_name, "channel_id": self.channel_id}

    @classmethod
    def from_dict(cls, d: dict[str, typing.Any]) -> RelayConnectionSnapshot:
        """Deserialize from dict."""
        return cls(socket_name=str(d["socket_name"]), channel_id=int(d["channel_id"]))


@dataclasses.dataclass
class RelaySnapshot:
    """Snapshot of a registered relay for persistence."""

    client_key: tuple[int, str]
    socket_name: str
    mux_snapshot: anet.mux.MuxSnapshot
    connections: list[RelayConnectionSnapshot]

    def to_dict(self) -> dict[str, typing.Any]:
        """Serialize to dict."""
        return {
            "client_key": list(self.client_key),
            "socket_name": self.socket_name,
            "mux_snapshot": self.mux_snapshot.to_dict(),
            "connections": [c.to_dict() for c in self.connections],
        }

    @classmethod
    def from_dict(cls, d: dict[str, typing.Any]) -> RelaySnapshot:
        """Deserialize from dict."""
        ck = d["client_key"]
        return cls(
            client_key=(int(ck[0]), str(ck[1])),
            socket_name=str(d["socket_name"]),
            mux_snapshot=anet.mux.MuxSnapshot.from_dict(d["mux_snapshot"]),
            connections=[RelayConnectionSnapshot.from_dict(c) for c in d["connections"]],
        )



class RelayConnection:
    """Relays data between user socket and a channel opened through Relay."""

    def __init__(
        self,
        socket_name: str,
        host_mux: anet.mux.Mux,
        host_id: int,
    ) -> None:
        self._socket_name = socket_name
        self._host_mux = host_mux
        self._channel_id = host_id
        sock = anet.sockets.store.get(socket_name)
        logger.info(f"sock_name={socket_name}")
        assert sock is not None
        self._sock = sock
        self._task = asyncio.create_task(self._run())
        def _done_cb(fut: asyncio.Future[None]) -> None:
            if fut.cancelled():
                # If the process is being killed for good, we do not need to cleanup sockets
                # If the process is dying to reload, we need to keep sockets around so they
                # can be restored later.
                return
            anet.sockets.store.remove(self._socket_name)
            self._sock.close()
        self._task.add_done_callback(_done_cb)

    @property
    def channel_id(self) -> int:
        """Channel ID for this connection (read-only)."""
        return self._channel_id

    @classmethod
    def start(
        cls,
        socket_name: str,
        host_mux: anet.mux.Mux,
        host_id: int,
    ) -> RelayConnection:
        """Start a relay connection. Spawns run() as background task."""
        return RelayConnection(socket_name, host_mux, host_id)

    def stop(self):
        self._task.cancel()

    async def wait_stop(self):
        try:
            await self._task
        except asyncio.CancelledError:
            # await a cancelled task raises
            pass

    async def _run(self) -> None:
        """Relay data between socket and channel."""

        async def user_to_host() -> None:
            logger.debug("relay_user_to_host start")
            try:
                while True:
                    data = await self._sock.recv(4096)
                    if data == b"":
                        break
                    logger.debug(f"relay_user_to_host rx={len(data)}")
                    write_task: asyncio.Task[None] = asyncio.ensure_future(
                        self._host_mux.channel_write(self._channel_id, data)
                    )
                    try:
                        await asyncio.shield(write_task)
                    except asyncio.CancelledError:
                        await write_task
                        raise
                    logger.debug(f"relay_user_to_host tx={len(data)}")
            except anet.exceptions.Error:
                pass
            finally:
                await self._host_mux.channel_close_write(self._channel_id)

        async def host_to_user() -> None:
            logger.debug("relay_host_to_user start")
            try:
                while True:
                    data = await self._host_mux.channel_read(self._channel_id)
                    if data == b"":
                        break
                    logger.debug(f"relay_host_to_user rx={len(data)}")
                    send_task: asyncio.Task[int] = asyncio.ensure_future(self._sock.send(data))
                    try:
                        await asyncio.shield(send_task)
                    except asyncio.CancelledError:
                        await send_task
                        raise
                    logger.debug(f"relay_host_to_user tx={len(data)}")
            except anet.exceptions.Error:
                pass
            finally:
                await self._sock.shutdown(anet.base.Shut.WR)

        try:
            await asyncio.gather(user_to_host(), host_to_user())
        finally:
            await self._host_mux.channel_close(self._channel_id)

    def add_done_callback(self, cb: typing.Callable[[asyncio.Task[None]], None]) -> None:
        """Register callback for when this connection closes."""
        assert self._task is not None
        self._task.add_done_callback(cb)

    def snapshot(self) -> RelayConnectionSnapshot:
        """Snapshot this connection (identifiers only; data is in the mux)."""
        return RelayConnectionSnapshot(socket_name=self._socket_name, channel_id=self._channel_id)

    @classmethod
    def restore(
        cls,
        snap: RelayConnectionSnapshot,
        host_mux: anet.mux.Mux,
    ) -> RelayConnection:
        """Restore from snapshot. Caller must have re-added socket to store."""
        return cls.start(snap.socket_name, host_mux, snap.channel_id)


class Relay:
    """Manages a registered bastion client. Owns anet.mux.Mux."""

    def __init__(
        self,
        socket_name: str,
        client_key: tuple[int, str],
        mux: anet.mux.Mux,
        connections: dict[str, RelayConnection],
    ) -> None:
        self._socket_name = socket_name
        self._client_key = client_key
        self._mux = mux
        self._connections = connections

    @property
    def nconnections(self):
        return len(self._connections)

    @classmethod
    def start(cls, socket_name: str, client_key: tuple[int, str]) -> Relay:
        """Start a relay. Spawns run() as background task."""
        mux = anet.mux.Mux.create(socket_name)
        connections: dict[str, RelayConnection] = {}
        return Relay(socket_name, client_key, mux, connections)

    def stop(self):
        self._mux.stop()
        for connection in self._connections.values():
            connection.stop()

    async def wait_stop(self):
        await self._mux.wait_stop()
        for connection in self._connections.values():
            await connection.wait_stop()

    async def open_connection(self, socket_name: str) -> RelayConnection:
        """Open a new connection through this relay."""
        host_id = await self._mux.channel_open()
        connection = RelayConnection.start(socket_name, self._mux, host_id)
        def _on_done(fut: asyncio.Future[None]) -> None:
            if fut.cancelled():
                return
            connection = self._connections.get(socket_name)
            if connection is None:
                return
            del self._connections[socket_name]

        connection.add_done_callback(_on_done)
        self._connections[socket_name] = connection
        return connection

    def add_done_callback(self, cb: typing.Callable[[tuple[int,str]], None]) -> None:
        """Register callback for when this relay closes."""
        def _on_done(future: asyncio.Future[None]) -> None:
            if future.cancelled():
                return
            cb(self._client_key)
        self._mux.add_rx_done_callback(_on_done)

    def snapshot(self) -> RelaySnapshot:
        """Snapshot the relay (stops mux reader, drains state)."""
        mux_snapshot = self._mux.snapshot()
        connections = [conn.snapshot() for conn in self._connections.values()]
        return RelaySnapshot(
            client_key=self._client_key,
            socket_name=self._socket_name,
            mux_snapshot=mux_snapshot,
            connections=connections,
        )

    @classmethod
    def restore(cls, snap: RelaySnapshot) -> Relay:
        """Restore a Relay from snapshot. Spawns run() as background task."""
        mux = anet.mux.Mux.restore(snap.mux_snapshot)
        connections = {c.socket_name: RelayConnection.restore(c, mux) for c in snap.connections}
        return Relay(snap.socket_name, snap.client_key, mux, connections)
