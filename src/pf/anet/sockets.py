"""Global socket store for named socket storage."""

from __future__ import annotations

import collections.abc
import dataclasses

from . import base, socket


@dataclasses.dataclass
class SocketStoreSnapshot:
    sockets: dict[str, int]


class SocketStore:
    """Global singleton store for named sockets."""

    def __init__(self, sockets: dict[str, base.Socket] | None = None) -> None:
        self._sockets: dict[str, base.Socket] = {} if sockets is None else sockets

    def add(self, name: str, sock: base.Socket) -> None:
        """Register socket by name."""
        self._sockets[name] = sock

    def remove(self, name: str) -> base.Socket | None:
        """Unregister socket by name. Idempotent."""
        return self._sockets.pop(name, None)

    def get(self, name: str) -> base.Socket | None:
        """Get socket by name. Returns None if not found."""
        return self._sockets.get(name)

    def __iter__(self) -> collections.abc.Iterator[tuple[str, base.Socket]]:
        """Iterate over (name, socket) pairs."""
        return iter(self._sockets.items())

    def __len__(self) -> int:
        """Number of registered sockets."""
        return len(self._sockets)

    def snapshot(self) -> SocketStoreSnapshot:
        # We use detach() instead of fileno() below to make sure the socket will not close the associated
        # file descriptor if it is garbage collected later.
        return SocketStoreSnapshot(sockets={name: s.detach() for name, s in self._sockets.items()})

    @classmethod
    def restore(cls, snapshot: SocketStoreSnapshot) -> SocketStore:
        return SocketStore(
            sockets={
                name: socket.socket(socket.Family.INET, socket.Type.STREAM, fileno=fd)
                for name, fd in snapshot.sockets.items()
            }
        )


store: SocketStore = SocketStore()
