"""Global socket store for named socket storage."""

from __future__ import annotations

import collections.abc

from . import base


class SocketStore:
    """Global singleton store for named sockets."""

    def __init__(self) -> None:
        self._sockets: dict[str, base.Socket] = {}

    def add(self, name: str, sock: base.Socket) -> None:
        """Register socket by name."""
        self._sockets[name] = sock

    def remove(self, name: str) -> None:
        """Unregister socket by name. Idempotent."""
        self._sockets.pop(name, None)

    def get(self, name: str) -> base.Socket | None:
        """Get socket by name. Returns None if not found."""
        return self._sockets.get(name)

    def __iter__(self) -> collections.abc.Iterator[tuple[str, base.Socket]]:
        """Iterate over (name, socket) pairs."""
        return iter(self._sockets.items())

    def __len__(self) -> int:
        """Number of registered sockets."""
        return len(self._sockets)


store: SocketStore = SocketStore()
