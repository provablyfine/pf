"""stdin/stdout for `pf bastion connect` on Windows, where asyncio cannot.

`connect_async` relays between `ssh`'s stdio and the bastion. On POSIX that is
`loop.connect_read_pipe`/`connect_write_pipe` which does not work on win32.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import queue
import threading

logger = logging.getLogger(__name__)

_CHUNK = 4096


class StdinReader:
    """The `asyncio.StreamReader` half: `await read(n)`, and b"" at EOF.

    The reader thread is a daemon and is never joined. It is parked in
    `os.read(0, ...)` for the life of the relay, and there is no portable way to
    interrupt that; the process is exiting anyway by the time it matters.
    """

    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        self._queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._pending = b""
        self._eof = False
        threading.Thread(target=self._pump, daemon=True, name="pf-stdin").start()

    def _pump(self) -> None:
        while True:
            try:
                data = os.read(0, _CHUNK)
            except OSError:
                # ssh closing its end reads as an error rather than EOF often
                # enough that treating the two alike is the only sane contract.
                logger.debug("stdin read failed, treating as EOF", exc_info=True)
                data = b""
            self._loop.call_soon_threadsafe(self._queue.put_nowait, data)
            if not data:
                return

    async def read(self, n: int) -> bytes:
        """At most `n` bytes; b"" once stdin is done, and b"" forever after."""
        if not self._pending:
            if self._eof:
                return b""
            self._pending = await self._queue.get()
            if not self._pending:
                self._eof = True
                return b""
        data, self._pending = self._pending[:n], self._pending[n:]
        return data


class StdoutTransport:
    """The `asyncio.WriteTransport` half: `write`, `is_closing`, `abort`.

    `write()` is called from the loop and must not block, so it only enqueues;
    a writer thread does the `os.write`, looping on partial writes.

    Chosen deliberately: `abort()` closes fd 1 from the *calling* thread while
    the writer thread may be inside `os.write`. A write already in flight is
    allowed to finish or to fail with `EBADF`, which the pump swallows. The
    alternative -- handshaking with the writer thread first -- would reintroduce
    the wait that `abort()` exists to avoid, and the bytes at stake are protocol
    bytes `ssh` has stopped reading anyway.
    """

    def __init__(self) -> None:
        self._queue: queue.SimpleQueue[bytes | None] = queue.SimpleQueue()
        self._closing = False
        threading.Thread(target=self._pump, daemon=True, name="pf-stdout").start()

    def _pump(self) -> None:
        while True:
            data = self._queue.get()
            if data is None:
                return
            try:
                while data:
                    data = data[os.write(1, data) :]
            except OSError:
                logger.debug("stdout write failed, stopping", exc_info=True)
                return

    def write(self, data: bytes) -> None:
        if not self._closing:
            self._queue.put(data)

    def is_closing(self) -> bool:
        return self._closing

    def abort(self) -> None:
        if self._closing:
            return
        self._closing = True
        with contextlib.suppress(queue.Empty):
            while True:
                self._queue.get_nowait()
        self._queue.put(None)
        try:
            os.close(1)
        except OSError:
            logger.debug("closing stdout failed", exc_info=True)


def make_stdio(loop: asyncio.AbstractEventLoop) -> tuple[StdinReader, StdoutTransport]:
    return StdinReader(loop), StdoutTransport()
