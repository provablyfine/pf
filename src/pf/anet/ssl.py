from __future__ import annotations

import logging
import enum
import ssl as _ssl

from . import base, socket


class VerifyMode(enum.IntEnum):
    REQUIRED = _ssl.CERT_REQUIRED


class ContextProtocol(enum.IntEnum):
    SERVER = _ssl.PROTOCOL_TLS_SERVER
    CLIENT = _ssl.PROTOCOL_TLS_CLIENT


logger = logging.getLogger(__name__)


class Socket(base.Socket):
    def __init__(self, sock: socket.Socket, ctx: _ssl.SSLContext, server_side: bool, server_hostname: str|None):
        self._sock = sock
        self._in_bio = _ssl.MemoryBIO()
        self._out_bio = _ssl.MemoryBIO()
        self._ssl_object = ctx.wrap_bio(
            self._in_bio,
            self._out_bio,
            server_side=server_side,
            server_hostname=server_hostname
        )

    async def handshake(self):
        while True:
            try:
                self._ssl_object.do_handshake()
                await self._flush_send()
                break
            except (_ssl.SSLWantReadError, _ssl.SSLWantWriteError) as exc:
                await self._flush_send()
                try:
                    chunk = await self._read_record()
                except (EOFError, Exception):
                    raise
                else:
                    if not chunk:
                        raise ConnectionError("Socket closed unexpectedly") from exc
                    _accepted = self._in_bio.write(chunk)

    async def _flush_send(self):
        while self._out_bio.pending:
            data = self._out_bio.read()
            sent = 0
            while sent < len(data):
                sent += await self._sock.send(data[sent:])

    async def send(self, data: bytes) -> int:
        n = self._ssl_object.write(data)
        await self._flush_send()
        return n

    async def _recv(self, n: int):
        buf = bytearray()
        while len(buf) < n:
            chunk = await self._sock.recv(n - len(buf))
            if chunk == b"":
                raise EOFError()
                #raise _ssl.SSLEOFError
            buf.extend(chunk)
        return bytes(buf)

    async def _read_record(self) -> bytes:
        header = await self._recv(5)
        record_length = int.from_bytes(header[3:], "big")
        payload = await self._recv(record_length)
        return header + payload

    async def _read_data_record(self) -> bytes:
        if self._ssl_object.pending() == 0:
            record = await self._read_record()
            _accepted = self._in_bio.write(record)
        data = self._ssl_object.read()
        return data

    async def recv(self, n: int) -> bytes:
        # We ignore n. The caller is responsible
        # for handling data whose length does not
        # match the requested length.
        while True:
            try:
                return await self._read_data_record()
            except _ssl.SSLWantReadError:
                # This happens if a record is part of a multi-record
                # protocol message (like a handshake or re-key)
                continue
            except _ssl.SSLEOFError:
                return b""

    async def shutdown(self, flag: base.Shut) -> None:
        try:
            self._ssl_object.unwrap()
        except (_ssl.SSLWantWriteError, _ssl.SSLWantReadError):
            # flush 'close_notify' record to remote
            await self._flush_send()
            data = await self._sock.recv(4096)
            if not data:
                raise ConnectionError("Connection closed during TLS operation")
            self._in_bio.write(data)
        except Exception:
            # If the connection is already dead, unwrap might fail.
            pass
        finally:
            # TCP shutdown
            await self._sock.shutdown(base.Shut.WR)

    async def close(self):
        await self._sock.close()


class SSLContextBase:
    def __init__(self, ctx: _ssl.SSLContext):
        self._ctx = ctx

    def load_cert_chain(self, certfile: str, keyfile: str):
        self._ctx.load_cert_chain(certfile, keyfile)

    def load_verify_locations(self, ca_cert_file: str):
        self._ctx.load_verify_locations(ca_cert_file)

    @property
    def check_hostname(self) -> bool:
        return self._ctx.check_hostname

    @check_hostname.setter
    def check_hostname(self, value: bool):
        self._ctx.check_hostname = value

    @property
    def verify_mode(self) -> VerifyMode:
        return VerifyMode(self._ctx.verify_mode)

    @verify_mode.setter
    def verify_mode(self, mode: VerifyMode):
        self._ctx.verify_mode = mode.value

    async def wrap_socket(
        self,
        sock: socket.Socket,
        server_side: bool = False,
        server_hostname: str | None = None,
    ) -> Socket:
        return Socket(sock, self._ctx, server_side=server_side, server_hostname=server_hostname)


class SSLContext(SSLContextBase):
    def __init__(self, protocol: ContextProtocol):
        super().__init__(_ssl.SSLContext(protocol.value))


async def create_default_context() -> SSLContextBase:
    ctx = _ssl.create_default_context()
    return SSLContextBase(ctx)
