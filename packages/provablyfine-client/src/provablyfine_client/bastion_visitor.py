"""The visitor side of a bastion tunnel.

A visitor reaches a host that registered with the bastion.
It opens an HTTP CONNECT tunnel, then proves who it is with a token.

This module also holds the frp message framing that the host side shares.
"""

import asyncio
import base64
import collections.abc
import dataclasses
import json
import ssl
import struct
import typing
import urllib.parse

from . import exceptions

HANDSHAKE_TAG = "T"
ACCEPT_TAG = "A"

_MAX_CONNECT_RESPONSE = 16 * 1024


class Decryptor(typing.Protocol):
    def decrypt(self, data: bytes) -> bytes: ...


class Encryptor(typing.Protocol):
    def encrypt(self, data: bytes) -> bytes: ...


RecvFn = collections.abc.Callable[[], collections.abc.Awaitable[bytes]]
SendFn = collections.abc.Callable[[bytes], collections.abc.Awaitable[None]]


def jwt_audience(token: str) -> str:
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    claims = json.loads(base64.urlsafe_b64decode(payload))
    return str(claims["aud"])


def encode_frame(type_tag: str, payload: dict[str, object]) -> bytes:
    data = json.dumps(payload, separators=(",", ":")).encode()
    return bytes([ord(type_tag)]) + struct.pack(">Q", len(data)) + data


class FrpReader:
    """Buffered reader that decrypts bytes and exposes readexactly() for frp message parsing."""

    def __init__(self, recv: RecvFn, cipher: Decryptor | None) -> None:
        self._recv = recv
        self._cipher = cipher
        self._buf = bytearray()

    async def _fill(self) -> None:
        data = await self._recv()
        if not data:
            raise EOFError("connection closed")
        if self._cipher is not None:
            data = self._cipher.decrypt(data)
        self._buf.extend(data)

    async def readexactly(self, n: int) -> bytes:
        while len(self._buf) < n:
            await self._fill()
        result = bytes(self._buf[:n])
        del self._buf[:n]
        return result

    async def read_some(self, n: int = 65536) -> bytes:
        """Drain any buffered bytes first, then fall back to a fresh recv().

        Used once a handshake read is done and the connection switches to raw
        splicing: readexactly() may have buffered more than one frame's worth
        of bytes in a single recv() call, and a naive switch to raw recv()
        would silently drop them.
        """
        if self._buf:
            result = bytes(self._buf[:n])
            del self._buf[:n]
            return result
        data = await self._recv()
        if self._cipher is not None:
            data = self._cipher.decrypt(data)
        return data


async def read_frame(frp_reader: FrpReader) -> tuple[str, dict[str, object]]:
    header = await frp_reader.readexactly(9)
    tag = chr(header[0])
    length = struct.unpack(">Q", header[1:])[0]
    payload: dict[str, object] = json.loads(await frp_reader.readexactly(length))
    return tag, payload


async def write_frame(
    send: SendFn,
    cipher: Encryptor | None,
    type_tag: str,
    payload: dict[str, object],
) -> None:
    data = encode_frame(type_tag, payload)
    if cipher is not None:
        data = cipher.encrypt(data)
    await send(data)


@dataclasses.dataclass
class Tunnel:
    """An accepted tunnel. Bytes read from `reader` come from the host, after the handshake."""

    reader: FrpReader
    writer: asyncio.StreamWriter


async def _read_connect_status(reader: asyncio.StreamReader) -> tuple[str, int]:
    """Read the response head of an HTTP CONNECT. Return the version and the status code."""
    try:
        head = await reader.readuntil(b"\r\n\r\n")
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError) as e:
        raise exceptions.UI("Unable to reach bastion: invalid response") from e
    if len(head) > _MAX_CONNECT_RESPONSE:
        raise exceptions.UI("Unable to reach bastion: response too large")
    parts = head.split(b"\r\n", 1)[0].decode("ascii", errors="replace").split(" ", 2)
    if len(parts) < 2 or not parts[1].isdigit():
        raise exceptions.UI("Unable to reach bastion: invalid response")
    return parts[0], int(parts[1])


async def open_tunnel(url: str, hostname: str, token: str) -> Tunnel:
    """Open a tunnel to `hostname` through the bastion at `url` and present `token`.

    The token audience names the host on the bastion.
    Raises `exceptions.UI` if the bastion or the host refuses.
    """
    u = urllib.parse.urlsplit(url)
    host = u.hostname or url
    scheme_port = 443 if u.scheme == "https" else 80 if u.scheme == "http" else None
    port = u.port if u.port is not None else scheme_port

    if u.scheme not in ["http", "https"]:
        raise exceptions.UI(f"Unsupported url scheme={u.scheme}")

    ssl_context: ssl.SSLContext | None = None
    if u.scheme == "https":
        ssl_context = ssl.create_default_context()

    frpc_user = jwt_audience(token)
    reader, writer = await asyncio.open_connection(host, port, ssl=ssl_context)
    try:
        connect_target = f"{frpc_user}.{host}:{port}"
        writer.write(f"CONNECT {connect_target} HTTP/1.1\r\nHost: {connect_target}\r\n\r\n".encode("ascii"))
        await writer.drain()

        version, status_code = await _read_connect_status(reader)
        if version != "HTTP/1.1":
            raise exceptions.UI(f"Unable to reach bastion: version={version}")
        if status_code == 404:
            raise exceptions.UI(f'"{hostname}" is not registered')
        if status_code != 200:
            raise exceptions.UI(f"Unable to reach bastion: status_code={status_code}")

        async def raw_send(data: bytes) -> None:
            writer.write(data)
            await writer.drain()

        async def raw_recv() -> bytes:
            return await reader.read(65536)

        await write_frame(raw_send, None, HANDSHAKE_TAG, {"token": token})
        frame_reader = FrpReader(raw_recv, cipher=None)
        try:
            tag, resp = await read_frame(frame_reader)
        except EOFError as e:
            raise exceptions.UI("Bastion closed the connection") from e
        if tag != ACCEPT_TAG or not resp.get("ok"):
            reason = resp.get("reason", "rejected") if tag == ACCEPT_TAG else f"unexpected response tag={tag!r}"
            raise exceptions.UI(f"Bastion rejected connection: {reason}")
    except BaseException:
        writer.close()
        raise
    return Tunnel(reader=frame_reader, writer=writer)


async def send_command(url: str, hostname: str, token: str) -> None:
    """Send a command token to `hostname`. Return once the host has carried the command out."""
    tunnel = await open_tunnel(url, hostname, token)
    tunnel.writer.close()
