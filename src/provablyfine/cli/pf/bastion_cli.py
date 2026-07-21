from __future__ import annotations

import argparse
import asyncio
import base64
import collections.abc
import contextlib
import functools
import hashlib
import itertools
import json
import logging
import os
import platform
import signal
import ssl
import struct
import sys
import time
import urllib.parse

import cryptography.hazmat.decrepit.ciphers.modes
import cryptography.hazmat.primitives.ciphers
import cryptography.hazmat.primitives.ciphers.algorithms
import provablyfine_client as pfc

from ... import client
from .. import http as cli_http
from .. import login

logger = logging.getLogger(__name__)

_FRP_VERSION = "0.69.1"
_HEARTBEAT_INTERVAL = 30.0
_HEARTBEAT_TIMEOUT = 90.0
_FRP_WS_PATH = "/~!frp"  # frp's fixed WebSocket upgrade path (fatedier/frp)


def _jwt_audience(token: str) -> str:
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    claims = json.loads(base64.urlsafe_b64decode(payload))
    return str(claims["aud"])


# ---------------------------------------------------------------------------
# AES-128-CFB stream cipher (matches Go's golib/crypto v0.7.0 NewWriter/NewReader)
# ---------------------------------------------------------------------------


def _frp_derive_key(token: str) -> bytes:
    """PBKDF2(token, salt='frp', iterations=64, dklen=16, hash=SHA1).

    Matches Go's golib/crypto with DefaultSalt overridden to 'frp' by frp service.
    Token is empty when frps uses plugin/OIDC auth with no static auth.token.
    """
    return hashlib.pbkdf2_hmac("sha1", token.encode(), b"frp", 64, 16)


class _AESCFBEncryptor:
    """AES-128-CFB stream encryptor.

    Prepends a random 16-byte IV to the first write, then streams CFB ciphertext.
    Matches Go's golib/crypto.NewWriter behaviour.
    """

    def __init__(self, key: bytes) -> None:
        iv = os.urandom(16)
        c = cryptography.hazmat.primitives.ciphers.Cipher(
            cryptography.hazmat.primitives.ciphers.algorithms.AES(key),
            cryptography.hazmat.decrepit.ciphers.modes.CFB(iv),
        )
        self._enc = c.encryptor()
        self._iv: bytes | None = iv

    def encrypt(self, data: bytes) -> bytes:
        if self._iv is not None:
            prefix, self._iv = self._iv, None
            return prefix + self._enc.update(data)
        return self._enc.update(data)


class _AESCFBDecryptor:
    """AES-128-CFB stream decryptor.

    Reads a 16-byte IV from the first bytes of the stream, then decrypts.
    Matches Go's golib/crypto.NewReader behaviour.
    """

    def __init__(self, key: bytes) -> None:
        self._key = key
        self._iv_buf = bytearray()
        self._dec: cryptography.hazmat.primitives.ciphers.CipherContext | None = None

    def decrypt(self, data: bytes) -> bytes:
        if self._dec is not None:
            return self._dec.update(data)
        needed = 16 - len(self._iv_buf)
        if len(data) < needed:
            self._iv_buf.extend(data)
            return b""
        self._iv_buf.extend(data[:needed])
        c = cryptography.hazmat.primitives.ciphers.Cipher(
            cryptography.hazmat.primitives.ciphers.algorithms.AES(self._key),
            cryptography.hazmat.decrepit.ciphers.modes.CFB(bytes(self._iv_buf)),
        )
        self._dec = c.decryptor()
        remaining = data[needed:]
        return self._dec.update(remaining) if remaining else b""


# ---------------------------------------------------------------------------
# Frp message framing
# ---------------------------------------------------------------------------


def _frp_encode(type_tag: str, payload: dict[str, object]) -> bytes:
    data = json.dumps(payload, separators=(",", ":")).encode()
    return bytes([ord(type_tag)]) + struct.pack(">Q", len(data)) + data


class _FrpReader:
    """Buffered reader that decrypts bytes from a TCP or WSS transport and
    exposes readexactly() for frp message parsing.
    """

    def __init__(
        self,
        recv: collections.abc.Callable[[], collections.abc.Awaitable[bytes]],
        cipher: _AESCFBDecryptor | None,
    ) -> None:
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


async def _frp_read(frp_reader: _FrpReader) -> tuple[str, dict[str, object]]:
    header = await frp_reader.readexactly(9)
    tag = chr(header[0])
    length = struct.unpack(">Q", header[1:])[0]
    payload: dict[str, object] = json.loads(await frp_reader.readexactly(length))
    return tag, payload


# ---------------------------------------------------------------------------
# Transport: open a TCP or WSS connection to frps
# ---------------------------------------------------------------------------

_RecvFn = collections.abc.Callable[[], collections.abc.Awaitable[bytes]]
_SendFn = collections.abc.Callable[[bytes], collections.abc.Awaitable[None]]


def _xor_mask(data: bytes, mask: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, itertools.cycle(mask)))


def _ws_encode_frame(payload: bytes, opcode: int = 0x2) -> bytes:
    """Encode a client→server masked WebSocket frame (RFC 6455). Default opcode: binary (0x2)."""
    mask = os.urandom(4)
    n = len(payload)
    header = bytearray([0x80 | opcode])  # FIN=1
    if n < 126:
        header.append(0x80 | n)
    elif n < 65536:
        header.append(0x80 | 126)
        header.extend(struct.pack(">H", n))
    else:
        header.append(0x80 | 127)
        header.extend(struct.pack(">Q", n))
    header.extend(mask)
    return bytes(header) + _xor_mask(payload, mask)


async def _ws_read_frame(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bytes:
    """Read one server→client WebSocket frame and return its payload.

    frps (gorilla/websocket) sends TEXT frames for frp messages regardless of
    whether the content is valid UTF-8 (e.g. after cipher is enabled).  We read
    raw bytes here and ignore the TEXT/BINARY distinction so encrypted content
    is not rejected.  Server→client frames are never masked per RFC 6455.
    Ping frames are answered with pong as required by RFC 6455 §5.5.3.
    """
    while True:
        hdr = await reader.readexactly(2)
        opcode = hdr[0] & 0x0F
        masked = bool(hdr[1] & 0x80)
        length = hdr[1] & 0x7F
        if length == 126:
            length = struct.unpack(">H", await reader.readexactly(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", await reader.readexactly(8))[0]
        if masked:
            mask_bytes = await reader.readexactly(4)
            payload = _xor_mask(await reader.readexactly(length), mask_bytes)
        else:
            payload = await reader.readexactly(length)
        if opcode == 0x8:  # close
            raise EOFError("WebSocket closed by server")
        if opcode == 0x9:  # ping - echo payload back as pong
            writer.write(_ws_encode_frame(payload, 0xA))
            await writer.drain()
            continue
        if opcode == 0xA:  # pong - skip
            continue
        return payload


async def _ws_connect(
    host: str,
    port: int,
    ssl_ctx: ssl.SSLContext | None,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Open a raw TCP connection and perform WebSocket upgrade to frp's control path."""
    reader, writer = await asyncio.open_connection(host, port, ssl=ssl_ctx)
    key = base64.b64encode(os.urandom(16)).decode()
    default_port = 443 if ssl_ctx else 80
    host_header = host if port == default_port else f"{host}:{port}"
    await cli_http.Request(
        method="GET",
        resource_target=_FRP_WS_PATH,
        version="HTTP/1.1",
        headers={
            "Host": host_header,
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": key,
            "Sec-WebSocket-Version": "13",
            "Origin": f"http://{host}",
        },
        body=b"",
    ).serialize(writer)
    response = await cli_http.Response.deserialize(reader)
    if response.status_code != 101:
        writer.close()
        raise OSError(f"server rejected WebSocket connection: HTTP {response.status_code}")
    return reader, writer


@contextlib.asynccontextmanager
async def _open_transport(
    host: str,
    port: int,
    ssl_ctx: ssl.SSLContext | None,
) -> collections.abc.AsyncGenerator[tuple[_RecvFn, _SendFn]]:
    reader, writer = await _ws_connect(host, port, ssl_ctx)

    async def ws_recv() -> bytes:
        return await _ws_read_frame(reader, writer)

    async def ws_send(msg: bytes) -> None:
        writer.write(_ws_encode_frame(msg))
        await writer.drain()

    try:
        yield ws_recv, ws_send
    finally:
        writer.close()


async def _frp_write(
    send: _SendFn,
    cipher: _AESCFBEncryptor | None,
    type_tag: str,
    payload: dict[str, object],
) -> None:
    data = _frp_encode(type_tag, payload)
    if cipher is not None:
        data = cipher.encrypt(data)
    await send(data)


# ---------------------------------------------------------------------------
# Work connection handling
# ---------------------------------------------------------------------------


def _local_arch() -> str:
    m = platform.machine().lower()
    return {"x86_64": "amd64", "aarch64": "arm64"}.get(m, m)


async def _handle_work_conn(
    host: str,
    port: int,
    ssl_ctx: ssl.SSLContext | None,
    run_id: str,
    local_ip: str,
    local_port: int,
) -> None:
    try:
        async with _open_transport(host, port, ssl_ctx) as (recv, send):
            # Work connections do NOT use the stream cipher.
            frp_reader = _FrpReader(recv, cipher=None)
            await _frp_write(send, None, "w", {"run_id": run_id})
            tag, msg = await _frp_read(frp_reader)
            if tag != "s":
                logger.debug(f"work conn: unexpected tag={tag!r}")
                return
            if msg.get("error"):
                logger.debug(f"work conn: rejected: {msg['error']}")
                return

            local_reader, local_writer = await asyncio.open_connection(local_ip, local_port)

            async def frps_to_local() -> None:
                try:
                    while True:
                        data = await recv()
                        if not data:
                            break
                        local_writer.write(data)
                except Exception:
                    pass

            async def local_to_frps() -> None:
                try:
                    while True:
                        data = await local_reader.read(65536)
                        if not data:
                            break
                        await send(data)
                except Exception:
                    pass

            try:
                await asyncio.gather(frps_to_local(), local_to_frps())
            finally:
                local_writer.close()
    except Exception as e:
        logger.debug(f"work conn: failed: {e}")


# ---------------------------------------------------------------------------
# Main frp client loop
# ---------------------------------------------------------------------------


async def _run_frp_client(
    sc: pfc.AsyncSessionClient,
    bastion_url: str,
    identity_name: str,
    local_port: int,
    stop_event: asyncio.Event,
    frps_bind_port: int | None = None,
) -> None:
    u = urllib.parse.urlsplit(bastion_url)
    host = u.hostname or bastion_url
    server_port = frps_bind_port or u.port or (443 if u.scheme == "https" else 80)
    ssl_ctx: ssl.SSLContext | None = ssl.create_default_context() if u.scheme == "https" else None

    while not stop_event.is_set():
        # Refresh token on each (re)connect attempt.
        try:
            token_response = await sc.get_self_token("bastion", hostname=identity_name)
            jwt_token = token_response.token
            frpc_user = _jwt_audience(jwt_token)
        except Exception as e:
            logger.warning(f"Failed to obtain frp token for bastion={bastion_url}: {e}")
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=5)
            except TimeoutError:
                pass
            continue

        connected = False
        try:
            async with _open_transport(host, server_port, ssl_ctx) as (recv, send):
                connected = True
                logger.info(f"frp: connected to bastion={bastion_url}")
                await _frp_session(
                    recv=recv,
                    send=send,
                    host=host,
                    server_port=server_port,
                    ssl_ctx=ssl_ctx,
                    jwt_token=jwt_token,
                    frpc_user=frpc_user,
                    identity_name=identity_name,
                    local_port=local_port,
                    stop_event=stop_event,
                )
        except Exception as e:
            if connected:
                logger.warning(f"frp: session ended for bastion={bastion_url}: {e}")
            else:
                logger.warning(f"frp: transport connect failed for bastion={bastion_url}: {e}")

        if not stop_event.is_set():
            logger.info(f"frp: reconnecting in 5s for bastion={bastion_url}")
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=5)
            except TimeoutError:
                pass


async def _frp_session(
    *,
    recv: _RecvFn,
    send: _SendFn,
    host: str,
    server_port: int,
    ssl_ctx: ssl.SSLContext | None,
    jwt_token: str,
    frpc_user: str,
    identity_name: str,
    local_port: int,
    stop_event: asyncio.Event,
) -> None:
    # --- Login ---
    login_msg: dict[str, object] = {
        "version": _FRP_VERSION,
        "hostname": identity_name,
        "os": platform.system().lower(),
        "arch": _local_arch(),
        "user": frpc_user,
        "privilege_key": jwt_token,
        "timestamp": int(time.time()),
        "run_id": "",
        "pool_count": 1,
    }
    # Before cipher: write Login in plain frp framing.
    plain_reader = _FrpReader(recv, cipher=None)
    await _frp_write(send, None, "o", login_msg)

    tag, resp = await _frp_read(plain_reader)
    if tag != "1":
        raise OSError(f"expected LoginResp, got tag={tag!r}")
    if resp.get("error"):
        raise OSError(f"Login rejected: {resp['error']}")
    run_id = str(resp.get("run_id", ""))
    logger.info(f"frp: logged in run_id={run_id}")

    # --- Enable AES-128-CFB stream cipher on control connection ---
    # frps derives the cipher key from auth.token (empty when plugin/OIDC auth is used).
    # Key = PBKDF2(token, salt='frp', iterations=64, dklen=16, hash=SHA1).
    # Writer prepends a random 16-byte IV on first write; reader reads that IV first.
    cipher_key = _frp_derive_key("")
    cipher_r = _AESCFBDecryptor(cipher_key)
    cipher_w = _AESCFBEncryptor(cipher_key)
    enc_reader = _FrpReader(recv, cipher=cipher_r)

    # --- Register proxy ---
    proxy_msg: dict[str, object] = {
        "proxy_name": "ssh",
        "proxy_type": "tcpmux",
        "multiplexer": "httpconnect",
        "local_ip": "127.0.0.1",
        "local_port": local_port,
        "custom_domains": [f"{frpc_user}.{host}"],
    }
    await _frp_write(send, cipher_w, "p", proxy_msg)

    background_tasks: set[asyncio.Task[None]] = set()

    def spawn_work_conn() -> None:
        t: asyncio.Task[None] = asyncio.create_task(
            _handle_work_conn(host, server_port, ssl_ctx, run_id, "127.0.0.1", local_port)
        )
        background_tasks.add(t)
        t.add_done_callback(background_tasks.discard)

    loop = asyncio.get_running_loop()
    last_ping = loop.time()

    try:
        while not stop_event.is_set():
            now = loop.time()
            elapsed = now - last_ping
            timeout = max(0.1, _HEARTBEAT_INTERVAL - elapsed)

            try:
                tag, msg = await asyncio.wait_for(_frp_read(enc_reader), timeout=timeout)
            except TimeoutError:
                if loop.time() - last_ping > _HEARTBEAT_TIMEOUT:
                    raise OSError("heartbeat timeout")
                await _frp_write(send, cipher_w, "h", {})
                last_ping = loop.time()
                continue

            if tag == "2":  # NewProxyResp
                if msg.get("error"):
                    raise OSError(f"NewProxy rejected: {msg['error']}")
                logger.info("frp: proxy registered")
            elif tag == "r":  # ReqWorkConn
                spawn_work_conn()
            elif tag == "4":  # Pong
                last_ping = loop.time()
            else:
                logger.debug(f"frp: unhandled control tag={tag!r}")
    finally:
        for t in list(background_tasks):
            t.cancel()
        if background_tasks:
            await asyncio.gather(*background_tasks, return_exceptions=True)


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------


@client.ssh_utils.exception
def _register_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    factory = client.Factory(c, timeout=args.timeout)
    login.ensure_session(c, factory)

    async def _run() -> None:
        loop = asyncio.get_running_loop()
        stop_event = asyncio.Event()

        def signal_handler() -> None:
            stop_event.set()

        loop.add_signal_handler(signal.SIGTERM, signal_handler)
        loop.add_signal_handler(signal.SIGINT, signal_handler)

        sc = client.Factory(c, timeout=args.timeout).async_session()
        identity = await sc.get_self()
        identity_name = identity.name

        active_tasks: dict[int, asyncio.Task[None]] = {}

        def done_callback(bastion_id: int, task: asyncio.Task[None]) -> None:
            active_tasks.pop(bastion_id, None)

        while not stop_event.is_set():
            try:
                bastions_response = await sc.list_self_bastions()
                current_bastions = {b.id: b for b in bastions_response.bastions}

                for bastion_id in list(active_tasks.keys()):
                    if bastion_id not in current_bastions:
                        task = active_tasks.pop(bastion_id)
                        task.cancel()

                for bastion_id, bastion in current_bastions.items():
                    if bastion_id in active_tasks:
                        continue
                    task = asyncio.create_task(
                        _run_frp_client(sc, bastion.url, identity_name, args.port, stop_event, args.frps_bind_port)
                    )
                    active_tasks[bastion_id] = task
                    task.add_done_callback(functools.partial(done_callback, bastion_id))
            except Exception as e:
                logger.debug(f"Poll error: {e}")

            try:
                await asyncio.wait_for(stop_event.wait(), timeout=args.poll_interval)
            except TimeoutError:
                pass

        for task in list(active_tasks.values()):
            task.cancel()
        if active_tasks:
            await asyncio.gather(*active_tasks.values(), return_exceptions=True)

    asyncio.run(_run())


async def connect_async(url: str, hostname: str, sc: pfc.AsyncSessionClient) -> None:
    u = urllib.parse.urlsplit(url)
    host = u.hostname or url
    scheme_port = 443 if u.scheme == "https" else 80 if u.scheme == "http" else None
    port = u.port if u.port is not None else scheme_port

    if u.scheme not in ["http", "https"]:
        raise pfc.exceptions.UI(f"Unsupported url scheme={u.scheme}")

    ssl_context: ssl.SSLContext | None = None
    if u.scheme == "https":
        ssl_context = ssl.create_default_context()

    token_response = await sc.get_self_token("bastion", hostname=hostname)
    frpc_user = _jwt_audience(token_response.token)

    reader, writer = await asyncio.open_connection(host, port, ssl=ssl_context)

    connect_target = f"{frpc_user}.{host}:{port}"
    await cli_http.Request(
        method="CONNECT",
        resource_target=connect_target,
        version="HTTP/1.1",
        headers={"Host": connect_target},
        body=b"",
    ).serialize(writer)

    response = await cli_http.Response.deserialize(reader)
    if response.version != "HTTP/1.1":
        raise pfc.exceptions.UI(f"Unable to reach bastion: version={response.version}")
    if response.status_code == 404:
        raise pfc.exceptions.UI(f'"{hostname}" is not registered')
    if response.status_code != 200:
        raise pfc.exceptions.UI(f"Unable to reach bastion: status_code={response.status_code}")

    loop = asyncio.get_running_loop()

    stdin_reader = asyncio.StreamReader()
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(stdin_reader), sys.stdin.buffer)
    stdout_transport, _ = await loop.connect_write_pipe(asyncio.BaseProtocol, sys.stdout.buffer)

    async def forward_stdin() -> None:
        while True:
            data = await stdin_reader.read(4096)
            if not data:
                break
            writer.write(data)
            await writer.drain()
        try:
            writer.write_eof()
        except (NotImplementedError, OSError):
            writer.close()

    async def forward_stdout() -> None:
        while True:
            data = await reader.read(4096)
            if not data:
                break
            stdout_transport.write(data)

    async def _run_both() -> None:
        await asyncio.gather(forward_stdin(), forward_stdout())

    gather_task: asyncio.Task[None] = asyncio.create_task(_run_both())

    def signal_handler() -> None:
        gather_task.cancel()

    loop.add_signal_handler(signal.SIGTERM, signal_handler)
    loop.add_signal_handler(signal.SIGINT, signal_handler)
    try:
        await gather_task
    except asyncio.CancelledError:
        pass


def _connect_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    factory = client.Factory(c, timeout=args.timeout)
    login.ensure_session(c, factory)

    async def _run() -> None:
        sc = factory.async_session()
        await connect_async(args.url, args.hostname, sc)

    asyncio.run(_run())


def add_subparser(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(required=True, dest="subcommand", metavar="subcommand")

    register_parser = sub.add_parser("register", help="Register with bastions")
    register_parser.add_argument("-p", "--port", type=int, default=2222, help="Local port to listen on")
    register_parser.add_argument(
        "-i",
        "--poll-interval",
        type=int,
        default=30,
        help="Interval in seconds to poll for bastions",
    )
    register_parser.add_argument(
        "--frps-bind-port",
        type=int,
        default=None,
        help="frps control port (overrides the port in the bastion URL;"
        " needed when the HTTP CONNECT port and the frps control port differ)",
    )
    register_parser.set_defaults(func=_register_function)

    connect_parser = sub.add_parser("connect", help="Connect via bastion")
    connect_parser.add_argument("--url", required=True, help="Bastion URL")
    connect_parser.add_argument("--hostname", required=True, help="Target hostname")
    connect_parser.set_defaults(func=_connect_function)
