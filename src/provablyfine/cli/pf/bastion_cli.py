from __future__ import annotations

import argparse
import asyncio
import base64
import functools
import hashlib
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

import cryptography.hazmat.primitives.ciphers
import cryptography.hazmat.primitives.ciphers.algorithms
import cryptography.hazmat.primitives.ciphers.modes
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
            cryptography.hazmat.primitives.ciphers.modes.CFB(iv),
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
            cryptography.hazmat.primitives.ciphers.modes.CFB(bytes(self._iv_buf)),
        )
        self._dec = c.decryptor()
        remaining = data[needed:]
        return self._dec.update(remaining) if remaining else b""


# ---------------------------------------------------------------------------
# WebSocket minimal framing (binary frames only)
# ---------------------------------------------------------------------------


def _ws_encode_frame(payload: bytes) -> bytes:
    """Encode a client→server masked binary WebSocket frame."""
    mask = os.urandom(4)
    length = len(payload)
    header = bytearray([0x82])  # FIN=1, opcode=binary(2)
    if length <= 125:
        header.append(0x80 | length)
    elif length <= 65535:
        header.append(0xFE)  # MASK=1, length=126
        header.extend(struct.pack(">H", length))
    else:
        header.append(0xFF)  # MASK=1, length=127
        header.extend(struct.pack(">Q", length))
    header.extend(mask)
    mask4 = mask * ((len(payload) + 3) // 4)
    return bytes(header) + bytes(a ^ b for a, b in zip(payload, mask4))


async def _ws_read_frame(reader: asyncio.StreamReader) -> bytes:
    """Read one server→client WebSocket frame and return its payload."""
    hdr = await reader.readexactly(2)
    length = hdr[1] & 0x7F
    if length == 126:
        length = struct.unpack(">H", await reader.readexactly(2))[0]
    elif length == 127:
        length = struct.unpack(">Q", await reader.readexactly(8))[0]
    return await reader.readexactly(length)


# ---------------------------------------------------------------------------
# Frp message framing
# ---------------------------------------------------------------------------


def _frp_encode(type_tag: str, payload: dict[str, object]) -> bytes:
    data = json.dumps(payload, separators=(",", ":")).encode()
    return bytes([ord(type_tag)]) + struct.pack(">Q", len(data)) + data


class _FrpReader:
    """Buffered reader that decrypts bytes from a TCP or WSS stream and
    exposes readexactly() for frp message parsing.
    """

    def __init__(
        self,
        reader: asyncio.StreamReader,
        cipher: _AESCFBDecryptor | None,
        is_wss: bool,
    ) -> None:
        self._reader = reader
        self._cipher = cipher
        self._is_wss = is_wss
        self._buf = bytearray()

    async def _fill(self) -> None:
        if self._is_wss:
            data: bytes = await _ws_read_frame(self._reader)
        else:
            data = await self._reader.read(65536)
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


async def _open_transport(
    host: str,
    port: int,
    is_wss: bool,
    ssl_ctx: ssl.SSLContext | None,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    reader, writer = await asyncio.open_connection(host, port, ssl=ssl_ctx)
    if is_wss:
        key = base64.b64encode(os.urandom(16)).decode()
        await cli_http.Request(
            method="GET",
            resource_target=_FRP_WS_PATH,
            version="HTTP/1.1",
            headers={
                "Host": host,
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
            raise OSError(f"WebSocket upgrade failed: status={response.status_code}")
    return reader, writer


async def _frp_write(
    writer: asyncio.StreamWriter,
    cipher: _AESCFBEncryptor | None,
    is_wss: bool,
    type_tag: str,
    payload: dict[str, object],
) -> None:
    data = _frp_encode(type_tag, payload)
    if cipher is not None:
        data = cipher.encrypt(data)
    if is_wss:
        writer.write(_ws_encode_frame(data))
    else:
        writer.write(data)
    await writer.drain()


# ---------------------------------------------------------------------------
# Work connection handling
# ---------------------------------------------------------------------------


def _local_arch() -> str:
    m = platform.machine().lower()
    return {"x86_64": "amd64", "aarch64": "arm64"}.get(m, m)


async def _handle_work_conn(
    host: str,
    port: int,
    is_wss: bool,
    ssl_ctx: ssl.SSLContext | None,
    run_id: str,
    local_ip: str,
    local_port: int,
) -> None:
    try:
        reader, writer = await _open_transport(host, port, is_wss, ssl_ctx)
    except Exception as e:
        logger.debug(f"work conn: transport open failed: {e}")
        return

    # Work connections do NOT use the stream cipher.
    frp_reader = _FrpReader(reader, cipher=None, is_wss=is_wss)
    try:
        await _frp_write(writer, None, is_wss, "w", {"run_id": run_id})
        tag, msg = await _frp_read(frp_reader)
        if tag != "s":
            logger.debug(f"work conn: unexpected tag={tag!r}")
            return
        if msg.get("error"):
            logger.debug(f"work conn: rejected: {msg['error']}")
            return
    except Exception as e:
        logger.debug(f"work conn: handshake failed: {e}")
        writer.close()
        return

    try:
        local_reader, local_writer = await asyncio.open_connection(local_ip, local_port)
    except Exception as e:
        logger.debug(f"work conn: cannot connect to local {local_ip}:{local_port}: {e}")
        writer.close()
        return

    async def frps_to_local() -> None:
        try:
            while True:
                data = await _ws_read_frame(reader) if is_wss else await reader.read(65536)
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
                writer.write(_ws_encode_frame(data) if is_wss else data)
        except Exception:
            pass

    try:
        await asyncio.gather(frps_to_local(), local_to_frps())
    finally:
        writer.close()
        local_writer.close()


# ---------------------------------------------------------------------------
# Main frp client loop (replaces _manage_frpc)
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
    is_wss = u.scheme == "https"

    ssl_ctx: ssl.SSLContext | None = None
    if is_wss:
        ssl_ctx = ssl.create_default_context()

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

        try:
            reader, writer = await _open_transport(host, server_port, is_wss, ssl_ctx)
        except Exception as e:
            logger.warning(f"frp: transport connect failed for bastion={bastion_url}: {e}")
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=5)
            except TimeoutError:
                pass
            continue

        logger.info(f"frp: connected to bastion={bastion_url}")
        try:
            await _frp_session(
                reader=reader,
                writer=writer,
                host=host,
                server_port=server_port,
                is_wss=is_wss,
                ssl_ctx=ssl_ctx,
                jwt_token=jwt_token,
                frpc_user=frpc_user,
                identity_name=identity_name,
                local_port=local_port,
                stop_event=stop_event,
            )
        except Exception as e:
            logger.warning(f"frp: session ended for bastion={bastion_url}: {e}")
        finally:
            writer.close()

        if not stop_event.is_set():
            logger.info(f"frp: reconnecting in 5s for bastion={bastion_url}")
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=5)
            except TimeoutError:
                pass


async def _frp_session(
    *,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    host: str,
    server_port: int,
    is_wss: bool,
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
    plain_reader = _FrpReader(reader, cipher=None, is_wss=is_wss)
    await _frp_write(writer, None, is_wss, "o", login_msg)

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
    enc_reader = _FrpReader(reader, cipher=cipher_r, is_wss=is_wss)

    # --- Register proxy ---
    proxy_msg: dict[str, object] = {
        "proxy_name": "ssh",
        "proxy_type": "tcpmux",
        "multiplexer": "httpconnect",
        "local_ip": "127.0.0.1",
        "local_port": local_port,
        "custom_domains": [f"{frpc_user}.{host}"],
    }
    await _frp_write(writer, cipher_w, is_wss, "p", proxy_msg)

    # frps sends ReqWorkConn immediately on ctl.Start() before NewProxyResp arrives.
    # Collect work-conn tasks started during registration to manage their lifecycle.
    background_tasks: set[asyncio.Task[None]] = set()

    def spawn_work_conn() -> None:
        t: asyncio.Task[None] = asyncio.create_task(
            _handle_work_conn(host, server_port, is_wss, ssl_ctx, run_id, "127.0.0.1", local_port)
        )
        background_tasks.add(t)
        t.add_done_callback(background_tasks.discard)

    while True:
        tag, resp = await asyncio.wait_for(_frp_read(enc_reader), timeout=30.0)
        if tag == "2":  # NewProxyResp
            if resp.get("error"):
                raise OSError(f"NewProxy rejected: {resp['error']}")
            break
        if tag == "r":  # ReqWorkConn interleaved before NewProxyResp
            spawn_work_conn()
        else:
            logger.debug(f"frp: unhandled tag during proxy setup: {tag!r}")
    logger.info("frp: proxy registered")

    # --- Steady state ---
    loop = asyncio.get_running_loop()
    last_ping = loop.time()

    try:
        while not stop_event.is_set():
            now = loop.time()
            elapsed = now - last_ping
            timeout = max(0.1, _HEARTBEAT_INTERVAL - elapsed)

            try:
                tag, _msg = await asyncio.wait_for(_frp_read(enc_reader), timeout=timeout)
            except TimeoutError:
                # Time to send a ping.
                if loop.time() - last_ping > _HEARTBEAT_TIMEOUT:
                    raise OSError("heartbeat timeout")
                await _frp_write(writer, cipher_w, is_wss, "h", {})
                last_ping = loop.time()
                continue

            if tag == "r":  # ReqWorkConn
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
