from __future__ import annotations

import asyncio
import datetime
import ipaddress
import logging
import os

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import pf.anet.base as base
import pf.anet.socket as anet_socket
import pf.anet.ssl as anet_ssl
import pf.anet.stream as stream

logger = logging.getLogger(__name__)


def _ipv6_available() -> bool:
    """Check if IPv6 is available (sync, for @pytest.mark.skipif at collection time)."""
    import socket as _socket
    try:
        s = _socket.socket(_socket.AF_INET6, _socket.SOCK_STREAM)
        s.close()
        return True
    except OSError:
        return False


def _create_server_context(
    certfile: str | os.PathLike[str],
    keyfile: str | os.PathLike[str],
) -> anet_ssl.SSLContext:
    """Create server-side SSL context from certificate and key files."""
    ctx = anet_ssl.SSLContext(anet_ssl.ContextProtocol.SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    return ctx


def _create_client_context(
    cafile: str | os.PathLike[str],
    check_hostname: bool = True,
) -> anet_ssl.SSLContext:
    """Create client-side SSL context with CA verification."""
    ctx = anet_ssl.SSLContext(anet_ssl.ContextProtocol.CLIENT)
    ctx.load_verify_locations(cafile)
    ctx.check_hostname = check_hostname
    ctx.verify_mode = anet_ssl.VerifyMode.REQUIRED
    return ctx


@pytest.fixture(scope="session")
def ssl_contexts(tmp_path_factory: pytest.TempPathFactory) -> tuple[anet_ssl.SSLContext, anet_ssl.SSLContext]:
    """Generate self-signed CA and server certificate; return (server_ctx, client_ctx)."""
    tmpdir = tmp_path_factory.mktemp("ssl")

    # Generate CA key and cert
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")]
    )
    now = datetime.datetime.now(datetime.UTC)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(
            now + datetime.timedelta(days=365)
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    # Generate server key and cert
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]
    )
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(ca_subject)
        .public_key(server_key.public_key())
        .serial_number(2)
        .not_valid_before(now)
        .not_valid_after(
            now + datetime.timedelta(days=365)
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    # Write to temp files
    ca_cert_file = tmpdir / "ca.pem"
    server_cert_file = tmpdir / "server.pem"
    server_key_file = tmpdir / "server.key"

    ca_cert_file.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    server_cert_file.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    server_key_file.write_bytes(
        server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    # Create SSL contexts using anet factories
    server_ctx = _create_server_context(server_cert_file, server_key_file)
    client_ctx = _create_client_context(ca_cert_file, check_hostname=False)

    # Wrap in anet.ssl.SSLContext
    return server_ctx, client_ctx


@pytest.fixture
async def anet_socketpair() -> tuple[anet_socket.Socket, anet_socket.Socket]:
    """Create a connected AF_UNIX socketpair wrapped in anet.socket.Socket."""
    a, b = await anet_socket.socketpair(anet_socket.Family.UNIX, anet_socket.Type.STREAM)
    yield a, b
    await a.close()
    await b.close()


@pytest.fixture
async def tls_socketpair(
    anet_socketpair: tuple[anet_socket.Socket, anet_socket.Socket],
    ssl_contexts: tuple[anet_ssl.SSLContext, anet_ssl.SSLContext],
) -> tuple[anet_ssl.Socket, anet_ssl.Socket]:
    """Create a TLS-wrapped socketpair with completed handshake."""
    raw_client, raw_server = anet_socketpair
    server_ctx, client_ctx = ssl_contexts

    ssl_server = await server_ctx.wrap_socket(raw_server, server_side=True)
    ssl_client = await client_ctx.wrap_socket(raw_client, server_side=False, server_hostname=None)

    # Handshake must be concurrent
    await asyncio.gather(ssl_server.handshake(), ssl_client.handshake())

    yield ssl_client, ssl_server
    await ssl_client.close()
    await ssl_server.close()


# ===== Plain Socket Tests =====


@pytest.mark.anyio
async def test_socket_bidirectional_echo(anet_socketpair: tuple[anet_socket.Socket, anet_socket.Socket]) -> None:
    """Client sends data, server echoes it back."""
    client, server = anet_socketpair
    test_data = b"hello from client"

    await client.send(test_data)
    received = await server.recv(4096)
    assert received == test_data
    await server.send(test_data)
    echoed = await client.recv(4096)
    assert echoed == test_data


@pytest.mark.anyio
async def test_socket_large_data(anet_socketpair: tuple[anet_socket.Socket, anet_socket.Socket]) -> None:
    """Transfer 256 KiB of data bidirectionally."""
    client, server = anet_socketpair
    test_data = b"x" * (256 * 1024)

    async def server_task() -> None:
        buf = b""
        while len(buf) < len(test_data):
            chunk = await server.recv(65536)
            assert chunk, "Server received EOF before all data"
            buf += chunk
        assert buf == test_data
        await server.send(buf)

    async def client_task() -> None:
        await client.send(test_data)
        # Receive echo
        buf = b""
        while len(buf) < len(test_data):
            chunk = await client.recv(65536)
            assert chunk, "Client received EOF before echo"
            buf += chunk
        assert buf == test_data

    await asyncio.gather(client_task(), server_task())


@pytest.mark.anyio
async def test_socket_eof_on_close(anet_socketpair: tuple[anet_socket.Socket, anet_socket.Socket]) -> None:
    """Close socket; peer should recv b''."""
    client, server = anet_socketpair
    await client.send(b"ping")
    received = await server.recv(4096)
    assert received == b"ping"

    await client.close()
    eof = await server.recv(4096)
    assert eof == b""


@pytest.mark.anyio
async def test_socket_shutdown_wr_causes_eof(anet_socketpair: tuple[anet_socket.Socket, anet_socket.Socket]) -> None:
    """shutdown(SHUT_WR) signals EOF to peer; reverse direction still works."""
    client, server = anet_socketpair

    # Client half-closes write side
    await client.shutdown(base.Shut.WR)

    # Server should recv EOF
    eof = await server.recv(4096)
    assert eof == b""

    # But server can still send
    await server.send(b"still works")
    response = await client.recv(4096)
    assert response == b"still works"


@pytest.mark.anyio
async def test_socket_ipv4_loopback_echo() -> None:
    """Real TCP on 127.0.0.1 with listen/accept/connect."""
    # Server: create socket, bind, listen
    server_sock = await anet_socket.socket(anet_socket.Family.INET, anet_socket.Type.STREAM)
    await server_sock.bind(("127.0.0.1", 0))
    await server_sock.listen(1)
    server_addr = server_sock.getsockname()

    # Client: create socket, connect
    client_sock = await anet_socket.socket(anet_socket.Family.INET, anet_socket.Type.STREAM)
    await client_sock.connect(server_addr)

    # Server: accept connection
    accepted, _ = await server_sock.accept()

    # Exchange data
    test_data = b"ipv4-test"
    await client_sock.send(test_data)
    received = await accepted.recv(4096)
    assert received == test_data

    # Cleanup
    await client_sock.close()
    await accepted.close()
    await server_sock.close()


@pytest.mark.anyio
@pytest.mark.skipif(not _ipv6_available(), reason="IPv6 not available")
async def test_socket_ipv6_loopback_echo() -> None:
    """Real TCP on ::1 with listen/accept/connect."""
    # Server: create socket, bind, listen
    server_sock = await anet_socket.socket(anet_socket.Family.INET6, anet_socket.Type.STREAM)
    await server_sock.bind(("::1", 0, 0, 0))
    await server_sock.listen(1)
    server_addr = server_sock.getsockname()

    # Client: create socket, connect
    client_sock = await anet_socket.socket(anet_socket.Family.INET6, anet_socket.Type.STREAM)
    await client_sock.connect(server_addr)

    # Server: accept connection
    accepted, _ = await server_sock.accept()

    # Exchange data
    test_data = b"ipv6-test"
    await client_sock.send(test_data)
    received = await accepted.recv(4096)
    assert received == test_data

    # Cleanup
    await client_sock.close()
    await accepted.close()
    await server_sock.close()


# ===== TLS Socket Tests =====


@pytest.mark.anyio
async def test_ssl_handshake_bidirectional_echo(tls_socketpair: tuple[anet_ssl.Socket, anet_ssl.Socket]) -> None:
    """After handshake, exchange data over TLS."""
    client, server = tls_socketpair
    test_data = b"tls hello from client"

    async def server_task() -> None:
        buf = b""
        while len(buf) < len(test_data):
            chunk = await server.recv(65536)
            if not chunk:
                break
            buf += chunk
        assert buf == test_data
        await server.send(buf)

    async def client_task() -> None:
        await client.send(test_data)
        buf = b""
        while len(buf) < len(test_data):
            chunk = await client.recv(65536)
            if not chunk:
                break
            buf += chunk
        assert buf == test_data

    await asyncio.gather(client_task(), server_task())


@pytest.mark.anyio
async def test_ssl_large_data(tls_socketpair: tuple[anet_ssl.Socket, anet_ssl.Socket]) -> None:
    """Transfer 128 KiB over TLS."""
    client, server = tls_socketpair
    test_data = b"y" * (128 * 1024)

    async def server_task() -> None:
        buf = b""
        while len(buf) < len(test_data):
            chunk = await server.recv(65536)
            if not chunk:
                break
            buf += chunk
        assert buf == test_data
        await server.send(buf)

    async def client_task() -> None:
        await client.send(test_data)
        buf = b""
        while len(buf) < len(test_data):
            chunk = await client.recv(65536)
            if not chunk:
                break
            buf += chunk
        assert buf == test_data

    await asyncio.gather(client_task(), server_task())


@pytest.mark.anyio
async def test_ssl_clean_eof_via_close_notify(tls_socketpair: tuple[anet_ssl.Socket, anet_ssl.Socket]) -> None:
    """Client shutdown triggers TLS close_notify; server receives EOF."""
    client, server = tls_socketpair

    # Exchange one message
    await client.send(b"ping")
    received = await server.recv(65536)
    assert received == b"ping"

    # Client initiates TLS shutdown
    await client.shutdown(base.Shut.WR)

    # Server should receive EOF (triggered by SSLEOFError in recv)
    eof = await server.recv(65536)
    assert eof == b""


@pytest.mark.anyio
async def test_ssl_eof_during_handshake(anet_socketpair: tuple[anet_socket.Socket, anet_socket.Socket],
                                        ssl_contexts: tuple[anet_ssl.SSLContext, anet_ssl.SSLContext]) -> None:
    """Close raw socket during TLS handshake; expect ConnectionError."""
    raw_client, raw_server = anet_socketpair
    _server_ctx, client_ctx = ssl_contexts

    ssl_client = await client_ctx.wrap_socket(raw_client, server_side=False, server_hostname=None)

    # Start client handshake
    client_task = asyncio.create_task(ssl_client.handshake())

    # Yield to let client start the handshake
    await asyncio.sleep(0)

    # Close the raw server socket before handshake completes
    await raw_server.close()

    # Client handshake should raise ConnectionError
    with pytest.raises(ConnectionError):
        await client_task


@pytest.mark.anyio
async def test_ssl_recv_ignores_n(tls_socketpair: tuple[anet_ssl.Socket, anet_ssl.Socket]) -> None:
    """recv(n) ignores n and returns one full TLS record (design feature)."""
    client, server = tls_socketpair
    test_data = b"x" * 1000

    # Use a task to request recv while server is sending
    recv_task = asyncio.create_task(client.recv(1))
    await asyncio.sleep(0)  # Yield
    await server.send(test_data)

    record_data = await recv_task
    # Should receive all 1000 bytes, not just 1
    assert len(record_data) >= len(test_data)
    assert test_data in record_data  # The data should be in the record


@pytest.mark.anyio
async def test_ssl_recv_skips_protocol_records(tls_socketpair: tuple[anet_ssl.Socket, anet_ssl.Socket]) -> None:
    """recv loop handles protocol messages (e.g., session tickets) transparently."""
    client, server = tls_socketpair

    # Immediately after handshake, TLS 1.3 may send NewSessionTicket.
    # Calling recv on client should skip it and return data once server sends.
    test_data = b"hello after ticket"

    async def server_task() -> None:
        await asyncio.sleep(0.01)
        await server.send(test_data)

    async def client_task() -> None:
        buf = b""
        while len(buf) < len(test_data):
            chunk = await client.recv(65536)
            if not chunk:
                break
            buf += chunk
        assert buf == test_data

    await asyncio.gather(client_task(), server_task())


# ===== Stream Reader Tests =====


@pytest.mark.anyio
async def test_stream_read_until_single_recv(anet_socketpair: tuple[anet_socket.Socket, anet_socket.Socket]) -> None:
    """read_until finds delimiter in single recv."""
    client, server = anet_socketpair
    test_line = b"hello\n"

    read_task = asyncio.create_task(stream.Reader(client).read_until(b"\n"))
    await asyncio.sleep(0)
    await server.send(test_line)
    result = await read_task
    assert result == test_line


@pytest.mark.anyio
async def test_stream_read_until_spanning_recvs(anet_socketpair: tuple[anet_socket.Socket, anet_socket.Socket]) -> None:
    """read_until finds delimiter spanning multiple recvs."""
    client, server = anet_socketpair
    chunk1 = b"hel"
    chunk2 = b"lo\nworld"

    async def server_send_chunks() -> None:
        await server.send(chunk1)
        await asyncio.sleep(0.01)
        await server.send(chunk2)

    reader = stream.Reader(client)
    read_task = asyncio.create_task(reader.read_until(b"\n"))
    await asyncio.sleep(0)
    await server_send_chunks()
    result = await read_task
    assert result == b"hello\n"


@pytest.mark.anyio
async def test_stream_read_until_eof_before_delimiter(
    anet_socketpair: tuple[anet_socket.Socket, anet_socket.Socket],
) -> None:
    """read_until raises IncompleteReadError if EOF before delimiter."""
    client, server = anet_socketpair

    async def server_close() -> None:
        await server.send(b"no newline here")
        await server.close()

    async def client_read() -> None:
        reader = stream.Reader(client)
        with pytest.raises(stream.IncompleteReadError):
            await reader.read_until(b"\n")

    await asyncio.gather(client_read(), server_close())


@pytest.mark.anyio
async def test_stream_read_until_multiple_sequential(
    anet_socketpair: tuple[anet_socket.Socket, anet_socket.Socket],
) -> None:
    """Multiple sequential read_until calls consume buffer correctly."""
    client, server = anet_socketpair
    test_data = b"line1\nline2\nline3\n"

    async def client_task() -> None:
        reader = stream.Reader(client)
        line1 = await reader.read_until(b"\n")
        assert line1 == b"line1\n"
        line2 = await reader.read_until(b"\n")
        assert line2 == b"line2\n"
        line3 = await reader.read_until(b"\n")
        assert line3 == b"line3\n"

    async def server_task() -> None:
        await server.send(test_data)

    await asyncio.gather(client_task(), server_task())


@pytest.mark.anyio
async def test_stream_read_until_remainder_buffered(
    anet_socketpair: tuple[anet_socket.Socket, anet_socket.Socket],
) -> None:
    """read_until leaves remainder in buffer for next call."""
    client, server = anet_socketpair
    test_data = b"AAAA\nBBBB\n"

    async def client_task() -> None:
        reader = stream.Reader(client)
        first = await reader.read_until(b"\n")
        assert first == b"AAAA\n"
        # BBBB\n is now in the reader's buffer; no more socket recv needed
        second = await reader.read_until(b"\n")
        assert second == b"BBBB\n"

    async def server_task() -> None:
        await server.send(test_data)

    await asyncio.gather(client_task(), server_task())


@pytest.mark.anyio
async def test_stream_read_until_plain_socket(anet_socketpair: tuple[anet_socket.Socket, anet_socket.Socket]) -> None:
    """read_until works with plain anet.socket.Socket."""
    client, server = anet_socketpair
    test_line = b"plain socket\n"

    read_task = asyncio.create_task(stream.Reader(client).read_until(b"\n"))
    await asyncio.sleep(0)
    await server.send(test_line)
    result = await read_task
    assert result == test_line


@pytest.mark.anyio
async def test_stream_read_until_ssl_socket(tls_socketpair: tuple[anet_ssl.Socket, anet_ssl.Socket]) -> None:
    """read_until works with TLS anet.ssl.Socket."""
    client, server = tls_socketpair
    test_line = b"tls data\n"

    read_task = asyncio.create_task(stream.Reader(client).read_until(b"\n"))
    await asyncio.sleep(0)
    await server.send(test_line)
    result = await read_task
    assert result == test_line
