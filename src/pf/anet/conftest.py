"""Shared fixtures and helpers for anet tests."""

from __future__ import annotations

import asyncio
import datetime
import ipaddress
import os

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import pf.anet.socket as anet_socket
import pf.anet.ssl as anet_ssl


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
    ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    now = datetime.datetime.now(datetime.UTC)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    # Generate server key and cert
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(ca_subject)
        .public_key(server_key.public_key())
        .serial_number(2)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
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

    # Create SSL contexts
    server_ctx = _create_server_context(server_cert_file, server_key_file)
    client_ctx = _create_client_context(ca_cert_file, check_hostname=False)

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
