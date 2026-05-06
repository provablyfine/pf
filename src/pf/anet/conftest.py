"""Shared fixtures and helpers for anet tests."""

from __future__ import annotations

import asyncio
import collections.abc
import datetime
import ipaddress
import os

import cryptography
import cryptography.hazmat.primitives.asymmetric.rsa as crypto_rsa
import cryptography.hazmat.primitives.hashes as crypto_hashes
import cryptography.hazmat.primitives.serialization as crypto_serialization
import cryptography.x509
import cryptography.x509.oid as crypto_oid
import pytest

import pf.anet.socket as anet_socket
import pf.anet.ssl as anet_ssl


def _create_server_context(
    certfile: str | os.PathLike[str],
    keyfile: str | os.PathLike[str],
) -> anet_ssl.SSLContext:
    """Create server-side SSL context from certificate and key files."""
    ctx = anet_ssl.SSLContext(anet_ssl.ContextProtocol.SERVER)
    ctx.load_cert_chain(str(certfile), str(keyfile))
    return ctx


def _create_client_context(
    cafile: str | os.PathLike[str],
    check_hostname: bool = True,
) -> anet_ssl.SSLContext:
    """Create client-side SSL context with CA verification."""
    ctx = anet_ssl.SSLContext(anet_ssl.ContextProtocol.CLIENT)
    ctx.load_verify_locations(str(cafile))
    ctx.check_hostname = check_hostname
    ctx.verify_mode = anet_ssl.VerifyMode.REQUIRED
    return ctx


@pytest.fixture(scope="session")
def ssl_contexts(tmp_path_factory: pytest.TempPathFactory) -> tuple[anet_ssl.SSLContext, anet_ssl.SSLContext]:
    """Generate self-signed CA and server certificate; return (server_ctx, client_ctx)."""
    tmpdir = tmp_path_factory.mktemp("ssl")

    # Generate CA key and cert
    ca_key = crypto_rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = cryptography.x509.Name([cryptography.x509.NameAttribute(crypto_oid.NameOID.COMMON_NAME, "Test CA")])
    now = datetime.datetime.now(datetime.UTC)
    ca_cert = (
        cryptography.x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            cryptography.x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(ca_key, crypto_hashes.SHA256())
    )

    # Generate server key and cert
    server_key = crypto_rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_subject = cryptography.x509.Name(
        [cryptography.x509.NameAttribute(crypto_oid.NameOID.COMMON_NAME, "127.0.0.1")]
    )
    server_cert = (
        cryptography.x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(ca_subject)
        .public_key(server_key.public_key())
        .serial_number(2)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            cryptography.x509.SubjectAlternativeName([cryptography.x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]),
            critical=False,
        )
        .sign(ca_key, crypto_hashes.SHA256())
    )

    # Write to temp files
    ca_cert_file = tmpdir / "ca.pem"
    server_cert_file = tmpdir / "server.pem"
    server_key_file = tmpdir / "server.key"

    ca_cert_file.write_bytes(ca_cert.public_bytes(crypto_serialization.Encoding.PEM))
    server_cert_file.write_bytes(server_cert.public_bytes(crypto_serialization.Encoding.PEM))
    server_key_file.write_bytes(
        server_key.private_bytes(
            encoding=crypto_serialization.Encoding.PEM,
            format=crypto_serialization.PrivateFormat.PKCS8,
            encryption_algorithm=crypto_serialization.NoEncryption(),
        )
    )

    # Create SSL contexts
    server_ctx = _create_server_context(server_cert_file, server_key_file)
    client_ctx = _create_client_context(ca_cert_file, check_hostname=False)

    return server_ctx, client_ctx


@pytest.fixture
async def anet_socketpair() -> collections.abc.AsyncGenerator[tuple[anet_socket.Socket, anet_socket.Socket], None]:
    """Create a connected AF_UNIX socketpair wrapped in anet.socket.Socket."""
    a, b = await anet_socket.socketpair(anet_socket.Family.UNIX, anet_socket.Type.STREAM)
    yield a, b
    await a.close()
    await b.close()


@pytest.fixture
async def tls_socketpair(
    anet_socketpair: tuple[anet_socket.Socket, anet_socket.Socket],
    ssl_contexts: tuple[anet_ssl.SSLContext, anet_ssl.SSLContext],
) -> collections.abc.AsyncGenerator[tuple[anet_ssl.Socket, anet_ssl.Socket], None]:
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
