from __future__ import annotations

import cryptography
import cryptography.hazmat.primitives.asymmetric.ec
import cryptography.hazmat.primitives.asymmetric.ed25519
import cryptography.hazmat.primitives.asymmetric.rsa
import cryptography.hazmat.primitives.serialization
import pytest

from .. import jwk
from . import buffer, cert, serde

# ── fixtues ──────────────────────────────────────────────────────────────────


@pytest.fixture
def ed25519_priv() -> jwk.Private:
    return jwk.Private.generate_ed25519()


@pytest.fixture
def ec256_priv() -> jwk.Private:
    return jwk.Private.generate_ecdsa_nistp256()


@pytest.fixture
def ec384_priv() -> jwk.Private:
    return jwk.Private.generate_ecdsa_nistp384()


@pytest.fixture
def ec521_priv() -> jwk.Private:
    return jwk.Private.generate_ecdsa_nistp521()


@pytest.fixture
def rsa3072_priv() -> jwk.Private:
    return jwk.Private.generate_rsa(3072)


@pytest.fixture
def ed25519_signer() -> jwk.Private:
    return jwk.Private.generate_ed25519()


@pytest.fixture
def ed25519_cert(ed25519_priv: jwk.Private, ed25519_signer: jwk.Private) -> cert.Cert:
    return cert.Cert.create_host(
        public_key=ed25519_priv.public(),
        serial_number=42,
        identifier="host.example.com",
        principals=["host.example.com"],
        valid_after=1_000_000_000,
        valid_before=2_000_000_000,
        signer=ed25519_signer,
    )


# ── public key round-trip ────────────────────────────────────────────────────


@pytest.mark.parametrize("fix", ["ed25519_priv", "ec256_priv", "ec384_priv", "ec521_priv", "rsa3072_priv"])
def test_public_roundtrip(fix: str, request: pytest.FixtureRequest) -> None:
    priv: jwk.Private = request.getfixturevalue(fix)
    pub = priv.public()
    data = serde.serialize_public(pub)
    pub2 = serde.deserialize_public(data)
    assert pub2.type == pub.type
    assert pub2.to_dict() == pub.to_dict()


# ── private key agent blob ───────────────────────────────────────────────────


def test_private_agent_blob_ed25519(ed25519_priv: jwk.Private) -> None:
    data = serde.serialize_private(ed25519_priv)
    r = buffer.Reader(data)
    key_type = r.read_string()
    assert key_type == b"ssh-ed25519"
    pub_blob = r.read_string()
    combo_blob = r.read_string()
    assert combo_blob[-32:] == pub_blob


@pytest.mark.parametrize("fix", ["ec256_priv", "ec384_priv", "ec521_priv"])
def test_private_agent_blob_ec(fix: str, request: pytest.FixtureRequest) -> None:
    priv: jwk.Private = request.getfixturevalue(fix)
    data = serde.serialize_private(priv)
    r = buffer.Reader(data)
    key_type = r.read_string()
    assert key_type.startswith(b"ecdsa-sha2-nistp")
    r.read_string()
    q = r.read_string()
    d = r.read_mpint()
    crypto_key = priv.to_crypto()
    assert q == crypto_key.public_key().public_bytes(
        encoding=cryptography.hazmat.primitives.serialization.Encoding.X962,
        format=cryptography.hazmat.primitives.serialization.PublicFormat.UncompressedPoint,
    )
    assert d == crypto_key.private_numbers().private_value


def test_private_agent_blob_rsa(rsa3072_priv: jwk.Private) -> None:
    data = serde.serialize_private(rsa3072_priv)
    r = buffer.Reader(data)
    key_type = r.read_string()
    assert key_type == b"ssh-rsa"
    n = r.read_mpint()
    e = r.read_mpint()
    d = r.read_mpint()
    iqmp = r.read_mpint()
    p = r.read_mpint()
    q = r.read_mpint()
    priv_nums = rsa3072_priv.to_crypto().private_numbers()
    assert n == priv_nums.public_numbers.n
    assert e == priv_nums.public_numbers.e
    assert d == priv_nums.d
    assert iqmp == priv_nums.iqmp
    assert p == priv_nums.p
    assert q == priv_nums.q


# ── cert round-trip ──────────────────────────────────────────────────────────


def test_cert_serialize_deserialize(ed25519_cert: cert.Cert) -> None:
    data = serde.serialize_cert(ed25519_cert)
    c2 = serde.deserialize_cert(data)
    assert c2.public_key.type == ed25519_cert.public_key.type
    assert c2.identifier == ed25519_cert.identifier
    assert c2.serial_number == ed25519_cert.serial_number
    assert c2.principals == ed25519_cert.principals


# ── private certificate blob ─────────────────────────────────────────────────


def test_private_cert_blob_ed25519(ed25519_priv: jwk.Private, ed25519_cert: cert.Cert) -> None:
    data = serde.serialize_private_certificate(ed25519_priv, ed25519_cert)
    r = buffer.Reader(data)
    key_type = r.read_string()
    assert key_type == b"ssh-ed25519-cert-v01@openssh.com"
    cert_blob = r.read_string()
    assert cert_blob == serde.serialize_cert(ed25519_cert)
    pub_blob = r.read_string()
    combo_blob = r.read_string()
    assert combo_blob[-len(pub_blob) :] == pub_blob


@pytest.mark.parametrize("fix", ["ec256_priv", "ec384_priv", "ec521_priv"])
def test_private_cert_blob_ec(fix: str, ed25519_cert: cert.Cert, request: pytest.FixtureRequest) -> None:
    priv: jwk.Private = request.getfixturevalue(fix)
    ec_cert = cert.Cert.create_host(
        public_key=priv.public(),
        serial_number=99,
        identifier="host.ec",
        principals=["host.ec"],
        valid_after=1_000_000_000,
        valid_before=2_000_000_000,
        signer=priv,
    )
    data = serde.serialize_private_certificate(priv, ec_cert)
    r = buffer.Reader(data)
    key_type = r.read_string()
    assert key_type.startswith(b"ecdsa-sha2-nistp")
    assert key_type.endswith(b"-cert-v01@openssh.com")
    cert_blob = r.read_string()
    assert cert_blob == serde.serialize_cert(ec_cert)
    d = r.read_mpint()
    assert d == priv.to_crypto().private_numbers().private_value
