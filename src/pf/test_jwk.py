from __future__ import annotations

import secrets

import pytest

from . import base64url, jwk

PUB_FIXTURES = ["ed25519_private", "ec256_private", "ec384_private", "ec521_private", "rsa3072_private"]


# ── KeyType ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "name,expected_type",
    [
        ("ed25519", jwk.KeyType.ED25519),
        ("ecdsa-256", jwk.KeyType.ECDSA_NISTP256),
        ("ecdsa-384", jwk.KeyType.ECDSA_NISTP384),
        ("ecdsa-521", jwk.KeyType.ECDSA_NISTP521),
        ("rsa-3072", jwk.KeyType.RSA_3072),
        ("rsa-7680", jwk.KeyType.RSA_7680),
        ("rsa-15360", jwk.KeyType.RSA_15360),
    ],
)
def test_key_type_from_to_string(name: str, expected_type: jwk.KeyType) -> None:
    assert jwk.KeyType.from_string(name) == expected_type
    assert expected_type.to_string() == name


def test_key_type_invalid_string() -> None:
    with pytest.raises(KeyError):
        jwk.KeyType.from_string("invalid")


# ── rfc7638_thumbprint ──────────────────────────────────────────────────────


def test_rfc7638_thumbprint_deterministic() -> None:
    data = {"kty": "oct", "k": base64url.encode(b"\x00" * 32)}
    assert jwk.rfc7638_thumbprint(data) == jwk.rfc7638_thumbprint(data)


def test_rfc7638_thumbprint_different_input() -> None:
    data1 = {"kty": "oct", "k": base64url.encode(b"\x00" * 32)}
    data2 = {"kty": "oct", "k": base64url.encode(b"\xff" * 32)}
    assert jwk.rfc7638_thumbprint(data1) != jwk.rfc7638_thumbprint(data2)


# ── Symmetric ────────────────────────────────────────────────────────────────


def test_symmetric_type() -> None:
    assert jwk.Symmetric.generate().type == jwk.KeyType.SYMMETRIC


def test_symmetric_generate_is_32_bytes() -> None:
    assert len(jwk.Symmetric.generate().to_bytes()) == 32


def test_symmetric_bytes_roundtrip() -> None:
    original = secrets.token_bytes(32)
    assert jwk.Symmetric.from_bytes(original).to_bytes() == original


def test_symmetric_dict_roundtrip() -> None:
    original = secrets.token_bytes(32)
    sym = jwk.Symmetric.from_bytes(original)
    sym2 = jwk.Symmetric.from_dict(sym.to_dict())
    assert sym2.to_bytes() == original


def test_symmetric_thumbprint_consistency() -> None:
    original = secrets.token_bytes(32)
    sym = jwk.Symmetric.from_bytes(original)
    assert sym.thumbprint() == jwk.rfc7638_thumbprint(sym.to_dict())


# ── Public ───────────────────────────────────────────────────────────────────


@pytest.fixture
def ed25519_private() -> jwk.Private:
    return jwk.Private.generate_ed25519()


@pytest.fixture
def ec256_private() -> jwk.Private:
    return jwk.Private.generate_ecdsa_nistp256()


@pytest.fixture
def ec384_private() -> jwk.Private:
    return jwk.Private.generate_ecdsa_nistp384()


@pytest.fixture
def ec521_private() -> jwk.Private:
    return jwk.Private.generate_ecdsa_nistp521()


@pytest.fixture
def rsa3072_private() -> jwk.Private:
    return jwk.Private.generate_rsa(3072)


def test_public_type_ed25519(ed25519_private: jwk.Private) -> None:
    assert ed25519_private.public().type == jwk.KeyType.ED25519


def test_public_type_ec256(ec256_private: jwk.Private) -> None:
    assert ec256_private.public().type == jwk.KeyType.ECDSA_NISTP256


def test_public_type_ec384(ec384_private: jwk.Private) -> None:
    assert ec384_private.public().type == jwk.KeyType.ECDSA_NISTP384


def test_public_type_ec521(ec521_private: jwk.Private) -> None:
    assert ec521_private.public().type == jwk.KeyType.ECDSA_NISTP521


def test_public_type_rsa3072(rsa3072_private: jwk.Private) -> None:
    assert rsa3072_private.public().type == jwk.KeyType.RSA_3072


@pytest.mark.parametrize("pub_fixture", PUB_FIXTURES)
def test_public_dict_roundtrip(pub_fixture: str, request: pytest.FixtureRequest) -> None:
    priv: jwk.Private = request.getfixturevalue(pub_fixture)
    pub = priv.public()
    pub2 = jwk.Public.from_dict(pub.to_dict())
    assert pub2.to_dict() == pub.to_dict()
    assert pub2.type == pub.type


@pytest.mark.parametrize("pub_fixture", PUB_FIXTURES)
def test_public_pem_roundtrip(pub_fixture: str, request: pytest.FixtureRequest) -> None:
    priv: jwk.Private = request.getfixturevalue(pub_fixture)
    pub = priv.public()
    pub2 = jwk.Public.from_pem(pub.to_pem())
    assert pub2.type == pub.type


@pytest.mark.parametrize("pub_fixture", PUB_FIXTURES)
def test_public_openssh_roundtrip(pub_fixture: str, request: pytest.FixtureRequest) -> None:
    priv: jwk.Private = request.getfixturevalue(pub_fixture)
    pub = priv.public()
    pub2 = jwk.Public.from_openssh(pub.to_openssh())
    assert pub2.type == pub.type


def test_public_thumbprint_consistency(ed25519_private: jwk.Private) -> None:
    pub = ed25519_private.public()
    assert pub.thumbprint() == jwk.rfc7638_thumbprint(pub.to_dict())


def test_public_ssh_fingerprint_format(ed25519_private: jwk.Private) -> None:
    pub = ed25519_private.public()
    assert pub.ssh_fingerprint().startswith("SHA256:")


def test_public_match_ssh_fingerprint(ed25519_private: jwk.Private) -> None:
    pub = ed25519_private.public()
    assert pub.match_ssh_fingerprint(pub.ssh_fingerprint())


def test_public_match_ssh_fingerprint_wrong(ed25519_private: jwk.Private) -> None:
    pub = ed25519_private.public()
    assert not pub.match_ssh_fingerprint("SHA256:wrongfingerprint")


def test_public_match_ssh_fingerprint_md5_raises(ed25519_private: jwk.Private) -> None:
    pub = ed25519_private.public()
    with pytest.raises(ValueError, match="MD5"):
        pub.match_ssh_fingerprint("MD5:somefingerprint")


# ── Private ──────────────────────────────────────────────────────────────────


def test_generate_ed25519() -> None:
    assert jwk.Private.generate(jwk.KeyType.ED25519).type == jwk.KeyType.ED25519


def test_generate_ec256() -> None:
    assert jwk.Private.generate(jwk.KeyType.ECDSA_NISTP256).type == jwk.KeyType.ECDSA_NISTP256


def test_generate_ec384() -> None:
    assert jwk.Private.generate(jwk.KeyType.ECDSA_NISTP384).type == jwk.KeyType.ECDSA_NISTP384


def test_generate_ec521() -> None:
    assert jwk.Private.generate(jwk.KeyType.ECDSA_NISTP521).type == jwk.KeyType.ECDSA_NISTP521


def test_generate_rsa3072() -> None:
    assert jwk.Private.generate(jwk.KeyType.RSA_3072).type == jwk.KeyType.RSA_3072


def test_private_dict_roundtrip_ed25519(ed25519_private: jwk.Private) -> None:
    d = ed25519_private.to_dict()
    priv2 = jwk.Private.from_dict(d)
    assert priv2.to_dict() == d
    assert priv2.type == ed25519_private.type


def test_private_dict_roundtrip_ec256(ec256_private: jwk.Private) -> None:
    d = ec256_private.to_dict()
    priv2 = jwk.Private.from_dict(d)
    assert priv2.to_dict() == d
    assert priv2.type == ec256_private.type


def test_private_public_key_consistency(ed25519_private: jwk.Private) -> None:
    pub = ed25519_private.public()
    pub2 = jwk.Public(ed25519_private.to_crypto().public_key())
    assert pub.to_dict() == pub2.to_dict()


def test_private_thumbprint_consistency(ed25519_private: jwk.Private) -> None:
    tp = ed25519_private.thumbprint()
    assert tp == jwk.rfc7638_thumbprint(ed25519_private.to_dict())
    assert tp == ed25519_private.public().thumbprint()


def test_private_crypto_roundtrip_ed25519(ed25519_private: jwk.Private) -> None:
    crypto_key = ed25519_private.to_crypto()
    priv2 = jwk.Private.from_crypto(crypto_key)
    assert priv2.type == ed25519_private.type


def test_public_ed25519_jwk_fields(ed25519_private: jwk.Private) -> None:
    d = ed25519_private.public().to_dict()
    assert d["kty"] == "OKP"
    assert d["crv"] == "Ed25519"
    assert "x" in d


def test_public_ec256_jwk_fields(ec256_private: jwk.Private) -> None:
    d = ec256_private.public().to_dict()
    assert d["kty"] == "EC"
    assert d["crv"] == "P-256"
    assert "x" in d
    assert "y" in d


def test_public_rsa3072_jwk_fields(rsa3072_private: jwk.Private) -> None:
    d = rsa3072_private.public().to_dict()
    assert d["kty"] == "RSA"
    assert "e" in d
    assert "n" in d
