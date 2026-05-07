from __future__ import annotations

import re
import shutil
import subprocess
import tempfile

import pytest

from .. import jwk
from . import cert, serde

_ssh_keygen_path = shutil.which("ssh-keygen")


def _write_pub(path: str, pub: jwk.Public) -> None:
    with open(path, "wb") as f:
        f.write(pub.to_openssh())


def _fingerprint_via_ssh_keygen(pub_path: str) -> str:
    out = subprocess.run(  # noqa: S603
        [_ssh_keygen_path, "-l", "-E", "sha256", "-f", pub_path],
        capture_output=True,
        text=True,
        check=True,
    )
    parts = out.stdout.strip().split()
    return parts[1]


def _write_cert(pub_path: str, certificate: cert.Cert) -> None:
    with open(pub_path, "wb") as f:
        f.write(certificate.to_openssh())


def _cert_details_via_ssh_keygen(cert_path: str) -> dict[str, str]:
    out = subprocess.run(  # noqa: S603
        [_ssh_keygen_path, "-L", "-f", cert_path],
        capture_output=True,
        text=True,
        check=True,
    )
    details: dict[str, str] = {}
    for line in out.stdout.splitlines():
        match = re.match(r"\s+([^:]+):\s+(.*)", line)
        if match:
            label = match.group(1).strip()
            value = match.group(2).strip()
            details[label] = value
    return details


def _fingerprint_of_signer_via_ssh_keygen(cert_path: str) -> str:
    out = subprocess.run(  # noqa: S603
        [_ssh_keygen_path, "-L", "-f", cert_path],
        capture_output=True,
        text=True,
        check=True,
    )
    for line in out.stdout.splitlines():
        if "Signing CA:" in line:
            match = re.search(r"SHA256:[A-Za-z0-9+/=]+", line)
            if match:
                return match.group(0)
    return ""


@pytest.fixture
def ed25519_priv() -> jwk.Private:
    return jwk.Private.generate_ed25519()


@pytest.fixture
def ec256_priv() -> jwk.Private:
    return jwk.Private.generate_ecdsa_nistp256()


@pytest.fixture
def rsa3072_priv() -> jwk.Private:
    return jwk.Private.generate_rsa(3072)


@pytest.fixture
def signer() -> jwk.Private:
    return jwk.Private.generate_ed25519()


# ── Fingerprint verification ─────────────────────────────────────────────────


@pytest.mark.skipif(not _ssh_keygen_path, reason="ssh-keygen not available")
@pytest.mark.parametrize(
    "key_fixture",
    ["ed25519_priv", "ec256_priv", "rsa3072_priv"],
)
def test_fingerprint_matches_ssh_keygen(
    key_fixture: str, request: pytest.FixtureRequest, tmp_path: tempfile.TemporaryDirectory
) -> None:
    priv: jwk.Private = request.getfixturevalue(key_fixture)
    pub = priv.public()
    pub_path = str(tmp_path / "key.pub")
    _write_pub(pub_path, pub)
    expected = _fingerprint_via_ssh_keygen(pub_path)
    actual = pub.ssh_fingerprint()
    assert actual == expected, f"expected {expected}, got {actual}"


# ── ssh-keygen -L for certificate metadata ──────────────────────────────────


@pytest.mark.skipif(not _ssh_keygen_path, reason="ssh-keygen not available")
@pytest.mark.parametrize(
    "key_fixture",
    ["ed25519_priv", "ec256_priv", "rsa3072_priv"],
)
def test_cert_details_match_ssh_keygen(
    key_fixture: str,
    signer: jwk.Private,
    request: pytest.FixtureRequest,
    tmp_path: tempfile.TemporaryDirectory,
) -> None:
    priv: jwk.Private = request.getfixturevalue(key_fixture)
    c = cert.Cert.create_host(
        public_key=priv.public(),
        serial_number=99,
        identifier="host.cert-test.local",
        principals=["host.cert-test.local", "alias.local"],
        valid_after=1_000_000_000,
        valid_before=2_000_000_000,
        signer=signer,
    )
    cert_path = str(tmp_path / "cert.pub")
    _write_cert(cert_path, c)
    details = _cert_details_via_ssh_keygen(cert_path)
    assert details["Serial"] == "99", details
    assert '"host.cert-test.local"' in details.get("Key ID", ""), details


@pytest.mark.skipif(not _ssh_keygen_path, reason="ssh-keygen not available")
@pytest.mark.parametrize(
    "key_fixture",
    ["ed25519_priv", "ec256_priv", "rsa3072_priv"],
)
def test_cert_signer_fingerprint_matches(
    key_fixture: str,
    signer: jwk.Private,
    request: pytest.FixtureRequest,
    tmp_path: tempfile.TemporaryDirectory,
) -> None:
    priv: jwk.Private = request.getfixturevalue(key_fixture)
    c = cert.Cert.create_host(
        public_key=priv.public(),
        serial_number=1,
        identifier="host.test",
        principals=["host.test"],
        valid_after=1_000_000_000,
        valid_before=2_000_000_000,
        signer=signer,
    )
    cert_path = str(tmp_path / "cert.pub")
    _write_cert(cert_path, c)
    ssh_signer_fp = _fingerprint_of_signer_via_ssh_keygen(cert_path)
    actual_signer_fp = c.signer_public_key.ssh_fingerprint()
    assert actual_signer_fp == ssh_signer_fp


# ── Cert fingerprint via ssh-keygen -l ───────────────────────────────────────


@pytest.mark.skipif(not _ssh_keygen_path, reason="ssh-keygen not available")
@pytest.mark.parametrize(
    "key_fixture",
    ["ed25519_priv", "ec256_priv", "rsa3072_priv"],
)
def test_cert_fingerprint_matches(
    key_fixture: str,
    signer: jwk.Private,
    request: pytest.FixtureRequest,
    tmp_path: tempfile.TemporaryDirectory,
) -> None:
    priv: jwk.Private = request.getfixturevalue(key_fixture)
    c = cert.Cert.create_host(
        public_key=priv.public(),
        serial_number=1,
        identifier="host.test",
        principals=["host.test"],
        valid_after=1_000_000_000,
        valid_before=2_000_000_000,
        signer=signer,
    )
    cert_path = str(tmp_path / "cert.pub")
    _write_cert(cert_path, c)
    ssh_fp = _fingerprint_via_ssh_keygen(cert_path)
    cert_fp = c.public_key.ssh_fingerprint()
    assert cert_fp == ssh_fp


# ── ssh-keygen cert vs host vs user roles ────────────────────────────────────


@pytest.mark.skipif(not _ssh_keygen_path, reason="ssh-keygen not available")
def test_host_cert_type_matches(
    ed25519_priv: jwk.Private,
    signer: jwk.Private,
    tmp_path: tempfile.TemporaryDirectory,
) -> None:
    c = cert.Cert.create_host(
        public_key=ed25519_priv.public(),
        serial_number=1,
        identifier="host.test",
        principals=["host.test"],
        valid_after=1_000_000_000,
        valid_before=2_000_000_000,
        signer=signer,
    )
    cert_path = str(tmp_path / "cert.pub")
    _write_cert(cert_path, c)
    out = subprocess.run(  # noqa: S603
        [_ssh_keygen_path, "-L", "-f", cert_path],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "host certificate" in out.stdout


@pytest.mark.skipif(not _ssh_keygen_path, reason="ssh-keygen not available")
def test_user_cert_type_matches(
    ed25519_priv: jwk.Private,
    signer: jwk.Private,
    tmp_path: tempfile.TemporaryDirectory,
) -> None:
    c = cert.Cert.create_user(
        public_key=ed25519_priv.public(),
        serial_number=1,
        identifier="user.test",
        principals=["user.test"],
        valid_after=1_000_000_000,
        valid_before=2_000_000_000,
        critical_options=cert.CriticalOptions(),
        extensions=cert.Extensions(),
        signer=signer,
    )
    cert_path = str(tmp_path / "cert.pub")
    _write_cert(cert_path, c)
    out = subprocess.run(  # noqa: S603
        [_ssh_keygen_path, "-L", "-f", cert_path],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "user certificate" in out.stdout


# ── Private key serialization round trip with ssh-keygen ────────────────────


@pytest.mark.skipif(not _ssh_keygen_path, reason="ssh-keygen not available")
@pytest.mark.parametrize(
    "key_fixture",
    ["ed25519_priv", "ec256_priv", "rsa3072_priv"],
)
def test_serde_private_reconstructs_same_public_key(
    key_fixture: str,
    request: pytest.FixtureRequest,
    tmp_path: tempfile.TemporaryDirectory,
) -> None:
    from . import buffer

    priv: jwk.Private = request.getfixturevalue(key_fixture)
    pub = priv.public()
    pub_path = str(tmp_path / "k.pub")
    _write_pub(pub_path, pub)
    ssh_fp = _fingerprint_via_ssh_keygen(pub_path)
    agent_blob = serde.serialize_private(priv)
    reader = buffer.Reader(agent_blob)
    key_type = reader.read_string()
    if key_type == b"ssh-ed25519":
        pub_blob = reader.read_string()
        combo_blob = reader.read_string()
        assert combo_blob[-len(pub_blob) :] == pub_blob
    fingerprint = pub.ssh_fingerprint()
    assert fingerprint == ssh_fp
