from __future__ import annotations

import base64
import os
import shutil
import subprocess
import tempfile

import pytest

from .. import jwk
from . import buffer, cert, exceptions, serde

_ssh_keygen = shutil.which("ssh-keygen")


def _ssh(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [_ssh_keygen, *args],
        check=True,
        capture_output=True,
        text=True,
    )


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


@pytest.mark.skipif(not _ssh_keygen, reason="ssh-keygen not found")
@pytest.mark.parametrize(
    "key_fixture",
    ["ed25519_priv", "ec256_priv", "rsa3072_priv"],
)
def test_public_fingerprint(
    key_fixture: str,
    request: pytest.FixtureRequest,
    tmp_path: tempfile.TemporaryDirectory,
) -> None:
    priv: jwk.Private = request.getfixturevalue(key_fixture)
    pub = priv.public()
    path = str(tmp_path / "k.pub")
    with open(path, "wb") as f:
        f.write(pub.to_openssh())
    out = _ssh(["-l", "-E", "sha256", "-f", path]).stdout.strip()
    ssh_fp = out.split()[1]
    assert ssh_fp == pub.ssh_fingerprint()


@pytest.mark.skipif(not _ssh_keygen, reason="ssh-keygen not found")
@pytest.mark.parametrize(
    "key_fixture,expected_type",
    [
        ("ed25519_priv", "ED25519"),
        ("ec256_priv", "ECDSA"),
        ("rsa3072_priv", "RSA"),
    ],
)
def test_public_key_type_label(
    key_fixture: str,
    expected_type: str,
    request: pytest.FixtureRequest,
    tmp_path: tempfile.TemporaryDirectory,
) -> None:
    priv: jwk.Private = request.getfixturevalue(key_fixture)
    path = str(tmp_path / "k.pub")
    with open(path, "wb") as f:
        f.write(priv.public().to_openssh())
    out = _ssh(["-l", "-f", path]).stdout.strip()
    label = out.rsplit("(", 1)[1].removesuffix(")")
    assert label == expected_type


@pytest.mark.skipif(not _ssh_keygen, reason="ssh-keygen not found")
def test_rsa_key_size(
    rsa3072_priv: jwk.Private,
    tmp_path: tempfile.TemporaryDirectory,
) -> None:
    path = str(tmp_path / "k.pub")
    with open(path, "wb") as f:
        f.write(rsa3072_priv.public().to_openssh())
    out = _ssh(["-l", "-f", path]).stdout.strip()
    bits = out.split()[0]
    assert bits == "3072"


@pytest.mark.skipif(not _ssh_keygen, reason="ssh-keygen not found")
@pytest.mark.parametrize(
    "key_fixture",
    ["ed25519_priv", "ec256_priv", "rsa3072_priv"],
)
def test_private_openssh_roundtrip(
    key_fixture: str,
    request: pytest.FixtureRequest,
    tmp_path: tempfile.TemporaryDirectory,
) -> None:
    priv: jwk.Private = request.getfixturevalue(key_fixture)
    priv_path = str(tmp_path / "k")
    with open(priv_path, "wb") as f:
        f.write(priv.to_openssh())
    os.chmod(priv_path, 0o600)
    out = _ssh(["-y", "-f", priv_path]).stdout.strip()
    reconstructed = jwk.Public.from_openssh(out.encode())
    assert reconstructed.type == priv.type
    assert reconstructed.ssh_fingerprint() == priv.public().ssh_fingerprint()


@pytest.mark.skipif(not _ssh_keygen, reason="ssh-keygen not found")
@pytest.mark.parametrize(
    "key_fixture",
    ["ed25519_priv", "ec256_priv", "rsa3072_priv"],
)
def test_cert_fingerprint(
    key_fixture: str,
    signer: jwk.Private,
    request: pytest.FixtureRequest,
    tmp_path: tempfile.TemporaryDirectory,
) -> None:
    priv: jwk.Private = request.getfixturevalue(key_fixture)
    c = cert.Cert.create_host(
        public_key=priv.public(),
        serial_number=42,
        identifier="cert-test",
        principals=["host.test"],
        valid_after=1_000_000_000,
        valid_before=2_000_000_000,
        signer=signer,
    )
    path = str(tmp_path / "c.pub")
    with open(path, "wb") as f:
        f.write(c.to_openssh())
    out = _ssh(["-l", "-E", "sha256", "-f", path]).stdout.strip()
    ssh_fp = out.split()[1]
    assert ssh_fp == c.public_key.ssh_fingerprint()


@pytest.mark.skipif(not _ssh_keygen, reason="ssh-keygen not found")
@pytest.mark.parametrize(
    "key_fixture",
    ["ed25519_priv", "ec256_priv", "rsa3072_priv"],
)
def test_cert_details(
    key_fixture: str,
    signer: jwk.Private,
    request: pytest.FixtureRequest,
    tmp_path: tempfile.TemporaryDirectory,
) -> None:
    priv: jwk.Private = request.getfixturevalue(key_fixture)
    c = cert.Cert.create_user(
        public_key=priv.public(),
        serial_number=99,
        identifier="user-test-id",
        principals=["alice", "bob"],
        valid_after=1_000_000_000,
        valid_before=2_000_000_000,
        critical_options=cert.CriticalOptions(
            force_command="/bin/echo hello",
            source_address=["10.0.0.1", "10.0.0.2"],
            verify_required=True,
        ),
        extensions=cert.Extensions(
            permit_agent_forwarding=True,
            permit_x11_forwarding=True,
        ),
        signer=signer,
    )
    path = str(tmp_path / "c.pub")
    with open(path, "wb") as f:
        f.write(c.to_openssh())
    out = _ssh(["-L", "-f", path]).stdout
    assert "Serial: 99" in out
    assert 'Key ID: "user-test-id"' in out
    assert "/bin/echo hello" in out
    assert "10.0.0.1,10.0.0.2" in out
    assert "verify-required" in out
    assert "permit-agent-forwarding" in out
    assert "permit-X11-forwarding" in out


def test_cert_extensions_and_critical_options_round_trip() -> None:
    # Round-trips through the real cryptography library (not ssh-keygen text
    # matching — a substring check like "verify-required" in out would still
    # pass even if the underlying option name were subtly wrong) with every
    # critical option and extension flag set, so a wrong/typo'd byte-string
    # key or a clobbered builder reference is caught precisely.
    signer = jwk.Private.generate_ed25519()
    critical_options = cert.CriticalOptions(
        force_command="/bin/true",
        source_address=["10.0.0.1", "10.0.0.2"],
        verify_required=True,
    )
    extensions = cert.Extensions(
        no_touch_required=True,
        permit_agent_forwarding=True,
        permit_port_forwarding=True,
        permit_pty=True,
        permit_user_rc=True,
        permit_x11_forwarding=True,
    )
    c = cert.Cert.create_user(
        public_key=jwk.Private.generate_ed25519().public(),
        serial_number=1,
        identifier="round-trip",
        principals=["alice"],
        valid_after=1_000_000_000,
        valid_before=2_000_000_000,
        critical_options=critical_options,
        extensions=extensions,
        signer=signer,
    )
    reloaded = cert.Cert.from_openssh(c.to_openssh())
    assert reloaded.critical_options == critical_options
    assert reloaded.extensions == extensions


def _with_nonce_length(raw: bytes, nonce_length: int) -> bytes:
    # cryptography's SSHCertificateBuilder always produces a 32-byte nonce and
    # gives no way to control its length, so to test from_openssh()'s nonce-length
    # boundary check we truncate a real cert's nonce field directly in the wire
    # format. load_ssh_public_identity() doesn't verify the signature at parse
    # time, so the now-invalid signature doesn't stop the nonce check from running.
    type_str, b64, *_ = raw.split(b" ", 2)
    blob = base64.b64decode(b64)
    r = buffer.Reader(blob)
    cert_type = r.read_string()
    nonce = r.read_string()
    rest = blob[r.offset :]
    w = buffer.Writer()
    w.write_string(cert_type)
    w.write_string(nonce[:nonce_length])
    w.write_bytes(rest)
    return type_str + b" " + base64.b64encode(w.to_bytes())


def _cert_with_validity(valid_after: int, valid_before: int) -> cert.Cert:
    signer = jwk.Private.generate_ed25519()
    return cert.Cert.create_host(
        public_key=jwk.Private.generate_ed25519().public(),
        serial_number=1,
        identifier="validity-test",
        principals=["host.test"],
        valid_after=valid_after,
        valid_before=valid_before,
        signer=signer,
    )


def test_cert_is_valid_within_window(monkeypatch: pytest.MonkeyPatch) -> None:
    c = _cert_with_validity(1_000_000_000, 2_000_000_000)
    monkeypatch.setattr(cert.time, "time", lambda: 1_500_000_000.0)
    assert c.is_valid()


def test_cert_is_valid_before_window(monkeypatch: pytest.MonkeyPatch) -> None:
    c = _cert_with_validity(1_000_000_000, 2_000_000_000)
    monkeypatch.setattr(cert.time, "time", lambda: 1_000_000_000.0 - 1)
    assert not c.is_valid()


def test_cert_is_valid_after_window(monkeypatch: pytest.MonkeyPatch) -> None:
    c = _cert_with_validity(1_000_000_000, 2_000_000_000)
    monkeypatch.setattr(cert.time, "time", lambda: 2_000_000_000.0 + 1)
    assert not c.is_valid()


def test_cert_is_valid_at_exact_boundaries(monkeypatch: pytest.MonkeyPatch) -> None:
    c = _cert_with_validity(1_000_000_000, 2_000_000_000)
    monkeypatch.setattr(cert.time, "time", lambda: 1_000_000_000.0)
    assert c.is_valid()
    monkeypatch.setattr(cert.time, "time", lambda: 2_000_000_000.0)
    assert c.is_valid()


def test_cert_nonce_exactly_16_bytes_is_accepted() -> None:
    signer = jwk.Private.generate_ed25519()
    c = cert.Cert.create_host(
        public_key=jwk.Private.generate_ed25519().public(),
        serial_number=1,
        identifier="nonce-test",
        principals=["host.test"],
        valid_after=1_000_000_000,
        valid_before=2_000_000_000,
        signer=signer,
    )
    truncated = _with_nonce_length(c.to_openssh(), 16)
    reloaded = cert.Cert.from_openssh(truncated)
    assert len(reloaded._cert.nonce) == 16


def test_cert_nonce_15_bytes_is_rejected() -> None:
    signer = jwk.Private.generate_ed25519()
    c = cert.Cert.create_host(
        public_key=jwk.Private.generate_ed25519().public(),
        serial_number=1,
        identifier="nonce-test",
        principals=["host.test"],
        valid_after=1_000_000_000,
        valid_before=2_000_000_000,
        signer=signer,
    )
    truncated = _with_nonce_length(c.to_openssh(), 15)
    with pytest.raises(exceptions.Error, match="Nonce must be bigger than 16 bytes"):
        cert.Cert.from_openssh(truncated)


@pytest.mark.skipif(not _ssh_keygen, reason="ssh-keygen not found")
def test_host_cert_role(
    ed25519_priv: jwk.Private,
    signer: jwk.Private,
    tmp_path: tempfile.TemporaryDirectory,
) -> None:
    c = cert.Cert.create_host(
        public_key=ed25519_priv.public(),
        serial_number=1,
        identifier="host-cert",
        principals=["host.test"],
        valid_after=1_000_000_000,
        valid_before=2_000_000_000,
        signer=signer,
    )
    path = str(tmp_path / "c.pub")
    with open(path, "wb") as f:
        f.write(c.to_openssh())
    out = _ssh(["-L", "-f", path]).stdout
    assert "host certificate" in out
    assert signer.public().ssh_fingerprint() in out


@pytest.mark.skipif(not _ssh_keygen, reason="ssh-keygen not found")
def test_user_cert_role(
    ed25519_priv: jwk.Private,
    signer: jwk.Private,
    tmp_path: tempfile.TemporaryDirectory,
) -> None:
    c = cert.Cert.create_user(
        public_key=ed25519_priv.public(),
        serial_number=1,
        identifier="user-cert",
        principals=["alice"],
        valid_after=1_000_000_000,
        valid_before=2_000_000_000,
        critical_options=cert.CriticalOptions(),
        extensions=cert.Extensions(),
        signer=signer,
    )
    path = str(tmp_path / "c.pub")
    with open(path, "wb") as f:
        f.write(c.to_openssh())
    out = _ssh(["-L", "-f", path]).stdout
    assert "user certificate" in out


@pytest.mark.skipif(not _ssh_keygen, reason="ssh-keygen not found")
@pytest.mark.parametrize(
    "key_fixture",
    ["ed25519_priv", "ec256_priv", "rsa3072_priv"],
)
def test_cert_signer_fingerprint(
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
    path = str(tmp_path / "c.pub")
    with open(path, "wb") as f:
        f.write(c.to_openssh())
    out = _ssh(["-L", "-f", path]).stdout
    signer_fp = signer.public().ssh_fingerprint()
    assert signer_fp in out


@pytest.mark.skipif(not _ssh_keygen, reason="ssh-keygen not found")
@pytest.mark.parametrize(
    "key_fixture",
    ["ed25519_priv", "ec256_priv", "rsa3072_priv"],
)
def test_serde_private_agent_blob_consistent(
    key_fixture: str,
    request: pytest.FixtureRequest,
    tmp_path: tempfile.TemporaryDirectory,
) -> None:
    priv: jwk.Private = request.getfixturevalue(key_fixture)
    pub = priv.public()
    pub_path = str(tmp_path / "k.pub")
    with open(pub_path, "wb") as f:
        f.write(pub.to_openssh())
    ref_fp = _ssh(["-l", "-E", "sha256", "-f", pub_path]).stdout.strip().split()[1]
    agent_blob = serde.serialize_private(priv)
    r = buffer.Reader(agent_blob)
    kt = r.read_string()
    if kt == b"ssh-ed25519":
        pub_blob = r.read_string()
        combo = r.read_string()
        assert combo.endswith(pub_blob)
    elif kt == b"ssh-rsa":
        n = r.read_mpint()
        e = r.read_mpint()
        d = r.read_mpint()
        iqmp = r.read_mpint()
        p = r.read_mpint()
        q = r.read_mpint()
        pn = priv.to_crypto().private_numbers()
        assert n == pn.public_numbers.n
        assert e == pn.public_numbers.e
        assert d == pn.d
        assert iqmp == pn.iqmp
        assert p == pn.p
        assert q == pn.q
    else:
        _ = r.read_string()
        _ = r.read_string()
        _ = r.read_mpint()
    assert ref_fp == pub.ssh_fingerprint()
