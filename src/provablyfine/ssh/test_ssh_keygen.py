from __future__ import annotations

import os
import shutil
import subprocess
import tempfile

import pytest

from .. import jwk
from . import cert, serde

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
    from . import buffer

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
