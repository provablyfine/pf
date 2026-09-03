from __future__ import annotations

import pathlib

import pytest

from ... import jwk, ssh
from . import openssh_session_deadline


@pytest.fixture
def ca_key() -> jwk.Private:
    return jwk.Private.generate_ed25519()


@pytest.fixture
def user_cert(ca_key: jwk.Private) -> ssh.cert.Cert:
    return ssh.cert.Cert.create_user(
        public_key=jwk.Private.generate_ed25519().public(),
        serial_number=1,
        identifier="1:alice",
        principals=["alice@1"],
        valid_after=1_000_000_000,
        valid_before=2_000_000_000,
        critical_options=ssh.cert.CriticalOptions(),
        extensions=ssh.cert.Extensions(session_deadline=1_500_000_000, connection_id="test-connection-id"),
        signer=ca_key,
    )


def _auth_info_line(c: ssh.cert.Cert) -> str:
    key_type, b64, *_rest = c.to_openssh().split(b" ")
    return f"publickey {key_type.decode()} {b64.decode()}"


def test_cert_from_auth_info_returns_none_when_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SSH_AUTH_INFO_0", raising=False)
    assert openssh_session_deadline._cert_from_auth_info() is None


def test_cert_from_auth_info_skips_non_cert_lines(monkeypatch: pytest.MonkeyPatch, user_cert: ssh.cert.Cert) -> None:
    monkeypatch.setenv("SSH_AUTH_INFO_0", "password")
    monkeypatch.setenv("SSH_AUTH_INFO_1", _auth_info_line(user_cert))
    monkeypatch.delenv("SSH_AUTH_INFO_2", raising=False)
    found = openssh_session_deadline._cert_from_auth_info()
    assert found is not None
    assert found.identifier == user_cert.identifier
    assert found.serial_number == user_cert.serial_number


def test_cert_from_auth_info_malformed_base64(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SSH_AUTH_INFO_0", "publickey ssh-ed25519-cert-v01@openssh.com not-valid-base64!!")
    monkeypatch.delenv("SSH_AUTH_INFO_1", raising=False)
    assert openssh_session_deadline._cert_from_auth_info() is None


def test_trusted_fingerprints_missing_file(tmp_path: pathlib.Path) -> None:
    missing = str(tmp_path / "does-not-exist.pub")
    assert openssh_session_deadline._trusted_fingerprints(missing) == set()


def test_trusted_fingerprints_reads_multiple_keys(tmp_path: pathlib.Path, ca_key: jwk.Private) -> None:
    other_key = jwk.Private.generate_ed25519()
    path = tmp_path / "pf_ca.pub"
    path.write_bytes(ca_key.public().to_openssh() + b"\n" + other_key.public().to_openssh() + b"\n")
    fingerprints = openssh_session_deadline._trusted_fingerprints(str(path))
    assert ca_key.public().ssh_fingerprint() in fingerprints
    assert other_key.public().ssh_fingerprint() in fingerprints


def test_trusted_fingerprints_ignores_untrusted_signer(tmp_path: pathlib.Path, user_cert: ssh.cert.Cert) -> None:
    untrusted_signer = jwk.Private.generate_ed25519()
    path = tmp_path / "pf_ca.pub"
    path.write_bytes(untrusted_signer.public().to_openssh() + b"\n")
    fingerprints = openssh_session_deadline._trusted_fingerprints(str(path))
    assert user_cert.signer_public_key.ssh_fingerprint() not in fingerprints
