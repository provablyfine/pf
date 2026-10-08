from __future__ import annotations

import pathlib
import sys

import pytest

from ... import jwk, ssh
from . import live_events, openssh_pam_session_deadline_linux

# The hook is a PAM module for Linux hosts. Closing a session stops a systemd timer with systemctl.
pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="the PAM hook runs on Linux only")


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
    assert openssh_pam_session_deadline_linux._cert_from_auth_info() is None


def test_cert_from_auth_info_skips_non_cert_lines(monkeypatch: pytest.MonkeyPatch, user_cert: ssh.cert.Cert) -> None:
    monkeypatch.setenv("SSH_AUTH_INFO_0", "password")
    monkeypatch.setenv("SSH_AUTH_INFO_1", _auth_info_line(user_cert))
    monkeypatch.delenv("SSH_AUTH_INFO_2", raising=False)
    found = openssh_pam_session_deadline_linux._cert_from_auth_info()
    assert found is not None
    assert found.identifier == user_cert.identifier
    assert found.serial_number == user_cert.serial_number


def test_cert_from_auth_info_malformed_base64(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SSH_AUTH_INFO_0", "publickey ssh-ed25519-cert-v01@openssh.com not-valid-base64!!")
    monkeypatch.delenv("SSH_AUTH_INFO_1", raising=False)
    assert openssh_pam_session_deadline_linux._cert_from_auth_info() is None


def test_trusted_fingerprints_missing_file(tmp_path: pathlib.Path) -> None:
    missing = str(tmp_path / "does-not-exist.pub")
    assert openssh_pam_session_deadline_linux._trusted_fingerprints(missing) == set()


def test_trusted_fingerprints_reads_multiple_keys(tmp_path: pathlib.Path, ca_key: jwk.Private) -> None:
    other_key = jwk.Private.generate_ed25519()
    path = tmp_path / "pf_ca.pub"
    path.write_bytes(ca_key.public().to_openssh() + b"\n" + other_key.public().to_openssh() + b"\n")
    fingerprints = openssh_pam_session_deadline_linux._trusted_fingerprints(str(path))
    assert ca_key.public().ssh_fingerprint() in fingerprints
    assert other_key.public().ssh_fingerprint() in fingerprints


def test_trusted_fingerprints_ignores_untrusted_signer(tmp_path: pathlib.Path, user_cert: ssh.cert.Cert) -> None:
    untrusted_signer = jwk.Private.generate_ed25519()
    path = tmp_path / "pf_ca.pub"
    path.write_bytes(untrusted_signer.public().to_openssh() + b"\n")
    fingerprints = openssh_pam_session_deadline_linux._trusted_fingerprints(str(path))
    assert user_cert.signer_public_key.ssh_fingerprint() not in fingerprints


CONNECTION_ID = "3fa85f64-5717-4562-b3fc-2c963f66afa6"


def _session_environment(
    monkeypatch: pytest.MonkeyPatch, ca_key: jwk.Private, tmp_path: pathlib.Path, deadline: int | None
) -> str:
    """Set up the environment of a PAM session. Returns the path of the CA public key file."""
    cert = ssh.cert.Cert.create_user(
        public_key=jwk.Private.generate_ed25519().public(),
        serial_number=1,
        identifier="1:alice",
        principals=["alice@1"],
        valid_after=1_000_000_000,
        valid_before=2_000_000_000,
        critical_options=ssh.cert.CriticalOptions(),
        extensions=ssh.cert.Extensions(session_deadline=deadline, connection_id=CONNECTION_ID),
        signer=ca_key,
    )
    monkeypatch.setenv("SSH_AUTH_INFO_0", _auth_info_line(cert))
    monkeypatch.delenv("SSH_AUTH_INFO_1", raising=False)
    monkeypatch.setenv("XDG_SESSION_ID", "42")
    ca_path = tmp_path / "pf_ca.pub"
    ca_path.write_bytes(ca_key.public().to_openssh() + b"\n")
    return str(ca_path)


def test_an_unbounded_session_is_reported_to_the_spool(
    monkeypatch: pytest.MonkeyPatch, ca_key: jwk.Private, tmp_path: pathlib.Path
) -> None:
    ca_path = _session_environment(monkeypatch, ca_key, tmp_path, deadline=None)
    spool = tmp_path / "spool"
    spool.mkdir()

    openssh_pam_session_deadline_linux._handle_open_session(ca_path, str(spool))
    openssh_pam_session_deadline_linux._handle_close_session(str(spool))

    events = [e for _, e in live_events.read_events(str(spool))]
    assert [(e.kind, e.connection_id, e.session_id) for e in events] == [
        ("start", CONNECTION_ID, "42"),
        ("end", CONNECTION_ID, "42"),
    ]


def test_a_certificate_from_an_untrusted_signer_is_not_reported(
    monkeypatch: pytest.MonkeyPatch, ca_key: jwk.Private, tmp_path: pathlib.Path
) -> None:
    _session_environment(monkeypatch, ca_key, tmp_path, deadline=None)
    other_ca = tmp_path / "other.pub"
    other_ca.write_bytes(jwk.Private.generate_ed25519().public().to_openssh() + b"\n")
    spool = tmp_path / "spool"
    spool.mkdir()

    openssh_pam_session_deadline_linux._handle_open_session(str(other_ca), str(spool))

    assert live_events.read_events(str(spool)) == []


def test_nothing_is_reported_without_a_spool_directory(
    monkeypatch: pytest.MonkeyPatch, ca_key: jwk.Private, tmp_path: pathlib.Path
) -> None:
    ca_path = _session_environment(monkeypatch, ca_key, tmp_path, deadline=None)

    openssh_pam_session_deadline_linux._handle_open_session(ca_path, None)
    openssh_pam_session_deadline_linux._handle_close_session(None)

    assert list(tmp_path.iterdir()) == [tmp_path / "pf_ca.pub"]


def test_an_open_session_is_recorded_for_the_reaper_until_it_closes(
    monkeypatch: pytest.MonkeyPatch, ca_key: jwk.Private, tmp_path: pathlib.Path
) -> None:
    ca_path = _session_environment(monkeypatch, ca_key, tmp_path, deadline=None)
    sessions = tmp_path / "sessions"

    openssh_pam_session_deadline_linux._handle_open_session(ca_path, None, str(sessions))
    assert [p.name for p in sessions.iterdir()] == [f"{CONNECTION_ID}-42"]

    openssh_pam_session_deadline_linux._handle_close_session(None, str(sessions))
    assert list(sessions.iterdir()) == []


def test_a_session_is_not_recorded_without_a_logind_session_id(
    monkeypatch: pytest.MonkeyPatch, ca_key: jwk.Private, tmp_path: pathlib.Path
) -> None:
    ca_path = _session_environment(monkeypatch, ca_key, tmp_path, deadline=None)
    monkeypatch.delenv("XDG_SESSION_ID")
    sessions = tmp_path / "sessions"

    openssh_pam_session_deadline_linux._handle_open_session(ca_path, None, str(sessions))

    assert not sessions.exists()


def test_a_certificate_from_an_untrusted_signer_is_not_recorded(
    monkeypatch: pytest.MonkeyPatch, ca_key: jwk.Private, tmp_path: pathlib.Path
) -> None:
    _session_environment(monkeypatch, ca_key, tmp_path, deadline=None)
    other_ca = tmp_path / "other.pub"
    other_ca.write_bytes(jwk.Private.generate_ed25519().public().to_openssh() + b"\n")
    sessions = tmp_path / "sessions"

    openssh_pam_session_deadline_linux._handle_open_session(str(other_ca), None, str(sessions))

    assert not sessions.exists()
