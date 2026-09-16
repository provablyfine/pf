from __future__ import annotations

from . import cert


def test_critical_options_to_dict() -> None:
    options = cert.CriticalOptions(
        force_command="ls -la",
        source_address=["10.0.0.1", "10.0.0.2"],
        verify_required=True,
    )
    assert options.to_dict() == {
        "force_command": "ls -la",
        "source_address": ["10.0.0.1", "10.0.0.2"],
        "verify_required": True,
    }


def test_critical_options_eq() -> None:
    a = cert.CriticalOptions(force_command="ls -la")
    b = cert.CriticalOptions(force_command="ls -la")
    c = cert.CriticalOptions(force_command="rm -rf /")
    assert a == b
    assert a != c
    assert a != "not critical options"


def test_critical_options_repr() -> None:
    options = cert.CriticalOptions(
        force_command="ls -la",
        source_address=["10.0.0.1", "10.0.0.2"],
        verify_required=True,
    )
    assert repr(options) == (
        "CriticalOptions(force_command='ls -la', source_address=['10.0.0.1', '10.0.0.2'], verify_required=True)"
    )


def test_extensions_to_dict() -> None:
    extensions = cert.Extensions(
        no_touch_required=True,
        permit_agent_forwarding=False,
        permit_port_forwarding=True,
        permit_pty=False,
        permit_user_rc=True,
        permit_x11_forwarding=False,
        session_deadline=1_700_000_000,
        connection_id="conn-id-123",
    )
    assert extensions.to_dict() == {
        "no_touch_required": True,
        "permit_agent_forwarding": False,
        "permit_port_forwarding": True,
        "permit_pty": False,
        "permit_user_rc": True,
        "permit_x11_forwarding": False,
        "session_deadline": 1_700_000_000,
        "connection_id": "conn-id-123",
    }


def test_extensions_eq() -> None:
    a = cert.Extensions(connection_id="conn-id-123")
    b = cert.Extensions(connection_id="conn-id-123")
    c = cert.Extensions(connection_id="conn-id-456")
    assert a == b
    assert a != c
    assert a != "not extensions"


def test_extensions_repr() -> None:
    extensions = cert.Extensions(
        no_touch_required=True,
        permit_agent_forwarding=False,
        permit_port_forwarding=True,
        permit_pty=False,
        permit_user_rc=True,
        permit_x11_forwarding=False,
        session_deadline=1_700_000_000,
        connection_id="conn-id-123",
    )
    assert repr(extensions) == (
        "Extensions(no_touch_required=True, permit_agent_forwarding=False, permit_port_forwarding=True, "
        "permit_pty=False, permit_user_rc=True, permit_x11_forwarding=False, session_deadline=1700000000, "
        "connection_id='conn-id-123')"
    )
