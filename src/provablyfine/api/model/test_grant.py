import json

import pydantic
import pytest

from . import grant

CAP = grant.SSHCapability
FILTER = {"id": 7, "tag_id_list": [1, 2], "boundary_id_list": None}


def _upcast(data: dict) -> grant.SSHGrant | None:
    g = grant.deserialize(data)
    assert isinstance(g, grant.SSHShellGrant | grant.SSHPortForwardingGrant | grant.SSHCommandGrant)
    return grant.upcast(g)


def _shell(agent: bool = False, x11: bool = False, usernames: list[str] | None = None) -> dict:
    return {
        "type": "ssh-shell",
        "filter": FILTER,
        "permission": {
            "username_list": ["root"] if usernames is None else usernames,
            "permit_agent_forwarding": agent,
            "permit_x11_forwarding": x11,
        },
    }


@pytest.mark.parametrize(
    ("agent", "x11", "expected"),
    [
        (False, False, [CAP.SHELL, CAP.PTY, CAP.USER_RC]),
        (True, False, [CAP.SHELL, CAP.PTY, CAP.USER_RC, CAP.AGENT_FORWARDING]),
        (False, True, [CAP.SHELL, CAP.PTY, CAP.USER_RC, CAP.X11_FORWARDING]),
        (True, True, [CAP.SHELL, CAP.PTY, CAP.USER_RC, CAP.AGENT_FORWARDING, CAP.X11_FORWARDING]),
    ],
)
def test_upcast_shell(agent: bool, x11: bool, expected: list[grant.SSHCapability]):
    g = _upcast(_shell(agent=agent, x11=x11))

    assert g is not None
    assert set(g.permission.capability_list or []) == set(expected)
    # Legacy shell issuance hardcoded permit_port_forwarding=False.
    assert CAP.PORT_FORWARDING not in (g.permission.capability_list or [])
    # [] means no commands. None would mean *any* command.
    assert g.permission.command_list == []


def test_upcast_port_forwarding():
    g = _upcast({"type": "ssh-port-forwarding", "filter": FILTER, "permission": {"username_list": ["alice"]}})

    assert g is not None
    assert g.permission.capability_list == [CAP.PORT_FORWARDING]
    assert g.permission.command_list == []


def test_upcast_command():
    g = _upcast(
        {
            "type": "ssh-command",
            "filter": FILTER,
            "permission": {"username_list": ["alice"], "command_list": ["git-upload-pack /repo"]},
        }
    )

    assert g is not None
    assert g.permission.capability_list == []
    assert g.permission.command_list == ["git-upload-pack /repo"]


def test_upcast_command_without_command_denotes_nothing():
    # Unrepresentable in the new schema, and exactly equivalent to being absent
    # in every position.
    assert (
        _upcast({"type": "ssh-command", "filter": FILTER, "permission": {"username_list": ["a"], "command_list": []}})
        is None
    )


def test_upcast_preserves_filter_and_usernames():
    g = _upcast(_shell(usernames=["{self}", "root"]))

    assert g is not None
    assert g.permission.username_list == ["{self}", "root"]
    assert g.filter.id == 7
    assert g.filter.tag_id_list == [1, 2]
    assert g.filter.boundary_id_list is None


def test_upcast_empty_username_list_survives():
    # The TUI creates legacy grants this way, so upcast must not reject it.
    g = _upcast(_shell(usernames=[]))

    assert g is not None
    assert g.permission.username_list == []


def test_ssh_permission_rejects_empty_atom_set():
    with pytest.raises(pydantic.ValidationError):
        grant.SSHPermission(username_list=["root"], capability_list=[], command_list=[])


def test_ssh_permission_allows_command_only():
    p = grant.SSHPermission(username_list=["root"], capability_list=[], command_list=["ls"])

    assert p.capability_list == []


def test_ssh_permission_allows_full_wildcard():
    p = grant.SSHPermission(username_list=None, capability_list=None, command_list=None)

    assert p.username_list is None


def test_ssh_grant_round_trip():
    data = {
        "type": "ssh",
        "filter": FILTER,
        "permission": {"username_list": None, "capability_list": ["shell", "pty"], "command_list": []},
    }

    g = grant.deserialize(data)

    assert isinstance(g, grant.SSHGrant)
    assert g.permission.capability_list == [CAP.SHELL, CAP.PTY]
    # Through json, not just ==: model_dump() returns SSHCapability members,
    # and StrEnum compares equal to its value, so a direct comparison would
    # pass even if the members were not JSON-serializable.
    assert json.loads(json.dumps(grant.serialize(g))) == data
