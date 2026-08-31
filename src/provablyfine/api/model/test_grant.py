import json

import pydantic
import pytest

from . import grant

CAP = grant.SSHCapability
FILTER = {"id": 7, "tag_id_list": [1, 2], "boundary_id_list": None}


def test_ssh_permission_rejects_empty_atom_set():
    with pytest.raises(pydantic.ValidationError):
        grant.SSHPermission(username_list=["root"], capability_list=[], command_list=[], max_session_ttl_s=None)


def test_ssh_permission_allows_command_only():
    p = grant.SSHPermission(username_list=["root"], capability_list=[], command_list=["ls"], max_session_ttl_s=None)

    assert p.capability_list == []


def test_ssh_permission_allows_full_wildcard():
    p = grant.SSHPermission(username_list=None, capability_list=None, command_list=None, max_session_ttl_s=None)

    assert p.username_list is None


def test_ssh_grant_round_trip():
    data = {
        "type": "ssh",
        "filter": FILTER,
        "permission": {
            "username_list": None,
            "capability_list": ["shell", "pty"],
            "command_list": [],
            "max_session_ttl_s": 3600,
        },
    }

    g = grant.deserialize(data)

    assert isinstance(g, grant.SSHGrant)
    assert g.permission.capability_list == [CAP.SHELL, CAP.PTY]
    # Through json, not just ==: model_dump() returns SSHCapability members,
    # and StrEnum compares equal to its value, so a direct comparison would
    # pass even if the members were not JSON-serializable.
    assert json.loads(json.dumps(grant.serialize(g))) == data


def test_legacy_ssh_grant_types_are_gone():
    # A row that predates the capability-model migration no longer parses. The
    # data migration is what guarantees none is left.
    with pytest.raises(pydantic.ValidationError):
        grant.deserialize({"type": "ssh-shell", "filter": FILTER, "permission": {"username_list": ["root"]}})


def test_ssh_permission_rejects_non_positive_ttl():
    for ttl in (0, -1):
        with pytest.raises(pydantic.ValidationError):
            grant.SSHPermission(
                username_list=["root"], capability_list=["shell"], command_list=[], max_session_ttl_s=ttl
            )


def test_ssh_permission_ttl_is_required():
    # Required and nullable, like every other field: null is the whole axis
    # (unbounded), and omitting it is not the same as saying so.
    with pytest.raises(pydantic.ValidationError):
        grant.deserialize(
            {
                "type": "ssh",
                "filter": FILTER,
                "permission": {"username_list": None, "capability_list": ["shell"], "command_list": []},
            }
        )
