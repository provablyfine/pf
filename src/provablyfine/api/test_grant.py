import types

import pytest

from . import grant, model


def _deserialize(items: list[dict]) -> list[model.grant.Grant]:
    return [model.grant.deserialize(g) for g in items]


def boundary(ceiling_list: list[dict], denied_list: list[dict]):
    return types.SimpleNamespace(id=1, ceiling_list=_deserialize(ceiling_list), denied_list=_deserialize(denied_list))


def role(grant_list: list[dict]):
    return types.SimpleNamespace(id=1, grant_list=_deserialize(grant_list))


def single_grants(g) -> grant.Grants:
    return grant.Grants([boundary([g], [])], [role([g])])


def _crd(create: bool, read: bool, delete: bool):
    return {
        "create": create,
        "read": read,
        "delete": delete,
    }


def _role_update(name: bool, description: bool, member_list: bool = False, grant_list: bool = False):
    return {
        "name": name,
        "description": description,
        "grant_list": grant_list,
        "member_list": member_list,
    }


def _boundary_update(name: bool, description: bool, ceiling_list: bool, denied_list: bool):
    return {
        "name": name,
        "description": description,
        "ceiling_list": ceiling_list,
        "denied_list": denied_list,
    }


def _tenant_update(display_name: bool, is_enabled: bool):
    return {
        "display_name": display_name,
        "is_enabled": is_enabled,
    }


def _bastion_update(url: bool, ssh_proxy_jump: bool, tag_list: bool):
    return {"url": url, "ssh_proxy_jump": ssh_proxy_jump, "tag_list": tag_list}


def _auth_update(name: bool, description: bool, is_enabled: bool, config: bool):
    return {"name": name, "description": description, "is_enabled": is_enabled, "config": config}


def _crud(create: bool, read: bool, update: dict[str, bool] | None, delete: bool):
    return {
        "create": create,
        "read": read,
        "update": update,
        "delete": delete,
    }


def _identity(
    create_allowed: bool,
    create_tag_id_list: list[int] | None,
    create_boundary_id_list: list[int] | None,
    read: bool,
    update: dict[str, bool] | None,
    delete: bool,
    add_tag_id_list: list[int] | None,
    del_tag_id_list: list[int] | None,
    invite_list: list[str] | None,
):
    return {
        "create": {
            "allowed": create_allowed,
            "allowed_tag_id_list": create_tag_id_list,
            "required_boundary_id_list": create_boundary_id_list,
        },
        "read": read,
        "update": update,
        "delete": delete,
        "add_tag_id_list": add_tag_id_list,
        "del_tag_id_list": del_tag_id_list,
        "invite_list": invite_list,
    }


def _identity_add_tag(add_tag_id_list: list[int] | None):
    return _identity(
        create_allowed=False,
        create_tag_id_list=[],
        create_boundary_id_list=[],
        read=False,
        update=None,
        delete=False,
        add_tag_id_list=add_tag_id_list,
        del_tag_id_list=[],
        invite_list=[],
    )


def _identity_del_tag(del_tag_id_list: list[int] | None):
    return _identity(
        create_allowed=False,
        create_tag_id_list=[],
        create_boundary_id_list=[],
        read=False,
        update=None,
        delete=False,
        add_tag_id_list=[],
        del_tag_id_list=del_tag_id_list,
        invite_list=[],
    )


def _identity_invite(invite_list: list[str] | None):
    return _identity(
        create_allowed=False,
        create_tag_id_list=[],
        create_boundary_id_list=[],
        read=False,
        update=None,
        delete=False,
        add_tag_id_list=[],
        del_tag_id_list=[],
        invite_list=invite_list,
    )


def _identity_create(tag_id_list: list[int] | None, boundary_id_list: list[int] | None):
    return _identity(
        create_allowed=True,
        create_tag_id_list=tag_id_list,
        create_boundary_id_list=boundary_id_list,
        read=False,
        update=None,
        delete=False,
        add_tag_id_list=[],
        del_tag_id_list=[],
        invite_list=[],
    )


def test_empty_tag():
    grants = grant.Grants([], [])
    assert not grants.tag(None).can_create()
    assert not grants.tag(1).can_read()
    assert not grants.tag(1).can_delete()

    grants = grant.Grants([], [role([])])
    assert not grants.tag(None).can_create()
    assert not grants.tag(1).can_read()
    assert not grants.tag(1).can_delete()

    grants = grant.Grants([boundary([], [])], [role([])])
    assert not grants.tag(None).can_create()
    assert not grants.tag(1).can_read()
    assert not grants.tag(1).can_delete()


@pytest.mark.parametrize(
    "create,read,delete",
    [
        (False, False, False),
        (True, False, False),
        (False, True, False),
        (False, False, True),
    ],
)
def test_filter_all_tag(create, read, delete):
    grants = single_grants(
        {"type": "tag", "filter": {"id": None}, "permission": _crd(create=create, read=read, delete=delete)}
    )
    assert grants.tag(None).can_create() == create
    assert grants.tag(1).can_read() == read
    assert grants.tag(1).can_delete() == delete
    assert grants.tag(2).can_read() == read
    assert grants.tag(2).can_delete() == delete


@pytest.mark.parametrize(
    "read,delete",
    [
        (False, False),
        (False, False),
        (True, False),
        (False, True),
    ],
)
def test_filter_one_tag(read, delete):
    grants = single_grants(
        {"type": "tag", "filter": {"id": 2}, "permission": _crd(create=False, read=read, delete=delete)}
    )
    assert not grants.tag(None).can_create()
    assert not grants.tag(1).can_read()
    assert not grants.tag(1).can_delete()
    assert grants.tag(2).can_read() == read
    assert grants.tag(2).can_delete() == delete


def test_tag_with_ceiling():
    # I am granted create, read, and delete but the ceiling only gives me create
    grants = grant.Grants(
        [
            boundary(
                [{"type": "tag", "filter": {"id": None}, "permission": _crd(create=True, read=False, delete=False)}], []
            )
        ],
        [role([{"type": "tag", "filter": {"id": None}, "permission": _crd(create=True, read=True, delete=True)}])],
    )
    assert grants.tag(None).can_create()
    assert not grants.tag(1).can_read()
    assert not grants.tag(1).can_delete()


def test_tag_with_denied():
    # I am granted create, read, and delete, within ceiling, but I am explicitly denied read
    grants = grant.Grants(
        [
            boundary(
                [{"type": "tag", "filter": {"id": None}, "permission": _crd(create=True, read=True, delete=True)}],
                [{"type": "tag", "filter": {"id": None}, "permission": _crd(create=False, read=True, delete=False)}],
            )
        ],
        [role([{"type": "tag", "filter": {"id": None}, "permission": _crd(create=True, read=True, delete=True)}])],
    )
    assert grants.tag(None).can_create()
    assert not grants.tag(1).can_read()
    assert grants.tag(1).can_delete()


def test_tag_with_ceiling_and_denied():
    # I am granted create, read, and delete but the ceiling only gives me create and I am explicitly denied create
    grants = grant.Grants(
        [
            boundary(
                [{"type": "tag", "filter": {"id": None}, "permission": _crd(create=True, read=False, delete=False)}],
                [{"type": "tag", "filter": {"id": None}, "permission": _crd(create=True, read=False, delete=False)}],
            )
        ],
        [role([{"type": "tag", "filter": {"id": None}, "permission": _crd(create=True, read=True, delete=True)}])],
    )
    assert not grants.tag(None).can_create()
    assert not grants.tag(1).can_read()
    assert not grants.tag(1).can_delete()


def test_tag_with_larger_ceiling():
    # I am granted create, the ceiling gives me create, read, and delete
    grants = grant.Grants(
        [
            boundary(
                [{"type": "tag", "filter": {"id": None}, "permission": _crd(create=True, read=True, delete=True)}], []
            )
        ],
        [role([{"type": "tag", "filter": {"id": None}, "permission": _crd(create=True, read=False, delete=False)}])],
    )
    assert grants.tag(None).can_create()
    assert not grants.tag(1).can_read()
    assert not grants.tag(1).can_delete()


def test_tag_with_multiple_ceiling():
    # I am granted create, and read, the ceiling gives me create, and read but as separate grants.
    grants = grant.Grants(
        [
            boundary(
                [
                    {"type": "tag", "filter": {"id": None}, "permission": _crd(create=True, read=False, delete=False)},
                    {"type": "tag", "filter": {"id": None}, "permission": _crd(create=False, read=True, delete=False)},
                ],
                [],
            )
        ],
        [role([{"type": "tag", "filter": {"id": None}, "permission": _crd(create=True, read=True, delete=False)}])],
    )
    assert grants.tag(None).can_create()
    assert grants.tag(1).can_read()
    assert not grants.tag(1).can_delete()


def test_tag_with_ceiling_filter():
    # I am granted create, read, and delete, via multiple boundary ceiling
    grants = grant.Grants(
        [
            boundary(
                [
                    {"type": "tag", "filter": {"id": None}, "permission": _crd(create=True, read=False, delete=False)},
                    {"type": "tag", "filter": {"id": 2}, "permission": _crd(create=False, read=True, delete=True)},
                ],
                [],
            )
        ],
        [role([{"type": "tag", "filter": {"id": None}, "permission": _crd(create=True, read=True, delete=True)}])],
    )
    assert grants.tag(None).can_create()
    assert not grants.tag(1).can_read()
    assert not grants.tag(1).can_delete()
    assert grants.tag(2).can_read()
    assert grants.tag(2).can_delete()


######## ROLE ########


def test_empty_role():
    grants = grant.Grants([], [])

    assert not grants.role(None).can_create()
    assert not grants.role(1).can_read()
    assert not grants.role(1).can_update("name")
    assert not grants.role(1).can_update("description")
    assert not grants.role(1).can_update("grant_list")
    assert not grants.role(1).can_delete()
    with pytest.raises(AssertionError):
        assert not grants.role(1).can_update("beurk")


@pytest.mark.parametrize(
    "create,read,update,delete",
    [
        (False, False, _role_update(False, False), False),
        (True, False, _role_update(False, False), False),
        (False, True, _role_update(False, False), False),
        (False, False, _role_update(True, False), False),
        (False, False, _role_update(False, True), False),
        (False, False, _role_update(False, False), True),
        (True, True, _role_update(True, True), True),
        (True, True, None, True),
        (True, False, None, True),
        (False, True, _role_update(True, False), True),
        (False, False, _role_update(False, False, member_list=True), False),
        (False, False, _role_update(False, False, grant_list=True), False),
    ],
)
def test_filter_all_role(create, read, update, delete):
    grants = single_grants(
        {
            "type": "role",
            "filter": {"id": None},
            "permission": _crud(create=create, read=read, update=update, delete=delete),
        }
    )
    assert grants.role(None).can_create() == create
    for role_id in [1, 2, 3]:
        assert grants.role(role_id).can_read() == read
        assert grants.role(role_id).can_delete() == delete
        assert grants.role(role_id).can_update("name") == (update is None or update["name"])
        assert grants.role(role_id).can_update("description") == (update is None or update["description"])
        assert grants.role(role_id).can_update("member_list") == (update is None or update["member_list"])
        assert grants.role(role_id).can_update("grant_list") == (update is None or update["grant_list"])


@pytest.mark.parametrize(
    "read,update,delete",
    [
        (False, _role_update(False, False), False),
        (True, _role_update(False, False), False),
        (False, _role_update(True, False), False),
        (False, _role_update(False, True), False),
        (False, _role_update(False, False), True),
        (True, _role_update(True, True), True),
        (True, None, True),
        (False, None, True),
        (True, _role_update(True, False), True),
    ],
)
def test_filter_one_role(read, update, delete):
    grants = single_grants(
        {
            "type": "role",
            "filter": {"id": 2},
            "permission": _crud(create=False, read=read, update=update, delete=delete),
        }
    )
    assert not grants.role(None).can_create()
    for role_id in [1, 2, 3]:
        assert grants.role(role_id).can_read() == (role_id == 2 and read)
        assert grants.role(role_id).can_delete() == (role_id == 2 and delete)
        assert grants.role(role_id).can_update("name") == (role_id == 2 and (update is None or update["name"]))
        assert grants.role(role_id).can_update("description") == (
            role_id == 2 and (update is None or update["description"])
        )


######## BOUNDARY ########


def test_empty_boundary():
    grants = grant.Grants([], [])

    assert not grants.boundary(None).can_create()
    assert not grants.boundary(1).can_read()
    assert not grants.boundary(1).can_update("name")
    assert not grants.boundary(1).can_update("description")
    assert not grants.boundary(1).can_update("ceiling_list")
    assert not grants.boundary(1).can_update("denied_list")
    assert not grants.boundary(1).can_delete()
    with pytest.raises(AssertionError):
        assert not grants.boundary(1).can_update("beurk")


@pytest.mark.parametrize(
    "update",
    [
        _boundary_update(False, False, False, False),
        _boundary_update(True, False, False, False),
        _boundary_update(False, True, False, False),
        _boundary_update(False, False, True, False),
        _boundary_update(False, False, False, True),
        _boundary_update(True, False, True, False),
        _boundary_update(False, True, False, True),
        _boundary_update(True, True, True, True),
        None,
    ],
)
def test_filter_one_boundary(update):
    # We only test the update field because the code is all the same for role
    grants = single_grants(
        {
            "type": "boundary",
            "filter": {"id": 2},
            "permission": _crud(create=False, read=False, update=update, delete=False),
        }
    )
    assert not grants.boundary(None).can_create()
    for boundary_id in [1, 2, 3]:
        assert not grants.boundary(boundary_id).can_read()
        assert not grants.boundary(boundary_id).can_delete()
        assert grants.boundary(boundary_id).can_update("name") == (
            boundary_id == 2 and (update is None or update["name"])
        )
        assert grants.boundary(boundary_id).can_update("description") == (
            boundary_id == 2 and (update is None or update["description"])
        )
        assert grants.boundary(boundary_id).can_update("ceiling_list") == (
            boundary_id == 2 and (update is None or update["ceiling_list"])
        )
        assert grants.boundary(boundary_id).can_update("denied_list") == (
            boundary_id == 2 and (update is None or update["denied_list"])
        )
        with pytest.raises(AssertionError):
            assert grants.boundary(boundary_id).can_update("beurk")


@pytest.mark.parametrize("create", [False, True])
def test_boundary_can_create_with_matching_filter(create):
    # A boundary_id that mismatches the grant's filter short-circuits before
    # the create predicate is ever invoked, so this needs a matching id.
    grants = single_grants(
        {
            "type": "boundary",
            "filter": {"id": 2},
            "permission": _crud(create=create, read=False, update=None, delete=False),
        }
    )
    assert grants.boundary(2).can_create() == create
    assert not grants.boundary(1).can_create()


######## IDENTITY ########


def test_empty_identity():
    grants = grant.Grants([], [])

    assert not grants.identity().can_create([], [])
    assert not grants.identity(1, [], []).can_read()
    assert not grants.identity(1, [], []).can_update("name")
    assert not grants.identity(1, [], []).can_delete()
    with pytest.raises(AssertionError):
        assert not grants.identity(1, [], []).can_update("beurk")


def test_identity_add_tag():
    grants = single_grants(
        {
            "type": "identity",
            "filter": {"id": 2, "tag_id_list": [], "boundary_id_list": []},
            "permission": _identity_add_tag([1, 2]),
        }
    )
    assert not grants.identity().can_create([], [])
    assert not grants.identity(1, [], []).can_add_tag(1)
    assert not grants.identity(1, [], []).can_add_tag(2)
    assert not grants.identity(1, [], []).can_add_tag(3)
    assert grants.identity(2, [], []).can_add_tag(1)
    assert grants.identity(2, [], []).can_add_tag(2)
    assert not grants.identity(2, [], []).can_add_tag(3)

    grants = single_grants(
        {
            "type": "identity",
            "filter": {"id": 2, "tag_id_list": [1, 2], "boundary_id_list": []},
            "permission": _identity_add_tag([1, 2]),
        }
    )
    assert not grants.identity(1, [], []).can_add_tag(1)
    assert not grants.identity(2, [], []).can_add_tag(1)
    assert not grants.identity(2, [2], []).can_add_tag(1)
    assert not grants.identity(2, [1], []).can_add_tag(1)
    assert grants.identity(2, [1, 2], []).can_add_tag(1)


def test_identity_add_tag_permission_none_is_unrestricted():
    grants = single_grants(
        {
            "type": "identity",
            "filter": {"id": None, "tag_id_list": None, "boundary_id_list": None},
            "permission": _identity(
                create_allowed=False,
                create_tag_id_list=None,
                create_boundary_id_list=None,
                read=False,
                update=None,
                delete=False,
                add_tag_id_list=None,
                del_tag_id_list=[],
                invite_list=[],
            ),
        }
    )
    assert grants.identity().can_add_tag(1)
    assert grants.identity().can_add_tag(999)


def test_identity_del_tag():
    grants = single_grants(
        {
            "type": "identity",
            "filter": {"id": 2, "tag_id_list": [], "boundary_id_list": []},
            "permission": _identity_del_tag([1, 2]),
        }
    )
    assert not grants.identity(1, [], []).can_del_tag(1)
    assert not grants.identity(1, [], []).can_del_tag(2)
    assert not grants.identity(1, [], []).can_del_tag(3)
    assert grants.identity(2, [], []).can_del_tag(1)
    assert grants.identity(2, [], []).can_del_tag(2)
    assert not grants.identity(2, [], []).can_del_tag(3)


def test_identity_del_tag_permission_none_is_unrestricted():
    grants = single_grants(
        {
            "type": "identity",
            "filter": {"id": None, "tag_id_list": None, "boundary_id_list": None},
            "permission": _identity_del_tag(None),
        }
    )
    assert grants.identity().can_del_tag(1)
    assert grants.identity().can_del_tag(999)


def test_identity_invite():
    grants = single_grants(
        {
            "type": "identity",
            "filter": {"id": 2, "tag_id_list": [], "boundary_id_list": []},
            "permission": _identity_invite(["email", "sms"]),
        }
    )
    assert not grants.identity(1, [], []).can_invite("email")
    assert not grants.identity(1, [], []).can_invite("sms")
    assert grants.identity(2, [], []).can_invite("email")
    assert grants.identity(2, [], []).can_invite("sms")
    assert not grants.identity(2, [], []).can_invite("slack")


def test_identity_invite_permission_none_is_unrestricted():
    grants = single_grants(
        {
            "type": "identity",
            "filter": {"id": None, "tag_id_list": None, "boundary_id_list": None},
            "permission": _identity_invite(None),
        }
    )
    assert grants.identity().can_invite("email")
    assert grants.identity().can_invite("carrier-pigeon")


def test_identity_add_tag_ceiling_and_denied():
    def _all_filter():
        return {"id": None, "tag_id_list": None, "boundary_id_list": None}

    grants = grant.Grants(
        [
            boundary(
                [
                    {"type": "identity", "filter": _all_filter(), "permission": _identity_add_tag([1, 2])},
                    {"type": "identity", "filter": _all_filter(), "permission": _identity_add_tag([3])},
                ],
                [{"type": "identity", "filter": _all_filter(), "permission": _identity_add_tag([2])}],
            )
        ],
        [role([{"type": "identity", "filter": _all_filter(), "permission": _identity_add_tag([0, 1, 2, 3, 4])}])],
    )
    assert grants.identity(1, [], []).can_add_tag(1)
    assert not grants.identity(1, [], []).can_add_tag(2)
    assert grants.identity(1, [], []).can_add_tag(3)
    assert not grants.identity(1, [], []).can_add_tag(4)


@pytest.mark.parametrize(
    "tag_id_list,boundary_id_list,expected1,expected2",
    [
        [None, None, True, True],
        [None, [], True, True],
        [[], None, False, False],
        [[], [], False, False],
        [[1], [1], True, False],
        [[1], [], True, False],
        [[], [1], False, False],
        [[1], [2], False, False],
        [[1, 2], [1], True, True],
        [[1, 2], [1, 2], False, True],
        [[1, 2], [], True, True],
        [[1, 2], [3, 1, 2], False, False],
        [[2], [2], False, False],
    ],
)
def test_identity_create(tag_id_list, boundary_id_list, expected1, expected2):
    grants = single_grants(
        {
            "type": "identity",
            "filter": {"id": None, "tag_id_list": None, "boundary_id_list": None},
            "permission": _identity_create(tag_id_list, boundary_id_list),
        }
    )

    assert grants.identity().can_create([1], [1]) == expected1
    assert grants.identity().can_create([1, 2], [1, 2]) == expected2


def test_identity_create_permission_none_is_unrestricted():
    grants = single_grants(
        {
            "type": "identity",
            "filter": {"id": None, "tag_id_list": None, "boundary_id_list": None},
            "permission": {
                "create": None,
                "read": False,
                "update": None,
                "delete": False,
                "add_tag_id_list": [],
                "del_tag_id_list": [],
                "invite_list": [],
            },
        }
    )
    assert grants.identity().can_create([1], [1])


def test_identity_create_requires_allowed():
    grants = single_grants(
        {
            "type": "identity",
            "filter": {"id": None, "tag_id_list": None, "boundary_id_list": None},
            "permission": _identity(
                create_allowed=False,
                create_tag_id_list=None,
                create_boundary_id_list=None,
                read=False,
                update=None,
                delete=False,
                add_tag_id_list=[],
                del_tag_id_list=[],
                invite_list=[],
            ),
        }
    )
    assert not grants.identity().can_create([1], [1])


def test_identity_filter_requires_tag_and_boundary_lists_when_filter_scopes_them():
    grants = single_grants(
        {
            "type": "identity",
            "filter": {"id": None, "tag_id_list": [1], "boundary_id_list": None},
            "permission": _identity_add_tag([1]),
        }
    )
    assert not grants.identity(None, None, []).can_add_tag(1)
    assert grants.identity(None, [1], []).can_add_tag(1)

    grants = single_grants(
        {
            "type": "identity",
            "filter": {"id": None, "tag_id_list": None, "boundary_id_list": [1]},
            "permission": _identity_add_tag([1]),
        }
    )
    assert not grants.identity(None, [], None).can_add_tag(1)
    assert not grants.identity(None, [], [2]).can_add_tag(1)
    assert grants.identity(None, [], [1]).can_add_tag(1)


def test_empty_identity_read_update_delete():
    grants = grant.Grants([], [])

    assert not grants.identity(1, [], []).can_read()
    assert not grants.identity(1, [], []).can_update("unix_username")
    assert not grants.identity(1, [], []).can_delete()


@pytest.mark.parametrize(
    "read,update,delete",
    [
        (False, {"name": False, "unix_username": False}, False),
        (True, {"name": False, "unix_username": False}, False),
        (False, {"name": True, "unix_username": False}, False),
        (False, {"name": False, "unix_username": True}, False),
        (False, {"name": False, "unix_username": False}, True),
        (True, {"name": True, "unix_username": True}, True),
        (True, None, True),
    ],
)
def test_filter_all_identity(read, update, delete):
    grants = single_grants(
        {
            "type": "identity",
            "filter": {"id": None, "tag_id_list": None, "boundary_id_list": None},
            "permission": _identity(
                create_allowed=False,
                create_tag_id_list=None,
                create_boundary_id_list=None,
                read=read,
                update=update,
                delete=delete,
                add_tag_id_list=[],
                del_tag_id_list=[],
                invite_list=[],
            ),
        }
    )
    for identity_id in [1, 2, 3]:
        assert grants.identity(identity_id, [], []).can_read() == read
        assert grants.identity(identity_id, [], []).can_delete() == delete
        assert grants.identity(identity_id, [], []).can_update("name") == (update is None or update["name"])
        assert grants.identity(identity_id, [], []).can_update("unix_username") == (
            update is None or update["unix_username"]
        )


@pytest.mark.parametrize(
    "read,update,delete",
    [
        (False, {"name": False, "unix_username": False}, False),
        (True, {"name": False, "unix_username": False}, False),
        (False, {"name": True, "unix_username": False}, False),
        (False, {"name": False, "unix_username": True}, False),
        (False, {"name": False, "unix_username": False}, True),
        (True, None, True),
    ],
)
def test_filter_one_identity(read, update, delete):
    grants = single_grants(
        {
            "type": "identity",
            "filter": {"id": 2, "tag_id_list": None, "boundary_id_list": None},
            "permission": _identity(
                create_allowed=False,
                create_tag_id_list=None,
                create_boundary_id_list=None,
                read=read,
                update=update,
                delete=delete,
                add_tag_id_list=[],
                del_tag_id_list=[],
                invite_list=[],
            ),
        }
    )
    for identity_id in [1, 2, 3]:
        assert grants.identity(identity_id, [], []).can_read() == (identity_id == 2 and read)
        assert grants.identity(identity_id, [], []).can_delete() == (identity_id == 2 and delete)
        assert grants.identity(identity_id, [], []).can_update("name") == (
            identity_id == 2 and (update is None or update["name"])
        )
        assert grants.identity(identity_id, [], []).can_update("unix_username") == (
            identity_id == 2 and (update is None or update["unix_username"])
        )


######## TENANT ########


def test_empty_tenant():
    grants = grant.Grants([], [])

    assert not grants.tenant(None).can_create()
    assert not grants.tenant(1).can_read()
    assert not grants.tenant(1).can_update("display_name")
    assert not grants.tenant(1).can_update("is_enabled")
    assert not grants.tenant(1).can_delete()
    with pytest.raises(AssertionError):
        assert not grants.tenant(1).can_update("beurk")


@pytest.mark.parametrize(
    "create,read,update,delete",
    [
        (False, False, _tenant_update(False, False), False),
        (True, False, _tenant_update(False, False), False),
        (False, True, _tenant_update(False, False), False),
        (False, False, _tenant_update(True, False), False),
        (False, False, _tenant_update(False, True), False),
        (False, False, _tenant_update(False, False), True),
        (True, True, _tenant_update(True, True), True),
        (True, True, None, True),
        (True, False, None, True),
        (False, True, _tenant_update(True, False), True),
    ],
)
def test_filter_all_tenant(create, read, update, delete):
    grants = single_grants(
        {
            "type": "tenant",
            "filter": {"id": None},
            "permission": _crud(create=create, read=read, update=update, delete=delete),
        }
    )
    assert grants.tenant(None).can_create() == create
    for tenant_id in [1, 2, 3]:
        assert grants.tenant(tenant_id).can_read() == read
        assert grants.tenant(tenant_id).can_delete() == delete
        assert grants.tenant(tenant_id).can_update("display_name") == (update is None or update["display_name"])
        assert grants.tenant(tenant_id).can_update("is_enabled") == (update is None or update["is_enabled"])


@pytest.mark.parametrize(
    "read,update,delete",
    [
        (False, _tenant_update(False, False), False),
        (True, _tenant_update(False, False), False),
        (False, _tenant_update(True, False), False),
        (False, _tenant_update(False, True), False),
        (False, _tenant_update(False, False), True),
        (True, _tenant_update(True, True), True),
        (True, None, True),
        (False, None, True),
        (True, _tenant_update(True, False), True),
    ],
)
def test_filter_one_tenant(read, update, delete):
    grants = single_grants(
        {
            "type": "tenant",
            "filter": {"id": 2},
            "permission": _crud(create=False, read=read, update=update, delete=delete),
        }
    )
    assert not grants.tenant(None).can_create()
    for tenant_id in [1, 2, 3]:
        assert grants.tenant(tenant_id).can_read() == (tenant_id == 2 and read)
        assert grants.tenant(tenant_id).can_delete() == (tenant_id == 2 and delete)
        assert grants.tenant(tenant_id).can_update("display_name") == (
            tenant_id == 2 and (update is None or update["display_name"])
        )
        assert grants.tenant(tenant_id).can_update("is_enabled") == (
            tenant_id == 2 and (update is None or update["is_enabled"])
        )


######## AUTH ########


def test_empty_auth():
    grants = grant.Grants([], [])

    assert not grants.auth(None).can_create()
    assert not grants.auth(1).can_read()
    assert not grants.auth(1).can_update("name")
    assert not grants.auth(1).can_update("description")
    assert not grants.auth(1).can_update("is_enabled")
    assert not grants.auth(1).can_update("config")
    assert not grants.auth(1).can_delete()
    with pytest.raises(AssertionError):
        assert not grants.auth(1).can_update("beurk")


@pytest.mark.parametrize(
    "create,read,update,delete",
    [
        (False, False, _auth_update(False, False, False, False), False),
        (True, False, _auth_update(False, False, False, False), False),
        (False, True, _auth_update(False, False, False, False), False),
        (False, False, _auth_update(True, False, False, False), False),
        (False, False, _auth_update(False, True, False, False), False),
        (False, False, _auth_update(False, False, True, False), False),
        (False, False, _auth_update(False, False, False, True), False),
        (False, False, _auth_update(False, False, False, False), True),
        (True, True, _auth_update(True, True, True, True), True),
        (True, True, None, True),
        (True, False, None, True),
        (False, True, _auth_update(True, False, False, False), True),
    ],
)
def test_filter_all_auth(create, read, update, delete):
    grants = single_grants(
        {
            "type": "auth",
            "filter": {"id": None},
            "permission": _crud(create=create, read=read, update=update, delete=delete),
        }
    )
    assert grants.auth(None).can_create() == create
    for auth_id in [1, 2, 3]:
        assert grants.auth(auth_id).can_read() == read
        assert grants.auth(auth_id).can_delete() == delete
        assert grants.auth(auth_id).can_update("name") == (update is None or update["name"])
        assert grants.auth(auth_id).can_update("description") == (update is None or update["description"])
        assert grants.auth(auth_id).can_update("is_enabled") == (update is None or update["is_enabled"])
        assert grants.auth(auth_id).can_update("config") == (update is None or update["config"])


@pytest.mark.parametrize(
    "read,update,delete",
    [
        (False, _auth_update(False, False, False, False), False),
        (True, _auth_update(False, False, False, False), False),
        (False, _auth_update(True, False, False, False), False),
        (False, _auth_update(False, True, False, False), False),
        (False, _auth_update(False, False, True, False), False),
        (False, _auth_update(False, False, False, True), False),
        (False, _auth_update(False, False, False, False), True),
        (True, _auth_update(True, True, True, True), True),
        (True, None, True),
        (False, None, True),
        (True, _auth_update(True, False, False, False), True),
    ],
)
def test_filter_one_auth(read, update, delete):
    grants = single_grants(
        {
            "type": "auth",
            "filter": {"id": 2},
            "permission": _crud(create=False, read=read, update=update, delete=delete),
        }
    )
    assert not grants.auth(None).can_create()
    for auth_id in [1, 2, 3]:
        assert grants.auth(auth_id).can_read() == (auth_id == 2 and read)
        assert grants.auth(auth_id).can_delete() == (auth_id == 2 and delete)
        assert grants.auth(auth_id).can_update("name") == (auth_id == 2 and (update is None or update["name"]))
        assert grants.auth(auth_id).can_update("description") == (
            auth_id == 2 and (update is None or update["description"])
        )
        assert grants.auth(auth_id).can_update("is_enabled") == (
            auth_id == 2 and (update is None or update["is_enabled"])
        )
        assert grants.auth(auth_id).can_update("config") == (auth_id == 2 and (update is None or update["config"]))


######## BASTION ########


def test_empty_bastion():
    grants = grant.Grants([], [])

    assert not grants.bastion(None).can_create()
    assert not grants.bastion(1).can_read()
    assert not grants.bastion(1).can_update("url")
    assert not grants.bastion(1).can_update("ssh_proxy_jump")
    assert not grants.bastion(1).can_update("tag_list")
    assert not grants.bastion(1).can_delete()
    with pytest.raises(AssertionError):
        assert not grants.bastion(1).can_update("beurk")


@pytest.mark.parametrize(
    "create,read,update,delete",
    [
        (False, False, _bastion_update(False, False, False), False),
        (True, False, _bastion_update(False, False, False), False),
        (False, True, _bastion_update(False, False, False), False),
        (False, False, _bastion_update(True, False, False), False),
        (False, False, _bastion_update(False, True, False), False),
        (False, False, _bastion_update(False, False, True), False),
        (False, False, _bastion_update(False, False, False), True),
        (True, True, _bastion_update(True, True, True), True),
        (True, True, None, True),
        (True, False, None, True),
        (False, True, _bastion_update(True, False, False), True),
    ],
)
def test_filter_all_bastion(create, read, update, delete):
    grants = single_grants(
        {
            "type": "bastion",
            "filter": {"id": None},
            "permission": _crud(create=create, read=read, update=update, delete=delete),
        }
    )
    assert grants.bastion(None).can_create() == create
    for bastion_id in [1, 2, 3]:
        assert grants.bastion(bastion_id).can_read() == read
        assert grants.bastion(bastion_id).can_delete() == delete
        assert grants.bastion(bastion_id).can_update("url") == (update is None or update["url"])
        assert grants.bastion(bastion_id).can_update("ssh_proxy_jump") == (update is None or update["ssh_proxy_jump"])
        assert grants.bastion(bastion_id).can_update("tag_list") == (update is None or update["tag_list"])


@pytest.mark.parametrize(
    "read,update,delete",
    [
        (False, _bastion_update(False, False, False), False),
        (True, _bastion_update(False, False, False), False),
        (False, _bastion_update(True, False, False), False),
        (False, _bastion_update(False, True, False), False),
        (False, _bastion_update(False, False, True), False),
        (False, _bastion_update(False, False, False), True),
        (True, _bastion_update(True, True, True), True),
        (True, None, True),
        (False, None, True),
        (True, _bastion_update(True, False, False), True),
    ],
)
def test_filter_one_bastion(read, update, delete):
    grants = single_grants(
        {
            "type": "bastion",
            "filter": {"id": 2},
            "permission": _crud(create=False, read=read, update=update, delete=delete),
        }
    )
    assert not grants.bastion(None).can_create()
    for bastion_id in [1, 2, 3]:
        assert grants.bastion(bastion_id).can_read() == (bastion_id == 2 and read)
        assert grants.bastion(bastion_id).can_delete() == (bastion_id == 2 and delete)
        assert grants.bastion(bastion_id).can_update("url") == (bastion_id == 2 and (update is None or update["url"]))
        assert grants.bastion(bastion_id).can_update("ssh_proxy_jump") == (
            bastion_id == 2 and (update is None or update["ssh_proxy_jump"])
        )
        assert grants.bastion(bastion_id).can_update("tag_list") == (
            bastion_id == 2 and (update is None or update["tag_list"])
        )


######## AUDIT LOG ########


def test_empty_audit_log():
    grants = grant.Grants([], [])
    assert not grants.audit_log().can_read()

    grants = grant.Grants([], [role([])])
    assert not grants.audit_log().can_read()

    grants = grant.Grants([boundary([], [])], [role([])])
    assert not grants.audit_log().can_read()


@pytest.mark.parametrize("read", [False, True])
def test_audit_log_read(read: bool):
    grants = single_grants({"type": "audit-log", "filter": {}, "permission": {"read": read}})
    assert grants.audit_log().can_read() == read


def test_audit_log_with_ceiling():
    grants = grant.Grants(
        [boundary([{"type": "audit-log", "filter": {}, "permission": {"read": False}}], [])],
        [role([{"type": "audit-log", "filter": {}, "permission": {"read": True}}])],
    )
    assert not grants.audit_log().can_read()


def test_audit_log_with_denied():
    grants = grant.Grants(
        [
            boundary(
                [{"type": "audit-log", "filter": {}, "permission": {"read": True}}],
                [{"type": "audit-log", "filter": {}, "permission": {"read": True}}],
            )
        ],
        [role([{"type": "audit-log", "filter": {}, "permission": {"read": True}}])],
    )
    assert not grants.audit_log().can_read()


######## SSH ########

CAP = model.grant.SSHCapability
ANY_FILTER = {"id": None, "tag_id_list": None, "boundary_id_list": None}


def _ssh(
    usernames: list[str] | None = None,
    capabilities: list[str] | None = None,
    commands: list[str] | None = None,
    filter: dict | None = None,
    ttl: int | None = None,
):
    return {
        "type": "ssh",
        "filter": ANY_FILTER if filter is None else filter,
        "permission": {
            "username_list": usernames,
            "capability_list": capabilities,
            "command_list": commands,
            "max_session_ttl_s": ttl,
        },
    }


def _deny_boundary(denied_list: list[dict]):
    # boundary() cannot express "no ceiling": an empty ceiling_list is a
    # ceiling that covers nothing, and therefore denies everything.
    return types.SimpleNamespace(id=1, ceiling_list=None, denied_list=_deserialize(denied_list))


def _decide(grants: grant.Grants, username: str = "alice", unix_username: str | None = "unix_alice"):
    return grants.ssh(1, [], []).decide(username, unix_username)


def test_ssh_decide_empty():
    decision = _decide(grant.Grants([], []))

    assert decision.capabilities == frozenset()
    assert decision.commands.permits("ls") is None


def test_ssh_decide_union_over_role_grants():
    grants = grant.Grants(
        [], [role([_ssh(capabilities=["shell"], commands=[]), _ssh(capabilities=["pty"], commands=[])])]
    )

    assert _decide(grants).capabilities == {CAP.SHELL, CAP.PTY}


def test_ssh_decide_null_capability_list_is_every_capability():
    grants = grant.Grants([], [role([_ssh()])])

    assert _decide(grants).capabilities == frozenset(model.grant.SSHCapability)


def test_ssh_decide_ceiling_intersects():
    grants = grant.Grants(
        [boundary([_ssh(capabilities=["shell", "pty"], commands=[])], [])],
        [role([_ssh()])],
    )

    assert _decide(grants).capabilities == {CAP.SHELL, CAP.PTY}


def test_ssh_decide_uncovered_by_ceiling_is_denied():
    # A ceiling that covers a different username, and a ceiling holding no SSH
    # entry at all, both deny everything.
    non_ssh = {"type": "tag", "filter": {"id": None}, "permission": _crd(create=True, read=True, delete=True)}
    for ceiling in [[_ssh(usernames=["bob"])], [non_ssh]]:
        grants = grant.Grants([boundary(ceiling, [])], [role([_ssh()])])

        assert _decide(grants).capabilities == frozenset()


def test_ssh_decide_ceiling_caps_forwarding():
    # A ceiling that covers only a subset of the capabilities the role grants
    grants = grant.Grants(
        [boundary([_ssh(capabilities=["shell"], commands=[])], [])],
        [role([_ssh(capabilities=["shell", "agent-forwarding"], commands=[])])],
    )

    assert _decide(grants).capabilities == {CAP.SHELL}


def test_ssh_decide_deny_is_targeted():
    grants = grant.Grants(
        [_deny_boundary([_ssh(capabilities=["agent-forwarding"], commands=[])])],
        [role([_ssh()])],
    )
    decision = _decide(grants)

    assert CAP.AGENT_FORWARDING not in decision.capabilities
    # The rest of the session survives: a deny is not all-or-nothing.
    assert CAP.SHELL in decision.capabilities


def test_ssh_decide_deny_scoped_by_username():
    grants = grant.Grants([_deny_boundary([_ssh(usernames=["root"])])], [role([_ssh()])])

    assert _decide(grants, username="root", unix_username="root").capabilities == frozenset()
    assert _decide(grants, username="alice").capabilities == frozenset(model.grant.SSHCapability)


def test_ssh_decide_username_matching():
    grants = grant.Grants([], [role([_ssh(usernames=["{self}"], capabilities=["shell"], commands=[])])])

    assert _decide(grants, username="unix_alice").capabilities == {CAP.SHELL}
    assert _decide(grants, username="alice").capabilities == frozenset()
    assert _decide(grants, username="alice", unix_username=None).capabilities == frozenset()

    wildcard = grant.Grants([], [role([_ssh(capabilities=["shell"], commands=[])])])
    assert _decide(wildcard, username="anyone").capabilities == {CAP.SHELL}


def test_ssh_decide_triplet_filter():
    tagged = {"id": None, "tag_id_list": [42], "boundary_id_list": None}

    granted = grant.Grants([], [role([_ssh(filter=tagged)])])
    assert granted.ssh(1, [], []).decide("alice", None).capabilities == frozenset()
    assert granted.ssh(1, [42], []).decide("alice", None).capabilities == frozenset(model.grant.SSHCapability)

    # A deny whose filter does not match must not deny.
    denied = grant.Grants([_deny_boundary([_ssh(filter=tagged)])], [role([_ssh()])])
    assert denied.ssh(1, [], []).decide("alice", None).capabilities == frozenset(model.grant.SSHCapability)
    assert denied.ssh(1, [42], []).decide("alice", None).capabilities == frozenset()


def test_ssh_decide_triplet_filter_identity_and_boundary():
    id_filtered = {"id": 7, "tag_id_list": None, "boundary_id_list": None}
    granted = grant.Grants([], [role([_ssh(filter=id_filtered)])])
    assert granted.ssh(1, [], []).decide("alice", None).capabilities == frozenset()
    assert granted.ssh(7, [], []).decide("alice", None).capabilities == frozenset(model.grant.SSHCapability)

    boundary_filtered = {"id": None, "tag_id_list": None, "boundary_id_list": [99]}
    granted = grant.Grants([], [role([_ssh(filter=boundary_filtered)])])
    assert granted.ssh(1, [], []).decide("alice", None).capabilities == frozenset()
    assert granted.ssh(1, [], [99]).decide("alice", None).capabilities == frozenset(model.grant.SSHCapability)


def test_ssh_decide_command_cofinite():
    grants = grant.Grants(
        [_deny_boundary([_ssh(capabilities=[], commands=["rm -rf /"])])],
        [role([_ssh()])],
    )
    decision = _decide(grants)

    assert decision.commands.permits("ls") is not None
    assert decision.commands.permits("rm -rf /") is None


def test_ssh_decide_command_is_exact_match():
    grants = grant.Grants([], [role([_ssh(capabilities=[], commands=["git-upload-pack /repo"])])])
    decision = _decide(grants)

    assert decision.commands.permits("git-upload-pack /repo") is not None
    assert decision.commands.permits("git-upload-pack /repo2") is None
    assert decision.commands.permits("git-upload-pack") is None


def test_ssh_decide_command_ceiling():
    grants = grant.Grants([boundary([_ssh(capabilities=[], commands=["ls"])], [])], [role([_ssh()])])
    decision = _decide(grants)

    assert decision.commands.permits("ls") is not None
    assert decision.commands.permits("rm") is None


def test_ssh_decide_command_ceiling_never_adds():
    grants = grant.Grants(
        [boundary([_ssh(capabilities=[], commands=["ls", "rm"])], [])],
        [role([_ssh(capabilities=[], commands=["ls"])])],
    )
    decision = _decide(grants)

    assert decision.commands.permits("ls") is not None
    # The ceiling names it, but a ceiling is a bound, not a grant.
    assert decision.commands.permits("rm") is None


@pytest.mark.parametrize("ttl", [None, 60])
def test_ssh_decide_command_deny_never_permits(ttl: int | None):
    grants = grant.Grants(
        [_deny_boundary([_ssh(capabilities=[], commands=["rm"], ttl=ttl)])],
        [role([_ssh(capabilities=[], commands=["ls"], ttl=3600)])],
    )
    decision = _decide(grants)

    assert decision.commands.permits("ls") is not None
    assert decision.commands.permits("rm") is None


def test_ssh_decide_order_independent():
    ceiling = [_ssh(capabilities=["shell", "pty"], commands=["ls"]), _ssh(capabilities=["user-rc"], commands=["df"])]
    denied = [_ssh(capabilities=["pty"], commands=[]), _ssh(capabilities=[], commands=["df"])]
    grants = grant.Grants([boundary(ceiling, denied)], [role([_ssh()])])
    reversed_grants = grant.Grants([boundary(ceiling[::-1], denied[::-1])], [role([_ssh()])])

    decision = _decide(grants)
    other = _decide(reversed_grants)

    assert decision.capabilities == other.capabilities == {CAP.SHELL, CAP.USER_RC}
    for command in ["ls", "df", "rm"]:
        assert decision.commands.permits(command) == other.commands.permits(command)
    assert decision.commands.permits("ls") is not None
    assert decision.commands.permits("df") is None


def test_ssh_decide_denies_compose_across_boundaries():
    # Each deny narrows independently, so the result does not depend on which
    # boundary an entry sits in, nor on the order of the boundaries.
    first = _deny_boundary([_ssh(capabilities=["shell"], commands=["/bin/ls"], ttl=600)])
    second = types.SimpleNamespace(
        id=2,
        ceiling_list=None,
        denied_list=_deserialize([_ssh(capabilities=["pty"], commands=["/bin/ls"], ttl=60)]),
    )
    granted = [_ssh(ttl=3600)]

    for boundaries in ([first, second], [second, first]):
        decision = _decide(grant.Grants(boundaries, [role(granted)]))

        assert decision.capability_ttl[CAP.SHELL] == 600
        assert decision.capability_ttl[CAP.PTY] == 60
        assert decision.capability_ttl[CAP.USER_RC] == 3600  # named by neither deny
        assert decision.commands.permits("/bin/ls").ttl == 60  # the tighter of the two
        assert decision.commands.permits("/bin/df").ttl == 3600


def test_ssh_candidate_commands_in_grant_order():
    grants = grant.Grants(
        [_deny_boundary([_ssh(capabilities=[], commands=["/bin/rm"])])],
        [role([_ssh(capabilities=[], commands=["/bin/df", "/bin/ls", "/bin/rm"])])],
    )

    commands, any_command = _decide(grants).commands.candidates()

    assert commands == ["/bin/df", "/bin/ls"]  # the denied one is dropped
    assert not any_command


def test_ssh_candidate_commands_wildcard_is_not_enumerable():
    grants = grant.Grants([], [role([_ssh(commands=None)])])

    commands, any_command = _decide(grants).commands.candidates()

    assert commands == []
    assert any_command


def test_ssh_candidate_commands_narrowed_by_ceiling():
    # A wildcard grant is not enumerable on its own, but a ceiling naming
    # commands collapses it to exactly those: what is listed then matches what
    # permits() allows.
    grants = grant.Grants([boundary([_ssh(capabilities=[], commands=["ls"])], [])], [role([_ssh(commands=None)])])

    commands, any_command = _decide(grants).commands.candidates()

    assert commands == ["ls"]
    assert not any_command


def test_ssh_list_decisions():
    grants = grant.Grants(
        [],
        [role([_ssh(usernames=["root"], capabilities=["shell"], commands=[]), _ssh(usernames=["bob"])])],
    )

    decisions = grants.ssh(1, [], []).list_decisions("unix_alice")

    assert [u for u, _ in decisions] == ["root", "bob"]
    assert dict(decisions)["root"].capabilities == {CAP.SHELL}


def test_ssh_list_decisions_wildcard_group():
    # The wildcard decision is exact: it must reflect a deny that names a
    # different username without inheriting it.
    grants = grant.Grants(
        [_deny_boundary([_ssh(usernames=["root"], capabilities=["agent-forwarding"], commands=[])])],
        [role([_ssh(usernames=["root"]), _ssh(usernames=None)])],
    )

    decisions = grants.ssh(1, [], []).list_decisions("unix_alice")
    by_username = dict(decisions)

    assert [u for u, _ in decisions] == ["root", None]
    assert CAP.AGENT_FORWARDING not in by_username["root"].capabilities
    assert CAP.AGENT_FORWARDING in by_username[None].capabilities


def test_ssh_list_decisions_enumerates_each_username_once_and_respects_grant_order():
    # A wildcard grant appearing before named grants must not stop the named
    # grants from still being enumerated, "{self}" entries must resolve
    # through the real unix_username, and repeated entries must not duplicate.
    grants = grant.Grants(
        [],
        [
            role(
                [
                    _ssh(usernames=None, capabilities=["shell"], commands=[]),
                    _ssh(usernames=["{self}"]),
                    _ssh(usernames=["{self}"]),
                ]
            )
        ],
    )

    decisions = grants.ssh(1, [], []).list_decisions("unix_alice")

    assert [u for u, _ in decisions] == ["unix_alice", None]


def test_ssh_list_decisions_threads_the_real_unix_username_into_each_decision():
    # The capability comes from a wildcard grant (unaffected by username
    # resolution) while the deny is scoped to "{self}", so the deny is only
    # observed to apply if list_decisions correctly threads the real
    # unix_username into each per-candidate decide() call.
    grants = grant.Grants(
        [_deny_boundary([_ssh(usernames=["{self}"], capabilities=["agent-forwarding"], commands=[])])],
        [
            role(
                [
                    _ssh(usernames=None, capabilities=["shell", "agent-forwarding"], commands=[]),
                    _ssh(usernames=["{self}"], capabilities=["shell"], commands=[]),
                ]
            )
        ],
    )

    decisions = grants.ssh(1, [], []).list_decisions("unix_alice")
    by_username = dict(decisions)

    assert CAP.AGENT_FORWARDING not in by_username["unix_alice"].capabilities
    assert CAP.AGENT_FORWARDING in by_username[None].capabilities


def test_ssh_list_decisions_wildcard_ignores_a_username_named_star():
    # "*" is a legal unix username
    grants = grant.Grants(
        [_deny_boundary([_ssh(usernames=["*"], capabilities=["shell"], commands=[])])],
        [role([_ssh(usernames=None, capabilities=["shell"], commands=[])])],
    )

    by_username = dict(grants.ssh(1, [], []).list_decisions(None))

    assert by_username[None].capabilities == {CAP.SHELL}


######## SSH session TTL ########


def test_ssh_ttl_unbounded_by_default():
    grants = grant.Grants([], [role([_ssh(capabilities=["shell"], commands=[])])])

    assert _decide(grants).capability_ttl[CAP.SHELL] is None


def test_ssh_ttl_grants_raise():
    grants = grant.Grants(
        [],
        [
            role(
                [_ssh(capabilities=["shell"], commands=[], ttl=60), _ssh(capabilities=["shell"], commands=[], ttl=3600)]
            )
        ],
    )

    assert _decide(grants).capability_ttl[CAP.SHELL] == 3600


def test_ssh_ttl_unbounded_grant_absorbs():
    # ttl=None is less restrictive than ttl=60
    grants = grant.Grants(
        [],
        [
            role(
                [_ssh(capabilities=["shell"], commands=[], ttl=60), _ssh(capabilities=["shell"], commands=[], ttl=None)]
            )
        ],
    )

    assert _decide(grants).capability_ttl[CAP.SHELL] is None


def test_ssh_ttl_ceiling_lowers_but_never_raises():
    granted = _ssh(capabilities=["shell"], commands=[], ttl=3600)

    tight = grant.Grants([boundary([_ssh(capabilities=["shell"], commands=[], ttl=60)], [])], [role([granted])])
    assert _decide(tight).capability_ttl[CAP.SHELL] == 60

    # A ceiling is a bound, not a grant: it cannot raise 3600 to 86400.
    loose = grant.Grants([boundary([_ssh(capabilities=["shell"], commands=[], ttl=86400)], [])], [role([granted])])
    assert _decide(loose).capability_ttl[CAP.SHELL] == 3600

    # An unbounded ceiling tightens nothing.
    unbounded = grant.Grants([boundary([_ssh(capabilities=["shell"], commands=[])], [])], [role([granted])])
    assert _decide(unbounded).capability_ttl[CAP.SHELL] == 3600


def test_ssh_ttl_ceiling_bounds_an_unbounded_grant():
    grants = grant.Grants(
        [boundary([_ssh(capabilities=["shell"], commands=[], ttl=60)], [])],
        [role([_ssh(capabilities=["shell"], commands=[])])],
    )

    assert _decide(grants).capability_ttl[CAP.SHELL] == 60


def test_ssh_ttl_bounded_deny_clamps_rather_than_removes():
    # deny a ttl means set an upper bound on ttl
    grants = grant.Grants(
        [_deny_boundary([_ssh(capabilities=["shell"], commands=[], ttl=60)])],
        [role([_ssh(capabilities=["shell"], commands=[], ttl=3600)])],
    )
    decision = _decide(grants)

    assert CAP.SHELL in decision.capabilities
    assert decision.capability_ttl[CAP.SHELL] == 60


def test_ssh_ttl_unbounded_deny_removes_the_atom():
    # deny of ttl=None means deny of matching capabilities.
    grants = grant.Grants(
        [_deny_boundary([_ssh(capabilities=["shell"], commands=[], ttl=None)])],
        [role([_ssh(capabilities=["shell"], commands=[], ttl=3600)])],
    )

    assert CAP.SHELL not in _decide(grants).capabilities


@pytest.mark.parametrize("ttl", [None, 60])
def test_ssh_ttl_deny_never_grants(ttl: int | None):
    # deny something that is not granted
    grants = grant.Grants(
        [_deny_boundary([_ssh(capabilities=["pty"], commands=[], ttl=ttl)])],
        [role([_ssh(capabilities=["shell"], commands=[], ttl=3600)])],
    )

    assert _decide(grants).capabilities == {CAP.SHELL}


def test_ssh_ttl_deny_is_scoped_by_username():
    grants = grant.Grants(
        [_deny_boundary([_ssh(usernames=["root"], capabilities=["shell"], commands=[], ttl=60)])],
        [role([_ssh(capabilities=["shell"], commands=[], ttl=3600)])],
    )

    assert _decide(grants, username="root").capability_ttl[CAP.SHELL] == 60
    assert _decide(grants, username="alice").capability_ttl[CAP.SHELL] == 3600


def test_ssh_ttl_is_per_capability():
    # A generous port-forwarding bound must not leak into the shell session.
    grants = grant.Grants(
        [],
        [
            role(
                [
                    _ssh(capabilities=["shell"], commands=[], ttl=3600),
                    _ssh(capabilities=["port-forwarding"], commands=[], ttl=86400),
                ]
            )
        ],
    )
    decision = _decide(grants)

    assert decision.capability_ttl[CAP.SHELL] == 3600
    assert decision.capability_ttl[CAP.PORT_FORWARDING] == 86400


def test_ssh_ttl_raises_for_a_capability_not_granted():
    grants = grant.Grants([], [role([_ssh(capabilities=["shell"], commands=[], ttl=60)])])

    with pytest.raises(KeyError):
        _decide(grants).capability_ttl[CAP.PTY]


def test_ssh_command_ttl():
    grants = grant.Grants(
        [_deny_boundary([_ssh(capabilities=[], commands=["/bin/ls"], ttl=60)])],
        [role([_ssh(capabilities=[], commands=None, ttl=3600)])],
    )
    decision = _decide(grants)

    # a bounded deny clamps the command it names and leaves every other command alone
    assert decision.commands.permits("/bin/ls").ttl == 60
    assert decision.commands.permits("/bin/df").ttl == 3600


def test_ssh_command_unbounded_deny_forbids():
    grants = grant.Grants(
        [_deny_boundary([_ssh(capabilities=[], commands=["/bin/ls"])])],
        [role([_ssh(capabilities=[], commands=None, ttl=3600)])],
    )
    decision = _decide(grants)

    assert decision.commands.permits("/bin/ls") is None
    assert decision.commands.permits("/bin/df").ttl == 3600


def test_ssh_ttl_order_independent():
    ceiling = [_ssh(capabilities=["shell"], commands=[], ttl=7200), _ssh(capabilities=["shell"], commands=[], ttl=1800)]
    denied = [_ssh(capabilities=["shell"], commands=[], ttl=600), _ssh(capabilities=["shell"], commands=[], ttl=900)]
    granted = [_ssh(capabilities=["shell"], commands=[], ttl=3600)]

    forward = grant.Grants([boundary(ceiling, denied)], [role(granted)])
    backward = grant.Grants([boundary(ceiling[::-1], denied[::-1])], [role(granted)])

    # ceiling union = 7200, lowered against granted 3600 -> 3600; denies clamp
    # to the smallest, 600.
    assert _decide(forward).capability_ttl[CAP.SHELL] == 600
    assert _decide(backward).capability_ttl[CAP.SHELL] == 600


def test_ssh_ttl_across_two_boundaries():
    # One boundary clamps a capability, a later one removes it. The removal
    # must win, and the resolved map must not keep a bound for a capability that is
    # no longer granted.
    clamps = _deny_boundary([_ssh(capabilities=["shell"], commands=[], ttl=60)])
    removes = types.SimpleNamespace(
        id=2,
        ceiling_list=_deserialize([_ssh(capabilities=["pty"], commands=[])]),
        denied_list=[],
    )
    granted = [_ssh(capabilities=["shell", "pty"], commands=[], ttl=3600)]

    forward = grant.Grants([clamps, removes], [role(granted)])
    backward = grant.Grants([removes, clamps], [role(granted)])

    for grants in (forward, backward):
        decision = _decide(grants)
        assert decision.capabilities == {CAP.PTY}
        assert decision.capability_ttl[CAP.PTY] == 3600
        with pytest.raises(KeyError):
            decision.capability_ttl[CAP.SHELL]


######## CapabilityTtl ########

# CapabilityTtl and SSHCommandPermissions combine permission lists directly:
# neither reads username_list or filter, because SSHChecker has already
# filtered on those. Building the lists here drops both dimensions.


def _perm(capabilities: list[str] | None = None, commands: list[str] | None = None, ttl: int | None = None):
    return model.grant.SSHPermission(**_ssh(capabilities=capabilities, commands=commands, ttl=ttl)["permission"])


def _every_capability(ttl: int | None = None):
    return grant.CapabilityTtl.allowed_by([_perm(capabilities=None, commands=[], ttl=ttl)])


def test_capability_ttl_is_a_mapping_of_granted_capabilities():
    ttl = grant.CapabilityTtl.allowed_by(
        [
            _perm(capabilities=["shell"], commands=[], ttl=60),
            _perm(capabilities=["shell", "pty"], commands=[], ttl=None),
        ]
    )

    # An unbounded grant absorbs a bounded one: the union of 60 and unbounded
    # is unbounded. Compare through dict(): a frozen dataclass wrapping a
    # Mapping is never == to a plain dict.
    assert dict(ttl) == {CAP.SHELL: None, CAP.PTY: None}
    assert len(ttl) == 2
    assert CAP.USER_RC not in ttl


def test_capability_ttl_allowed_by_is_order_independent():
    permissions = [
        _perm(capabilities=["shell"], commands=[], ttl=60),
        _perm(capabilities=["shell"], commands=[], ttl=3600),
        _perm(capabilities=["pty"], commands=[], ttl=None),
    ]

    forward = grant.CapabilityTtl.allowed_by(permissions)
    backward = grant.CapabilityTtl.allowed_by(permissions[::-1])

    assert dict(forward) == dict(backward) == {CAP.SHELL: 3600, CAP.PTY: None}


def test_capability_ttl_intersect_keeps_only_shared_capabilities():
    ceiling = grant.CapabilityTtl.allowed_by([_perm(capabilities=["shell", "pty"], commands=[], ttl=None)])

    assert dict(_every_capability(3600).intersect(ceiling)) == {CAP.SHELL: 3600, CAP.PTY: 3600}
    # Nothing is shared with a ceiling that grants nothing.
    assert dict(_every_capability(3600).intersect(grant.CapabilityTtl.allowed_by([]))) == {}


def test_capability_ttl_intersect_never_raises_a_bound():
    def bound(granted: int | None, ceiling: int | None):
        allowed = grant.CapabilityTtl.allowed_by([_perm(capabilities=["shell"], commands=[], ttl=granted)])
        limit = grant.CapabilityTtl.allowed_by([_perm(capabilities=["shell"], commands=[], ttl=ceiling)])
        return allowed.intersect(limit)[CAP.SHELL]

    assert bound(60, 3600) == 60
    assert bound(3600, 60) == 60
    # Unbounded is the identity of the intersection, on either side.
    assert bound(None, 3600) == 3600
    assert bound(3600, None) == 3600
    assert bound(None, None) is None


def test_capability_ttl_subtract_clamps_or_removes():
    base = _every_capability(3600)

    clamped = base.subtract([_perm(capabilities=["shell"], commands=[], ttl=60)])
    assert len(clamped) == len(base)
    assert clamped[CAP.SHELL] == 60
    assert clamped[CAP.PTY] == 3600

    # An unbounded deny is a removal, not a bound of None.
    removed = base.subtract([_perm(capabilities=["pty"], commands=[], ttl=None)])
    assert len(removed) == len(base) - 1
    with pytest.raises(KeyError):
        removed[CAP.PTY]


def test_capability_ttl_subtract_with_a_wildcard_capability_list_removes_everything():
    denied = _every_capability(3600).subtract([_perm(capabilities=None, commands=[], ttl=None)])

    assert dict(denied) == {}


######## SSHCommandPermissions ########


def test_command_permissions_empty_permits_nothing():
    commands = grant.SSHCommandPermissions.allowed_by([])

    assert commands.permits("ls") is None
    assert commands.candidates() == ([], False)


def test_command_permissions_named_command_inherits_the_wildcard_bound():
    # Naming a command must not take away what a wildcard already allows for
    # it, so the union is 60 rather than the 30 the naming entry carries.
    permissions = [
        _perm(capabilities=[], commands=None, ttl=60),
        _perm(capabilities=[], commands=["ls"], ttl=30),
    ]

    for ordered in (permissions, permissions[::-1]):
        commands = grant.SSHCommandPermissions.allowed_by(ordered)

        assert commands.permits("ls").ttl == 60
        assert commands.permits("df").ttl == 60


def test_command_permissions_candidates_with_a_wildcard_and_named_commands():
    commands = grant.SSHCommandPermissions.allowed_by(
        [
            _perm(capabilities=[], commands=None, ttl=3600),
            _perm(capabilities=[], commands=["ls"], ttl=60),
        ]
    )

    # "ls" is enumerated, but the wildcard still permits everything else, so
    # the list is not the whole answer.
    assert commands.candidates() == (["ls"], True)


def test_command_permissions_intersect_falls_back_to_each_side_default():
    named = grant.SSHCommandPermissions.allowed_by([_perm(capabilities=[], commands=["ls", "df"], ttl=3600)])
    wildcard = grant.SSHCommandPermissions.allowed_by([_perm(capabilities=[], commands=None, ttl=60)])

    # A command only one side names is still decided, against the other side's
    # default: the intersection keeps every named command, unlike CapabilityTtl.
    narrowed = named.intersect(wildcard)
    assert narrowed.permits("ls").ttl == 60
    assert narrowed.permits("df").ttl == 60
    assert narrowed.permits("rm") is None

    # The other way round is the same decision, reached from the other side:
    # the wildcard collapses to exactly the commands the ceiling names.
    lowered = wildcard.intersect(named)
    assert lowered.permits("ls").ttl == 60
    assert lowered.permits("rm") is None
    assert lowered.candidates() == (["ls", "df"], False)


def test_command_permissions_intersect_chains():
    base = grant.SSHCommandPermissions.allowed_by([_perm(capabilities=[], commands=None, ttl=3600)])
    first = grant.SSHCommandPermissions.allowed_by([_perm(capabilities=[], commands=["ls", "df"], ttl=1800)])
    second = grant.SSHCommandPermissions.allowed_by([_perm(capabilities=[], commands=["ls"], ttl=600)])

    for commands in (base.intersect(first).intersect(second), base.intersect(second).intersect(first)):
        assert commands.permits("ls").ttl == 600
        # Named by only one of the two ceilings, so denied by the other.
        assert commands.permits("df") is None
        assert commands.permits("rm") is None


def test_command_permissions_subtract_names_a_command_the_base_left_unnamed():
    base = grant.SSHCommandPermissions.allowed_by([_perm(capabilities=[], commands=None, ttl=3600)])

    clamped = base.subtract([_perm(capabilities=[], commands=["rm"], ttl=600)])
    assert clamped.permits("rm").ttl == 600
    assert clamped.permits("ls").ttl == 3600

    removed = base.subtract([_perm(capabilities=[], commands=["rm"], ttl=None)])
    assert removed.permits("rm") is None
    assert removed.permits("ls").ttl == 3600


def test_command_permissions_subtract_with_a_wildcard_command_list():
    base = grant.SSHCommandPermissions.allowed_by(
        [
            _perm(capabilities=[], commands=None, ttl=3600),
            _perm(capabilities=[], commands=["ls"], ttl=None),
        ]
    )

    # A deny naming no command reaches the named entries and the default alike.
    clamped = base.subtract([_perm(capabilities=[], commands=None, ttl=600)])
    assert clamped.permits("ls").ttl == 600
    assert clamped.permits("df").ttl == 600

    removed = base.subtract([_perm(capabilities=[], commands=None, ttl=None)])
    assert removed.permits("ls") is None
    assert removed.permits("df") is None
    assert removed.candidates() == ([], False)
