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


def _role_update(name: bool, description: bool):
    return {
        "name": name,
        "description": description,
        "grant_list": False,
        "member_list": False,
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
    assert not decision.permits_command("ls")


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
    # The bug being fixed: under the legacy checker this same policy yields
    # permit_agent_forwarding=True, because the ceiling is only a boolean gate
    # over username membership.
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


def test_ssh_decide_command_cofinite():
    grants = grant.Grants(
        [_deny_boundary([_ssh(capabilities=[], commands=["rm -rf /"])])],
        [role([_ssh()])],
    )
    decision = _decide(grants)

    assert decision.permits_command("ls")
    assert not decision.permits_command("rm -rf /")


def test_ssh_decide_command_is_exact_match():
    grants = grant.Grants([], [role([_ssh(capabilities=[], commands=["git-upload-pack /repo"])])])
    decision = _decide(grants)

    assert decision.permits_command("git-upload-pack /repo")
    assert not decision.permits_command("git-upload-pack /repo2")
    assert not decision.permits_command("git-upload-pack")


def test_ssh_decide_command_ceiling():
    grants = grant.Grants([boundary([_ssh(capabilities=[], commands=["ls"])], [])], [role([_ssh()])])
    decision = _decide(grants)

    assert decision.permits_command("ls")
    assert not decision.permits_command("rm")


def test_ssh_decide_order_independent():
    # Compared by behavior, not by equality: _CommandAxis holds tuples, whose
    # equality is order-sensitive.
    ceiling = [_ssh(capabilities=["shell", "pty"], commands=["ls"]), _ssh(capabilities=["user-rc"], commands=["df"])]
    denied = [_ssh(capabilities=["pty"], commands=[]), _ssh(capabilities=[], commands=["df"])]
    grants = grant.Grants([boundary(ceiling, denied)], [role([_ssh()])])
    reversed_grants = grant.Grants([boundary(ceiling[::-1], denied[::-1])], [role([_ssh()])])

    decision = _decide(grants)
    other = _decide(reversed_grants)

    assert decision.capabilities == other.capabilities == {CAP.SHELL, CAP.USER_RC}
    for command in ["ls", "df", "rm"]:
        assert decision.permits_command(command) == other.permits_command(command)
    assert decision.permits_command("ls")
    assert not decision.permits_command("df")


def test_ssh_candidate_commands_in_grant_order():
    grants = grant.Grants(
        [_deny_boundary([_ssh(capabilities=[], commands=["/bin/rm"])])],
        [role([_ssh(capabilities=[], commands=["/bin/df", "/bin/ls", "/bin/rm"])])],
    )

    commands, any_command = _decide(grants).candidate_commands()

    assert commands == ["/bin/df", "/bin/ls"]  # the denied one is dropped
    assert not any_command


def test_ssh_candidate_commands_wildcard_is_not_enumerable():
    grants = grant.Grants([], [role([_ssh(commands=None)])])

    commands, any_command = _decide(grants).candidate_commands()

    assert commands == []
    assert any_command


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


def test_ssh_list_decisions_wildcard_avoids_named_usernames():
    # "*" is a legal unix username, so the representative used for the wildcard
    # group must not collide with a name any entry mentions.
    grants = grant.Grants(
        [_deny_boundary([_ssh(usernames=["*"], capabilities=["shell"], commands=[])])],
        [role([_ssh(usernames=None, capabilities=["shell"], commands=[])])],
    )

    by_username = dict(grants.ssh(1, [], []).list_decisions(None))

    assert by_username[None].capabilities == {CAP.SHELL}


######## SSH session TTL ########


def test_ssh_ttl_unbounded_by_default():
    grants = grant.Grants([], [role([_ssh(capabilities=["shell"], commands=[])])])

    assert _decide(grants).session_ttl_s(CAP.SHELL) is None


def test_ssh_ttl_grants_raise():
    grants = grant.Grants(
        [],
        [
            role(
                [_ssh(capabilities=["shell"], commands=[], ttl=60), _ssh(capabilities=["shell"], commands=[], ttl=3600)]
            )
        ],
    )

    assert _decide(grants).session_ttl_s(CAP.SHELL) == 3600


def test_ssh_ttl_unbounded_grant_absorbs():
    # None is the top of the order, so it wins the max rather than being
    # treated as a missing value.
    grants = grant.Grants(
        [],
        [role([_ssh(capabilities=["shell"], commands=[], ttl=60), _ssh(capabilities=["shell"], commands=[])])],
    )

    assert _decide(grants).session_ttl_s(CAP.SHELL) is None


def test_ssh_ttl_ceiling_lowers_but_never_raises():
    granted = _ssh(capabilities=["shell"], commands=[], ttl=3600)

    tight = grant.Grants([boundary([_ssh(capabilities=["shell"], commands=[], ttl=60)], [])], [role([granted])])
    assert _decide(tight).session_ttl_s(CAP.SHELL) == 60

    # A ceiling is a bound, not a grant: it cannot raise 3600 to 86400.
    loose = grant.Grants([boundary([_ssh(capabilities=["shell"], commands=[], ttl=86400)], [])], [role([granted])])
    assert _decide(loose).session_ttl_s(CAP.SHELL) == 3600

    # An unbounded ceiling tightens nothing.
    unbounded = grant.Grants([boundary([_ssh(capabilities=["shell"], commands=[])], [])], [role([granted])])
    assert _decide(unbounded).session_ttl_s(CAP.SHELL) == 3600


def test_ssh_ttl_ceiling_bounds_an_unbounded_grant():
    grants = grant.Grants(
        [boundary([_ssh(capabilities=["shell"], commands=[], ttl=60)], [])],
        [role([_ssh(capabilities=["shell"], commands=[])])],
    )

    assert _decide(grants).session_ttl_s(CAP.SHELL) == 60


def test_ssh_ttl_bounded_deny_clamps_rather_than_removes():
    # The one asymmetry on this axis: a deny naming a bound denies only the
    # excess, so the capability survives with a tighter bound.
    grants = grant.Grants(
        [_deny_boundary([_ssh(capabilities=["shell"], commands=[], ttl=60)])],
        [role([_ssh(capabilities=["shell"], commands=[], ttl=3600)])],
    )
    decision = _decide(grants)

    assert CAP.SHELL in decision.capabilities
    assert decision.session_ttl_s(CAP.SHELL) == 60


def test_ssh_ttl_unbounded_deny_removes_the_atom():
    # null is the whole axis, and for a deny that is full removal -- identical
    # to the discrete case, not "clamp to unbounded".
    grants = grant.Grants(
        [_deny_boundary([_ssh(capabilities=["shell"], commands=[])])],
        [role([_ssh(capabilities=["shell"], commands=[], ttl=3600)])],
    )

    assert CAP.SHELL not in _decide(grants).capabilities


def test_ssh_ttl_deny_is_scoped_by_username():
    grants = grant.Grants(
        [_deny_boundary([_ssh(usernames=["root"], capabilities=["shell"], commands=[], ttl=60)])],
        [role([_ssh(capabilities=["shell"], commands=[], ttl=3600)])],
    )

    assert _decide(grants, username="root").session_ttl_s(CAP.SHELL) == 60
    assert _decide(grants, username="alice").session_ttl_s(CAP.SHELL) == 3600


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

    assert decision.session_ttl_s(CAP.SHELL) == 3600
    assert decision.session_ttl_s(CAP.PORT_FORWARDING) == 86400


def test_ssh_ttl_raises_for_a_capability_not_granted():
    grants = grant.Grants([], [role([_ssh(capabilities=["shell"], commands=[], ttl=60)])])

    with pytest.raises(KeyError):
        _decide(grants).session_ttl_s(CAP.PTY)


def test_ssh_command_ttl():
    grants = grant.Grants(
        [_deny_boundary([_ssh(capabilities=[], commands=["/bin/ls"], ttl=60)])],
        [role([_ssh(capabilities=[], commands=None, ttl=3600)])],
    )
    decision = _decide(grants)

    # The cofinite case: a bounded deny clamps the command it names and leaves
    # every other command alone.
    assert decision.command_ttl_s("/bin/ls") == 60
    assert decision.command_ttl_s("/bin/df") == 3600


def test_ssh_command_unbounded_deny_forbids():
    grants = grant.Grants(
        [_deny_boundary([_ssh(capabilities=[], commands=["/bin/ls"])])],
        [role([_ssh(capabilities=[], commands=None, ttl=3600)])],
    )
    decision = _decide(grants)

    assert not decision.permits_command("/bin/ls")
    with pytest.raises(KeyError):
        decision.command_ttl_s("/bin/ls")
    assert decision.command_ttl_s("/bin/df") == 3600


def test_ssh_ttl_order_independent():
    ceiling = [_ssh(capabilities=["shell"], commands=[], ttl=7200), _ssh(capabilities=["shell"], commands=[], ttl=1800)]
    denied = [_ssh(capabilities=["shell"], commands=[], ttl=600), _ssh(capabilities=["shell"], commands=[], ttl=900)]
    granted = [_ssh(capabilities=["shell"], commands=[], ttl=3600)]

    forward = grant.Grants([boundary(ceiling, denied)], [role(granted)])
    backward = grant.Grants([boundary(ceiling[::-1], denied[::-1])], [role(granted)])

    # ceiling union = 7200, lowered against granted 3600 -> 3600; denies clamp
    # to the smallest, 600.
    assert _decide(forward).session_ttl_s(CAP.SHELL) == 600
    assert _decide(backward).session_ttl_s(CAP.SHELL) == 600


def test_ssh_ttl_across_two_boundaries():
    # One boundary clamps a capability, a later one removes it. The removal
    # must win, and the resolved map must not keep a bound for an atom that is
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
        assert decision.session_ttl_s(CAP.PTY) == 3600
        with pytest.raises(KeyError):
            decision.session_ttl_s(CAP.SHELL)
