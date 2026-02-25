import types

import pytest

from . import grant


def _deserialize(l: list[grant.Grant]):
    return [grant.Grant.from_dict(g) for g in l]


def boundary(prefix, ceiling_list, denied_list):
    return types.SimpleNamespace(ceiling_list=_deserialize(ceiling_list), denied_list=_deserialize(denied_list))


def role(grant_list):
    return types.SimpleNamespace(grant_list=_deserialize(grant_list))


def _crd(create: bool, read: bool, delete: bool):
    return {
        'create': create,
        'read': read,
        'delete': delete,
    }


def _role_update(name: bool, description: bool):
    return {
        'name': name,
        'description': description,
    }

def _crud(create: bool, read: bool, update: dict[str,bool]|None, delete: bool):
    return {
        'create': create,
        'read': read,
        'update': update,
        'delete': delete,
    }


######## TAG ########

def test_empty_tag():
    grants = grant.Grants([], [])
    assert not grants.tag(None).can_create()
    assert not grants.tag(1).can_read()
    assert not grants.tag(1).can_delete()

    grants = grant.Grants([], [role([])])
    assert not grants.tag(None).can_create()
    assert not grants.tag(1).can_read()
    assert not grants.tag(1).can_delete()


@pytest.mark.parametrize("create,read,delete", [
    (False, False, False),
    (True, False, False),
    (False, True, False),
    (False, False, True),
])
def test_filter_all_tag(create, read, delete):
    grants = grant.Grants([], [role([
        {'type': 'tag', 'filter': {'id': None}, 'permission': _crd(create=create, read=read, delete=delete)}
    ])])
    assert grants.tag(None).can_create() == create
    assert grants.tag(1).can_read() == read
    assert grants.tag(1).can_delete() == delete
    assert grants.tag(2).can_read() == read
    assert grants.tag(2).can_delete() == delete


@pytest.mark.parametrize("read,delete", [
    (False, False),
    (False, False),
    (True, False),
    (False, True),
])
def test_filter_one_tag(read, delete):
    grants = grant.Grants([], [role([
        {'type': 'tag', 'filter': {'id': 2}, 'permission': _crd(create=False, read=read, delete=delete)}
    ])])
    assert not grants.tag(None).can_create()
    assert not grants.tag(1).can_read()
    assert not grants.tag(1).can_delete()
    assert grants.tag(2).can_read() == read
    assert grants.tag(2).can_delete() == delete


######## ROLE ########

def test_empty_role():
    grants = grant.Grants([], [])

    assert not grants.role(None).can_create()
    assert not grants.role(1).can_read()
    assert not grants.role(1).can_update('name')
    assert not grants.role(1).can_update('description')
    assert not grants.role(1).can_update('grant_list')
    assert not grants.role(1).can_delete()
    with pytest.raises(AssertionError):
        assert not grants.role(1).can_update('beurk')

@pytest.mark.parametrize("create,read,update,delete", [
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
])
def test_filter_all_role(create, read, update, delete):
    grants = grant.Grants([], [role([
        {'type': 'role', 'filter': {'id': None}, 'permission': _crud(create=create, read=read, update=update, delete=delete)}
    ])])
    assert grants.role(None).can_create() == create
    for role_id in [1, 2, 3]:
        assert grants.role(role_id).can_read() == read
        assert grants.role(role_id).can_delete() == delete
        assert grants.role(role_id).can_update('name') == (update is None or update['name'])
        assert grants.role(role_id).can_update('description') == (update is None or update['description'])

@pytest.mark.parametrize("read,update,delete", [
    (False, _role_update(False, False), False),
    (True, _role_update(False, False), False),
    (False, _role_update(True, False), False),
    (False, _role_update(False, True), False),
    (False, _role_update(False, False), True),
    (True, _role_update(True, True), True),
    (True, None, True),
    (False, None, True),
    (True, _role_update(True, False), True),
])
def test_filter_one_role(read, update, delete):
    grants = grant.Grants([], [role([
        {'type': 'role', 'filter': {'id': 2}, 'permission': _crud(create=False, read=read, update=update, delete=delete)}
    ])])
    assert not grants.role(None).can_create()
    for role_id in [1, 2, 3]:
        assert grants.role(role_id).can_read() == (role_id == 2 and read)
        assert grants.role(role_id).can_delete() == (role_id == 2 and delete)
        assert grants.role(role_id).can_update('name') == (role_id == 2 and (update is None or update['name']))
        assert grants.role(role_id).can_update('description') == (role_id == 2 and (update is None or update['description']))

######## BOUNDARY ########

def test_empty_boundary():
    grants = grant.Grants([], [])

    assert not grants.boundary(None).can_create()
    assert not grants.boundary(1).can_read()
    assert not grants.boundary(1).can_update('name')
    assert not grants.boundary(1).can_update('description')
    assert not grants.boundary(1).can_update('ceiling_list')
    assert not grants.boundary(1).can_update('denied_list')
    assert not grants.boundary(1).can_delete()
    with pytest.raises(AssertionError):
        assert not grants.boundary(1).can_update('beurk')

######## IDENTITY ########

def test_empty_identity():
    grants = grant.Grants([], [])

    assert not grants.identity(None, None, None).can_create()
    assert not grants.identity(1, [], []).can_read()
    assert not grants.identity(1, [], []).can_update('name')
    assert not grants.identity(1, [], []).can_delete()
    with pytest.raises(AssertionError):
        assert not grants.identity(1, [], []).can_update('beurk')

######## SSH ########

def test_empty_ssh():
    grants = grant.Grants([], [])

    assert len(grants.ssh(None, None, None).list_can_username('hello')) == 0


