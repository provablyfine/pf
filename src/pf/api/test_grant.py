import types

import pytest

from . import grant, model


def _deserialize(l: list[dict]) -> list[model.grant.Grant]:
    return [model.grant.deserialize(g) for g in l]


def boundary(ceiling_list: list[dict], denied_list: list[dict]):
    return types.SimpleNamespace(id=1, ceiling_list=_deserialize(ceiling_list), denied_list=_deserialize(denied_list))


def role(grant_list: list[dict]):
    return types.SimpleNamespace(id=1, grant_list=_deserialize(grant_list))

def single_grants(g) -> grant.Grants:
    return grant.Grants([boundary([g], [])], [role([g])])


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
        'grant_list': False,
        'member_list': False,
    }

def _boundary_update(name: bool, description: bool, ceiling_list: bool, denied_list: bool):
    return {
        'name': name,
        'description': description,
        'ceiling_list': ceiling_list,
        'denied_list': denied_list,
    }

def _crud(create: bool, read: bool, update: dict[str,bool]|None, delete: bool):
    return {
        'create': create,
        'read': read,
        'update': update,
        'delete': delete,
    }

def _identity(create_allowed: bool, create_tag_id_list: list[int]|None, create_boundary_id_list: list[int]|None, read: bool, update: dict[str,bool]|None, delete: bool, add_tag_id_list: list[int]|None, del_tag_id_list: list[int]|None, invite_list: list[str]|None):
    return {
        'create': {
            'allowed': create_allowed,
            'allowed_tag_id_list': create_tag_id_list,
            'required_boundary_id_list': create_boundary_id_list,
        },
        'read': read,
        'update': update,
        'delete': delete,
        'add_tag_id_list': add_tag_id_list,
        'del_tag_id_list': del_tag_id_list,
        'invite_list': invite_list,
    }

def _identity_add_tag(add_tag_id_list: list[int]|None):
    return _identity(create_allowed=False, create_tag_id_list=[], create_boundary_id_list=[], read=False, update=None, delete=False, add_tag_id_list=add_tag_id_list, del_tag_id_list=[], invite_list=[])

def _identity_create(tag_id_list: list[int]|None, boundary_id_list: list[int]|None):
    return _identity(create_allowed=True, create_tag_id_list=tag_id_list, create_boundary_id_list=boundary_id_list, read=False, update=None, delete=False, add_tag_id_list=[], del_tag_id_list=[], invite_list=[])


def _ssh_username(usernames: list[str]|None):
    return {
        'force_command_list': [],
        'username_list': usernames,
        'permit_pty': False,
        'permit_user_rc': False,
        'permit_x11_forwarding': False,
        'permit_agent_forwarding': False,
        'permit_port_forwarding': False,
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

    grants = grant.Grants([boundary([], [])], [role([])])
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
    grants = single_grants({'type': 'tag', 'filter': {'id': None}, 'permission': _crd(create=create, read=read, delete=delete)})
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
    grants = single_grants({'type': 'tag', 'filter': {'id': 2}, 'permission': _crd(create=False, read=read, delete=delete)})
    assert not grants.tag(None).can_create()
    assert not grants.tag(1).can_read()
    assert not grants.tag(1).can_delete()
    assert grants.tag(2).can_read() == read
    assert grants.tag(2).can_delete() == delete


def test_tag_with_ceiling():
    # I am granted create, read, and delete but the ceiling only gives me create
    grants = grant.Grants([boundary([
        {'type': 'tag', 'filter': {'id': None}, 'permission': _crd(create=True, read=False, delete=False)}
    ], [])], [role([
        {'type': 'tag', 'filter': {'id': None}, 'permission': _crd(create=True, read=True, delete=True)}
    ])])
    assert grants.tag(None).can_create()
    assert not grants.tag(1).can_read()
    assert not grants.tag(1).can_delete()

def test_tag_with_denied():
    # I am granted create, read, and delete, within ceiling, but I am explicitely denied read
    grants = grant.Grants([boundary([
        {'type': 'tag', 'filter': {'id': None}, 'permission': _crd(create=True, read=True, delete=True)}
    ],[
        {'type': 'tag', 'filter': {'id': None}, 'permission': _crd(create=False, read=True, delete=False)}
    ])], [role([
        {'type': 'tag', 'filter': {'id': None}, 'permission': _crd(create=True, read=True, delete=True)}
    ])])
    assert grants.tag(None).can_create()
    assert not grants.tag(1).can_read()
    assert grants.tag(1).can_delete()

def test_tag_with_ceiling_and_denied():
    # I am granted create, read, and delete but the ceiling only gives me create and I am explicitely denied create
    grants = grant.Grants([boundary([
        {'type': 'tag', 'filter': {'id': None}, 'permission': _crd(create=True, read=False, delete=False)}
    ],[
        {'type': 'tag', 'filter': {'id': None}, 'permission': _crd(create=True, read=False, delete=False)}
    ])], [role([
        {'type': 'tag', 'filter': {'id': None}, 'permission': _crd(create=True, read=True, delete=True)}
    ])])
    assert not grants.tag(None).can_create()
    assert not grants.tag(1).can_read()
    assert not grants.tag(1).can_delete()

def test_tag_with_larger_ceiling():
    # I am granted create, the ceiling gives me create, read, and delete
    grants = grant.Grants([boundary([
        {'type': 'tag', 'filter': {'id': None}, 'permission': _crd(create=True, read=True, delete=True)}
    ],[])], [role([
        {'type': 'tag', 'filter': {'id': None}, 'permission': _crd(create=True, read=False, delete=False)}
    ])])
    assert grants.tag(None).can_create()
    assert not grants.tag(1).can_read()
    assert not grants.tag(1).can_delete()

def test_tag_with_multiple_ceiling():
    # I am granted create, and read, the ceiling gives me create, and read but as separate grants.
    grants = grant.Grants([boundary([
        {'type': 'tag', 'filter': {'id': None}, 'permission': _crd(create=True, read=False, delete=False)},
        {'type': 'tag', 'filter': {'id': None}, 'permission': _crd(create=False, read=True, delete=False)}
    ],[])], [role([
        {'type': 'tag', 'filter': {'id': None}, 'permission': _crd(create=True, read=True, delete=False)}
    ])])
    assert grants.tag(None).can_create()
    assert grants.tag(1).can_read()
    assert not grants.tag(1).can_delete()

def test_tag_with_ceiling_filter():
    # I am granted create, read, and delete, via multiple boundary ceiling
    grants = grant.Grants([boundary([
        {'type': 'tag', 'filter': {'id': None}, 'permission': _crd(create=True, read=False, delete=False)},
        {'type': 'tag', 'filter': {'id': 2}, 'permission': _crd(create=False, read=True, delete=True)},
    ],[
    ])], [role([
        {'type': 'tag', 'filter': {'id': None}, 'permission': _crd(create=True, read=True, delete=True)}
    ])])
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
    grants = single_grants({'type': 'role', 'filter': {'id': None}, 'permission': _crud(create=create, read=read, update=update, delete=delete)})
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
    grants = single_grants({'type': 'role', 'filter': {'id': 2}, 'permission': _crud(create=False, read=read, update=update, delete=delete)})
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

@pytest.mark.parametrize("update", [
    _boundary_update(False, False, False, False),
    _boundary_update(True, False, False, False),
    _boundary_update(False, True, False, False),
    _boundary_update(False, False, True, False),
    _boundary_update(False, False, False, True),
    _boundary_update(True, False, True, False),
    _boundary_update(False, True, False, True),
    _boundary_update(True, True, True, True),
    None,
])
def test_filter_one_boundary(update):
    # We only test the update field because the code is all the same for role 
    grants = single_grants({'type': 'boundary', 'filter': {'id': 2}, 'permission': _crud(create=False, read=False, update=update, delete=False)})
    assert not grants.boundary(None).can_create()
    for boundary_id in [1, 2, 3]:
        assert not grants.boundary(boundary_id).can_read()
        assert not grants.boundary(boundary_id).can_delete()
        assert grants.boundary(boundary_id).can_update('name') == (boundary_id == 2 and (update is None or update['name']))
        assert grants.boundary(boundary_id).can_update('description') == (boundary_id == 2 and (update is None or update['description']))
        assert grants.boundary(boundary_id).can_update('ceiling_list') == (boundary_id == 2 and (update is None or update['ceiling_list']))
        assert grants.boundary(boundary_id).can_update('denied_list') == (boundary_id == 2 and (update is None or update['denied_list']))
        with pytest.raises(AssertionError):
            assert grants.boundary(boundary_id).can_update('beurk')

######## IDENTITY ########

def test_empty_identity():
    grants = grant.Grants([], [])

    assert not grants.identity().can_create([], [])
    assert not grants.identity(1, [], []).can_read()
    assert not grants.identity(1, [], []).can_update('name')
    assert not grants.identity(1, [], []).can_delete()
    with pytest.raises(AssertionError):
        assert not grants.identity(1, [], []).can_update('beurk')

def test_identity_add_tag():
    grants = single_grants({'type': 'identity', 'filter': {'id': 2, 'tag_id_list': [], 'boundary_id_list': []}, 'permission': _identity_add_tag([1,2])})
    assert not grants.identity().can_create([], [])
    assert not grants.identity(1, [], []).can_add_tag(1)
    assert not grants.identity(1, [], []).can_add_tag(2)
    assert not grants.identity(1, [], []).can_add_tag(3)
    assert grants.identity(2, [], []).can_add_tag(1)
    assert grants.identity(2, [], []).can_add_tag(2)
    assert not grants.identity(2, [], []).can_add_tag(3)

    grants = single_grants({'type': 'identity', 'filter': {'id': 2, 'tag_id_list': [1,2], 'boundary_id_list': []}, 'permission': _identity_add_tag([1,2])})
    assert not grants.identity(1, [], []).can_add_tag(1)
    assert not grants.identity(2, [], []).can_add_tag(1)
    assert not grants.identity(2, [2], []).can_add_tag(1)
    assert not grants.identity(2, [1], []).can_add_tag(1)
    assert grants.identity(2, [1,2], []).can_add_tag(1)


def test_identity_add_tag_ceiling_and_denied():
    def _all_filter():
        return {'id': None, 'tag_id_list': None, 'boundary_id_list': None}
    grants = grant.Grants([boundary([
        {'type': 'identity', 'filter': _all_filter(), 'permission': _identity_add_tag([1,2])},
        {'type': 'identity', 'filter': _all_filter(), 'permission': _identity_add_tag([3])}
    ], [
        {'type': 'identity', 'filter': _all_filter(), 'permission': _identity_add_tag([2])}
    ])], [role([
        {'type': 'identity', 'filter': _all_filter(), 'permission': _identity_add_tag([0,1,2,3,4])}
    ])])
    assert grants.identity(1, [], []).can_add_tag(1)
    assert not grants.identity(1, [], []).can_add_tag(2)
    assert grants.identity(1, [], []).can_add_tag(3)
    assert not grants.identity(1, [], []).can_add_tag(4)


@pytest.mark.parametrize("tag_id_list,boundary_id_list,expected1,expected2", [
    [None, None, True, True],
    [None, [], True, True],
    [[], None, False, False],
    [[], [], False, False],
    [[1], [1], True, False],
    [[1], [], True, False],
    [[], [1], False, False],
    [[1], [2], False, False],
    [[1,2], [1], True, True],
    [[1,2], [1,2], False, True],
    [[1,2], [], True, True],
    [[1,2], [3,1,2], False, False],
    [[2], [2], False, False],
])
def test_identity_create(tag_id_list, boundary_id_list, expected1, expected2):
    grants = single_grants({'type': 'identity', 'filter': {'id': None, 'tag_id_list': None, 'boundary_id_list': None}, 'permission': _identity_create(tag_id_list, boundary_id_list)})

    assert grants.identity().can_create([1], [1]) == expected1
    assert grants.identity().can_create([1,2], [1,2]) == expected2


######## SSH ########

def test_empty_ssh():
    grants = grant.Grants([], [])

    assert len(grants.ssh(1, [], []).list_can_username('hello')) == 0


def test_one_ssh():
    grants = single_grants({'type': 'ssh', 'filter': {'id': None, 'tag_id_list': None, 'boundary_id_list': None}, 'permission': _ssh_username(['alice', 'bob'])})

    assert len(grants.ssh(1, [], []).list_can_username('hello')) == 0
    assert len(grants.ssh(1, [], []).list_can_username('alice')) > 0
    assert len(grants.ssh(1, [], []).list_can_username('bob')) > 0

    grants = single_grants({'type': 'ssh', 'filter': {'id': None, 'tag_id_list': None, 'boundary_id_list': None}, 'permission': _ssh_username(None)})
    assert len(grants.ssh(1, [], []).list_can_username('hello')) > 0
    assert len(grants.ssh(1, [], []).list_can_username('any')) > 0

    grants = single_grants({'type': 'ssh', 'filter': {'id': None, 'tag_id_list': None, 'boundary_id_list': None}, 'permission': _ssh_username([])})
    assert len(grants.ssh(1, [], []).list_can_username('hello')) == 0
    assert len(grants.ssh(1, [], []).list_can_username('any')) == 0
