from __future__ import annotations
import dataclasses
import typing


@dataclasses.dataclass(frozen=True)
class BasePermission:
    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(klass, data) -> typing.Self:
        return klass(**data)


@dataclasses.dataclass(frozen=True)
class CRDPermission(BasePermission):
    create: bool
    read: bool
    delete: bool

    def can_create(self) -> bool:
        return self.create

    def can_read(self) -> bool:
        return self.read

    def can_delete(self) -> bool:
        return self.delete


@dataclasses.dataclass(frozen=True)
class CRUDPermission(CRDPermission):
    update: dict[str,bool]|None

    def can_update(self, field: str) -> bool:
        if self.update is None:
            return True
        return self.update[field]


class TagPermission(CRDPermission):
    pass


class RolePermission(CRUDPermission):
    pass


class BoundaryPermission(CRUDPermission):
    pass


@dataclasses.dataclass(frozen=True)
class IdentityPermission(CRUDPermission):
    add_tag: list[int]|None
    del_tag: list[int]|None
    invite: list[str]|None

    def can_add_tag(self, tag_id: int) -> bool:
        if self.add_tag is None:
            return True
        return tag_id in self.add_tag

    def can_del_tag(self, tag_id: int) -> bool:
        if self.del_tag is None:
            return True
        return tag_id in self.del_tag

    def can_invite(self, delivery: str) -> bool:
        if self.invite is None:
            return True
        return delivery in self.invite


@dataclasses.dataclass(frozen=True)
class SSHPermission(BasePermission):
    force_commands: list[str]|None = None
    usernames: list[str]|None = None
    permit_pty: bool = False
    permit_user_rc: bool = False
    permit_x11_forwarding: bool = False
    permit_agent_forwarding: bool = False
    permit_port_forwarding: bool = False

    def can_username(self, username: str):
        if self.usernames is None:
            return True
        return username in self.usernames


@dataclasses.dataclass(frozen=True)
class SingleIdFilter:
    id: int|None

    def is_match(self, id: int):
        if self.id is not None and self.id != id:
            return False
        return True

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(klass, data: dict) -> typing.Self:
        return klass(**data)


class TagFilter(SingleIdFilter):
    pass


class RoleFilter(SingleIdFilter):
    pass


class BoundaryFilter(SingleIdFilter):
    pass


@dataclasses.dataclass(frozen=True)
class TripletFilter:
    id: int|None
    tag_id: list[int]|None
    boundary_id: list[int]|None

    def is_match(self, identity_id: int, tag_id_list: list[int], boundary_id_list: list[int]):
        if self.id is not None and self.id != identity_id:
            return False
        if self.tag_id is not None and not all(tag_id in tag_id_list for tag_id in self.tag_id):
            return False
        if self.boundary_id is not None and not all(boundary_id in boundary_id_list for boundary_id in self.boundary_id):
            return False
        return True

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(klass, data: dict) -> typing.Self:
        return klass(**data)

class IdentityFilter(TripletFilter):
    pass

class SSHFilter(TripletFilter):
    pass


@dataclasses.dataclass(frozen=True)
class Grant:
    filter: SSHFilter|IdentityFilter|TagFilter|BoundaryFilter|RoleFilter
    permission: SSHPermission|IdentityPermission|TagPermission|BoundaryPermission|RolePermission

    def to_dict(self) -> dict:
        data = dataclasses.asdict(self)
        match self.filter:
            case SSHFilter():
                data['type'] = 'ssh'
            case IdentityFilter():
                data['type'] = 'identity'
            case TagFilter():
                data['type'] = 'tag'
            case BoundaryFilter():
                data['type'] = 'boundary'
            case RoleFilter():
                data['type'] = 'role'
            case _:
                assert False
        return data

    @classmethod
    def from_dict(klass, data: dict) -> Grant:
        match data['type']:
            case 'ssh':
                return Grant(
                    filter=SSHFilter.from_dict(data['filter']),
                    permission=SSHPermission.from_dict(data['permission'])
                )
            case 'identity':
                return Grant(
                    filter=IdentityFilter.from_dict(data['filter']),
                    permission=IdentityPermission.from_dict(data['permission'])
                )
            case 'tag':
                return Grant(
                    filter=TagFilter.from_dict(data['filter']),
                    permission=TagPermission.from_dict(data['permission'])
                )
            case 'boundary':
                return Grant(
                    filter=BoundaryFilter.from_dict(data['filter']),
                    permission=BoundaryPermission.from_dict(data['permission'])
                )
            case 'role':
                return Grant(
                    filter=RoleFilter.from_dict(data['filter']),
                    permission=RolePermission.from_dict(data['permission'])
                )
            case _:
                assert False


class BaseWrapper:
    def __init__(self, grant_list, ceiling_list, denied_list):
        self._grant_list = grant_list
        self._ceiling_list = ceiling_list
        self._denied_list = denied_list

    def list_can(self, cmp) -> list[Grant]:
        for ceiling in self._ceiling_list:
            if not cmp(ceiling.permission):
                return []
        for denied in self._denied_list:
            if cmp(denied.permission):
                return []
        allowed = []
        for grant in self._grant_list:
            if not cmp(grant.permission):
                continue
            allowed.append(grant)
        return allowed

    def can(self, cmp) -> bool:
        for ceiling in self._ceiling_list:
            if not cmp(ceiling.permission):
                return False
        for denied in self._denied_list:
            if cmp(denied.permission):
                return False
        for grant in self._grant_list:
            if cmp(grant.permission):
                return True
        return False


class CRDWrapper(BaseWrapper):
    def can_create(self) -> bool:
        return self.can(lambda p: p.can_create())

    def can_read(self) -> bool:
        return self.can(lambda p: p.can_read())

    def can_delete(self) -> bool:
        return self.can(lambda p: p.can_delete())


class CRUDWrapper(CRDWrapper):
    def _is_update_field(self, field: str) -> bool:
        raise NotImplementedError

    def can_update(self, field: str) -> bool:
        assert self._is_update_field(field)
        return self.can(lambda p: p.can_update(field))


class TagWrapper(CRDWrapper):
    pass


class BoundaryWrapper(CRUDWrapper):
    def _is_update_field(self, field):
        return field in set(['name', 'description', 'ceiling_list', 'denied_list'])


class RoleWrapper(CRUDWrapper):
    def _is_update_field(self, field):
        return field in set(['name', 'description', 'grant_list'])


class IdentityWrapper(CRUDWrapper):
    def _is_update_field(self, field):
        return field in set(['name'])

    def can_add_tag(self, tag_id: int) -> bool:
        return self.can(lambda p: p.can_add_tag(tag_id))

    def can_del_tag(self, tag_id: int) -> bool:
        return self.can(lambda p: p.can_del_tag(tag_id))

    def can_invite(self, delivery: str) -> bool:
        return self.can(lambda p: p.can_invite(delivery))


class SSHWrapper(BaseWrapper):
    def list_can_username(self, username: str) -> list[Grant]:
        return self.list_can(lambda p: p.can_username(username))


class Grants:
    def __init__(self, boundaries, roles):
        self._boundaries = boundaries
        self._roles = roles

    def _filter(self, cmp):
        grant_list = [grant for role in self._roles for grant in role.grant_list if cmp(grant.filter)]
        ceiling_list = [ceiling for boundary in self._boundaries for ceiling in boundary.ceiling_list if cmp(ceiling.filter)]
        denied_list = [denied for boundary in self._boundaries for denied in boundary.denied_list if cmp(denied.filter)]
        return grant_list, ceiling_list, denied_list

    def boundary(self, boundary_id: int) -> BoundaryWrapper:
        def cmp(filter: BoundaryFilter) -> bool:
            return isinstance(filter, BoundaryFilter) and filter.is_match(boundary_id)
        return BoundaryWrapper(*self._filter(cmp))

    def tag(self, tag_id: int) -> TagWrapper:
        def cmp(filter: TagFilter) -> bool:
            return isinstance(filter, TagFilter) and filter.is_match(tag_id)
        return TagWrapper(*self._filter(cmp))

    def role(self, role_id: int) -> RoleWrapper:
        def cmp(filter: RoleFilter) -> bool:
            return isinstance(filter, RoleFilter) and filter.is_match(role_id)
        return RoleWrapper(*self._filter(cmp))

    def identity(self, identity_id: int, tag_id_list: list[int], boundary_id_list: list[int]) -> IdentityWrapper:
        def cmp(filter: IdentityFilter) -> bool:
            return isinstance(filter, IdentityFilter) and filter.is_match(identity_id, tag_id_list, boundary_id_list)
        return IdentityWrapper(*self._filter(cmp))

    def ssh(self, identity_id: int, tag_id_list: list[int], boundary_id_list: list[int]) -> SSHWrapper:
        def cmp(filter: SSHFilter) -> bool:
            return isinstance(filter, SSHFilter) and filter.is_match(identity_id, tag_id_list, boundary_id_list)
        return SSHWrapper(*self._filter(cmp))

