from __future__ import annotations
import dataclasses
import typing
import abc

from ..context import ctx


def methodcache(f):
    """
    This decorator implements a per-object-instance cache of items.
    It also does None checking on the input to make sure the underlying
    lookup method does not need to deal with None input.
    """
    attr_name = f"_cache_{f.__name__}"
    def wrapper(self, items: list|None) -> list|None:
        if items is None:
            return None
        cache = getattr(self, attr_name)
        missing_items = [i for i in items if i not in cache]
        if len(missing_items) > 0:
            got_items = f(self, missing_items)
            if len(got_items) != len(missing_items):
                raise ValueError
            cache.update(got_items)
            setattr(self, attr_name, cache)
        return [cache[i] for i in items]
    return wrapper


class ClientDeserializer:
    """ This class serves a single purpose: hold the cache of name -> id mapping """
    @methodcache
    def from_tag_list(self, tag_list: list[str]) -> dict[str,int]:
        retval = {}
        for tag in tag_list:
            equal = tag.find('=')
            if equal == -1:
                raise ValueError
            name = tag[:equal]
            value = tag[equal+1:]
            t = ctx.db.tag.read_one(name=name, value=value)
            if t is None:
                raise ValueError
            retval[t.name] = t.id
        return retval

    @methodcache
    def from_boundary_list(self, boundary_list: list[str]) -> dict[str,int]:
        return {t.name: t.id for t in ctx.db.boundary.read_all(name=boundary_list)}

    @methodcache
    def from_role_list(self, role_list: list[str]) -> dict[str,int]:
        return {r.name: r.id for r in ctx.db.role.read_all(name=role_list)}

    @methodcache
    def from_identity_list(self, identity_list: list[str]) -> dict[str,int]:
        return {i.name: i.id for i in ctx.db.identity.read_all(name=identity_list)}


class ClientSerializer:
    """ This class serves a single purpose: hold the cache of id -> name mapping """
    @methodcache
    def to_tag_list(self, tag_id_list: list[int]) -> dict[int,str]:
        return {t.id: f'{t.name}={t.value}' for t in ctx.db.tag.read_all(id=tag_id_list)}

    @methodcache
    def to_boundary_list(self, boundary_id_list: list[int]) -> dict[int,str]:
        return {t.id: t.name for t in ctx.db.boundary.read_all(id=boundary_id_list)}

    @methodcache
    def to_role_list(self, role_id_list: list[int]) -> dict[int,str]:
        return {r.id: r.name for r in ctx.db.role.read_all(id=role_id_list)}

    @methodcache
    def to_identity_list(self, identity_id_list: list[int]) -> dict[int,str]:
        return {i.id: i.name for i in ctx.db.identity.read_all(id=identity_id_list)}


@dataclasses.dataclass(frozen=True)
class BaseSerde:
    @abc.abstractmethod
    def to_client_dict(self, serializer: ClientSerializer) -> dict:
        pass

    @classmethod
    @abc.abstractmethod
    def from_client_dict(klass, data: dict, deserializer: ClientDeserializer) -> typing.Self:
        pass

    def to_db_dict(self) -> dict:
        return dataclasses.asdict(self)

    @classmethod
    def from_db_dict(klass, data: dict) -> typing.Self:
        return klass(**data)


@dataclasses.dataclass(frozen=True)
class RDPermission(BaseSerde):
    read: bool
    delete: bool


@dataclasses.dataclass(frozen=True)
class CRDPermission(RDPermission):
    create: bool

    def to_client_dict(self, serializer: ClientSerializer) -> dict:
        return dataclasses.asdict(self)

    @classmethod
    def from_client_dict(klass, data: dict, deserializer: ClientDeserializer) -> typing.Self:
        return klass(**data)


@dataclasses.dataclass(frozen=True)
class CRUDPermission(CRDPermission):
    update: dict[str,bool]|None


class TagPermission(CRDPermission):
    pass


class RolePermission(CRUDPermission):
    pass


class BoundaryPermission(CRUDPermission):
    pass 


@dataclasses.dataclass(frozen=True)
class IdentityCreatePermission:
    """When an identity is created, the system
    checks that the caller is allowed to create the identity
    with the following attributes

    Attributes:
      allowed_tag_id_list: The maximal list of tags that can be assigned to the
                   newly-created identity at creation time. It is legal
                   to create identities with LESS tags than allowed here.
      required_boundary_tag_list: The minimal list of boundaries that must be
                   assigned to the newly-created identity at creation time.
                   It is legal to create identities with MORE boundaries
                   than required here.
    """
    allowed_tag_id_list: list[int]|None
    required_boundary_id_list: list[int]|None

    def to_client_dict(self, serializer: ClientSerializer) -> dict:
        return {
            'allowed_tag_list': serializer.to_tag_list(self.allowed_tag_id_list),
            'required_boundary_list': serializer.to_boundary_list(self.required_boundary_id_list),
        }

    @classmethod
    def from_client_dict(klass, data: dict, deserializer: ClientDeserializer) -> typing.Self:
        return klass(
            allowed_tag_id_list=deserializer.from_tag_list(data['create']['allowed_tag_list']),
            required_boundary_id_list=deserializer.from_boundary_list(data['create']['required_boundary_list']),
        )


@dataclasses.dataclass(frozen=True)
class IdentityPermission(RDPermission):
    create: IdentityCreatePermission
    update: dict[str,bool]|None
    add_tag_id_list: list[int]|None
    del_tag_id_list: list[int]|None
    invite_list: list[str]|None

    @classmethod
    def from_db_dict(klass, data: dict) -> typing.Self:
        return IdentityPermission(
            create=IdentityCreatePermission(**data['create']),
            read=data['read'],
            update=data['update'],
            delete=data['delete'],
            add_tag_id_list=data['add_tag_id_list'],
            del_tag_id_list=data['del_tag_id_list'],
            invite_list=data['invite_list'],
        )

    def to_client_dict(self, serializer: ClientSerializer) -> dict:
        return {
            'create': self.create.to_client_dict(serializer),
            'read': self.read,
            'update': self.update,
            'delete': self.delete,
            'add_tag_list': serializer.to_tag_list(self.add_tag_id_list),
            'del_tag_list': serializer.to_tag_list(self.del_tag_id_list),
            'invite_list': self.invite_list,
        }

    @classmethod
    def from_client_dict(klass, data: dict, deserializer: ClientDeserializer) -> typing.Self:
        return IdentityPermission(
            create=IdentityCreatePermission.from_client_dict(data['create'], deserializer),
            read=data['read'],
            update=data['update'],
            delete=data['delete'],
            add_tag_id_list=deserializer.from_tag_list(data['add_tag_list']),
            del_tag_id_list=deserializer.from_tag_list(data['del_tag_list']),
            invite_list=data['invite_list'],
        )


@dataclasses.dataclass(frozen=True)
class SSHPermission(BaseSerde):
    force_command_list: list[str]|None = None
    username_list: list[str]|None = None
    permit_pty: bool = False
    permit_user_rc: bool = False
    permit_x11_forwarding: bool = False
    permit_agent_forwarding: bool = False
    permit_port_forwarding: bool = False

    def to_client_dict(self, serializer: ClientSerializer) -> dict:
        return dataclasses.asdict(self)

    @classmethod
    def from_client_dict(klass, data: dict, deserializer: ClientDeserializer) -> typing.Self:
        return klass(**data)


@dataclasses.dataclass(frozen=True)
class SingleIdFilter(BaseSerde):
    id: int|None

    def is_match(self, id: int):
        if self.id is not None and self.id != id:
            return False
        return True


class TagFilter(SingleIdFilter):
    @abc.abstractmethod
    def to_client_dict(self, serializer: ClientSerializer) -> dict:
        return {
            'tag': None if self.id is None else serializer.to_tag_list([self.id])[0]
        }

    @classmethod
    @abc.abstractmethod
    def from_client_dict(klass, data, deserializer: ClientDeserializer) -> typing.Self:
        return TagFilter(id=None if data['tag'] is None else deserializer.from_tag_list([data['tag']])[0])


class RoleFilter(SingleIdFilter):
    def to_client_dict(self, serializer: ClientSerializer) -> dict:
        return {
            'role': None if self.id is None else serializer.to_role_list([self.id])[0]
        }

    @classmethod
    def from_client_dict(klass, data, deserializer: ClientDeserializer) -> typing.Self:
        return RoleFilter(id=None if data['role'] is None else deserializer.from_role_list([data['role']])[0])


class BoundaryFilter(SingleIdFilter):
    @abc.abstractmethod
    def to_client_dict(self, serializer: ClientSerializer) -> dict:
        return {
            'boundary': None if self.id is None else serializer.to_boundary_list([self.id])[0]
        }

    @classmethod
    @abc.abstractmethod
    def from_client_dict(klass, data, deserializer: ClientDeserializer) -> typing.Self:
        return BoundaryFilter(id=None if data['boundary'] is None else deserializer.from_boundary_list([data['boundary']])[0])


@dataclasses.dataclass(frozen=True)
class TripletFilter(BaseSerde):
    id: int|None
    tag_id_list: list[int]|None
    boundary_id_list: list[int]|None

    def to_client_dict(self, serializer: ClientSerializer) -> dict:
        return {
            'identity': None if self.id is None else serializer.to_identity_name_list([self.id])[0],
            'tag_list': serializer.to_tag_list(self.tag_id_list),
            'boundary_list': serializer.to_boundary_list(self.tag_id_list),
        }

    @classmethod
    def from_client_dict(klass, data, deserializer: ClientDeserializer) -> typing.Self:
        return klass(
            id=None if data['identity'] is None else deserializer.from_identity_list([data['identity']])[0],
            tag_id_list=deserializer.from_tag_list(data['tag_list']),
            boundary_id_list=deserializer.from_boundary_list(data['boundary_list']),
        )


class IdentityFilter(TripletFilter):
    pass


class SSHFilter(TripletFilter):
    pass


@dataclasses.dataclass(frozen=True)
class Grant(BaseSerde):
    filter: SSHFilter|IdentityFilter|TagFilter|BoundaryFilter|RoleFilter
    permission: SSHPermission|IdentityPermission|TagPermission|BoundaryPermission|RolePermission

    def _type(self):
        match self.filter:
            case SSHFilter():
                return 'ssh'
            case IdentityFilter():
                return 'identity'
            case TagFilter():
                return 'tag'
            case BoundaryFilter():
                return 'boundary'
            case RoleFilter():
                return 'role'
            case _:
                assert False

    def to_db_dict(self) -> dict:
        return {
            'type': self._type(),
            'filter': self.filter.to_db_dict(),
            'permission': self.permission.to_db_dict(),
        }

    @classmethod
    def from_db_dict(klass, data: dict) -> Grant:
        match data['type']:
            case 'ssh':
                return Grant(
                    filter=SSHFilter.from_db_dict(data['filter']),
                    permission=SSHPermission.from_db_dict(data['permission'])
                )
            case 'identity':
                return Grant(
                    filter=IdentityFilter.from_db_dict(data['filter']),
                    permission=IdentityPermission.from_db_dict(data['permission'])
                )
            case 'tag':
                return Grant(
                    filter=TagFilter.from_db_dict(data['filter']),
                    permission=TagPermission.from_db_dict(data['permission'])
                )
            case 'boundary':
                return Grant(
                    filter=BoundaryFilter.from_db_dict(data['filter']),
                    permission=BoundaryPermission.from_db_dict(data['permission'])
                )
            case 'role':
                return Grant(
                    filter=RoleFilter.from_db_dict(data['filter']),
                    permission=RolePermission.from_db_dict(data['permission'])
                )
            case _:
                assert False

    def to_client_dict(self, serializer: ClientSerializer) -> dict:
        return {
            'type': self._type(),
            'filter': self.filter.to_client_dict(serializer),
            'permission': self.filter.to_client_dict(serializer),
        }

    @classmethod
    def from_client_dict(klass, data: dict, deserializer: ClientDeserializer) -> typing.Self:
        match data['type']:
            case 'ssh':
                return Grant(
                    filter=SSHFilter.from_client_dict(data['filter'], deserializer),
                    permission=SSHPermission.from_client_dict(data['permission'], deserializer),
                )
            case 'identity':
                return Grant(
                    filter=IdentityFilter.from_client_dict(data['filter'], deserializer),
                    permission=IdentityPermission.from_client_dict(data['permission'], deserializer),
                )
            case 'tag':
                return Grant(
                    filter=TagFilter.from_client_dict(data['filter'], deserializer),
                    permission=TagPermission.from_client_dict(data['permission'], deserializer),
                )
            case 'boundary':
                return Grant(
                    filter=BoundaryFilter.from_client_dict(data['filter'], deserializer),
                    permission=BoundaryPermission.from_client_dict(data['permission'], deserializer),
                )
            case 'role':
                return Grant(
                    filter=RoleFilter.from_client_dict(data['filter'], deserializer),
                    permission=RolePermission.from_client_dict(data['permission'], deserializer),
                )
            case _:
                assert False
