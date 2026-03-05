import logging

from .. import schemas
from .context import ctx
from . import model


logger = logging.getLogger(__name__)


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
        cache = getattr(self, attr_name, {})
        missing_items = [i for i in items if i not in cache]
        if len(missing_items) > 0:
            got_items = f(self, missing_items)
            if len(got_items) != len(missing_items):
                logger.debug(f'Unable to find one of the items in the database: {missing_items}')
                raise ValueError
            cache.update(got_items)
            setattr(self, attr_name, cache)
        return [cache[i] for i in items]
    return wrapper

class GrantConverter:
    """ This class serves a single purpose: hold the cache of name <-> id mappings """
    @methodcache
    def from_tag_list(self, tag_list: list[str]) -> dict[str,int]:
        retval = {}
        for tag in tag_list:
            equal = tag.find('=')
            if equal == -1:
                logger.debug(f'Unable to parse tag=value: {tag}')
                raise ValueError
            name = tag[:equal]
            value = tag[equal+1:]
            t = ctx.db.tag.read_one(name=name, value=value)
            if t is None:
                logger.debug(f'Unable to find tag in database: {tag}')
                raise ValueError
            retval[tag] = t.id
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


def tag_to_schema(tag) -> schemas.Tag:
    return schemas.Tag(id=tag.id, name=tag.name, value=tag.value)


def grant_to_schema(converter: GrantConverter, grant: model.grant.Grant) -> schemas.Grant:
    match grant.type:
        case 'invalid':
            g = schemas.InvalidGrant()
        case 'tag':
            filter = schemas.TagFilter(None if grant.filter.id is None else converter.to_tag_list([grant.filter.id])[0])
            permission = schemas.TagPermission(create=grant.create, read=grant.read, delete=grant.delete)
            g = schemas.TagGrant(filter=filter, permission=permission)
        case 'boundary':
            filter = schemas.BoundaryFilter(None if grant.filter.id is None else converter.to_boundary_list([grant.filter.id])[0])
            permission = schemas.BoundaryPermission(
                create=grant.permission.create,
                read=grant.permission.read,
                update=schemas.BoundaryUpdatePermission(
                    name=grant.permission.update.name,
                    description=grant.permission.update.description,
                    ceiling_list=grant.permission.update.ceiling_list,
                    denied_list=grant.permission.update.denied_list,
                ),
                delete=grant.permission.delete,
            )
            g = schemas.BoundaryGrant(filter=filter, permission=permission)
        case 'role':
            filter = schemas.RoleFilter(None if grant.filter.id is None else converter.to_role_list([grant.filter.id])[0])
            permission = schemas.RolePermission(
                create=grant.permission.create,
                read=grant.permission.read,
                update=schemas.RoleUpdatePermission(
                    name=grant.permission.update.name,
                    description=grant.permission.update.description,
                    grant_list=grant.permission.update.grant_list,
                    member_list=grant.permission.update.member_list,
                ),
                delete=grant.permission.delete,
            )
            g = schemas.RoleGrant(filter=filter, permission=permission)
        case 'identity':
            filter = schemas.IdentityFilter(
                name=None if grant.filter.id is None else converter.to_identity_list([grant.filter.id])[0],
                tag_list=None if grant.filter.tag_list is None else converter.to_tag_list(grant.filter.tag_list),
                boundary_list=None if grant.filter.boundary_list is None else converter.to_boundary_list(grant.filter.boundary_list),
            )
            permission = schemas.IdentityPermission(
                create=grant.permission.create,
                read=grant.permission.read,
                update=schemas.IdentityUpdatePermission(
                    name=grant.permission.update.name,
                ),
                delete=grant.permission.delete,
                add_tag_list=None if grant.permission.add_tag_list is None else converter.to_tag_list(grant.permission.add_tag_list),
                del_tag_list=None if grant.permission.del_tag_list is None else converter.to_tag_list(grant.permission.del_tag_list),
                invite_list=grant.permission.invite_list,
            )
            g = schemas.IdentityGrant(filter=filter, permission=permission)
        case 'ssh':
            filter = schemas.SSHFilter(
                name=None if grant.filter.id is None else converter.to_identity_list([grant.filter.id])[0],
                tag_list=None if grant.filter.tag_list is None else converter.to_tag_list(grant.filter.tag_list),
                boundary_list=None if grant.filter.boundary_list is None else converter.to_boundary_list(grant.filter.boundary_list),
            )
            permission = schemas.SSHPermission(
                    force_command_list=grant.permission.force_command_list,
                    username_list=grant.permission.username_list,
                    permit_pty=grant.permission.permit_pty,
                    permit_user_rc=grant.permission.permit_user_rc,
                    permit_x11_forwarding=grant.permission.permit_x11_forwarding,
                    permit_agent_forwarding=grant.permission.permit_agent_forwarding,
                    permit_port_forwarding=grant.permission.permit_port_forwarding,
            )
            g = schemas.SSHGrant(filter=filter, permission=permission)
        case _:
            assert False
    return g

def grant_from_schema(converter: GrantConverter, grant: schemas.Grant) -> model.grant.Grant:
    match grant.type:
        case 'invalid':
            g = model.grant.InvalidGrant()
        case 'tag':
            filter = model.grant.TagFilter(None if grant.filter.name_value is None else converter.from_tag_list([grant.filter.name_value])[0])
            permission = model.grant.TagPermission(create=grant.create, read=grant.read, delete=grant.delete)
            g = model.grant.TagGrant(filter=filter, permission=permission)
        case 'boundary':
            filter = model.grant.BoundaryFilter(None if grant.filter.name is None else converter.from_boundary_list([grant.filter.name])[0])
            permission = model.grant.BoundaryPermission(
                create=grant.permission.create,
                read=grant.permission.read,
                update=model.grant.BoundaryUpdatePermission(
                    name=grant.permission.update.name,
                    description=grant.permission.update.description,
                    ceiling_list=grant.permission.update.ceiling_list,
                    denied_list=grant.permission.update.denied_list,
                ),
                delete=grant.permission.delete,
            )
            g = model.grant.BoundaryGrant(filter=filter, permission=permission)
        case 'role':
            filter = model.grant.RoleFilter(None if grant.filter.name is None else converter.from_role_list([grant.filter.name])[0])
            permission = model.grant.RolePermission(
                create=grant.permission.create,
                read=grant.permission.read,
                update=model.grant.RoleUpdatePermission(
                    name=grant.permission.update.name,
                    description=grant.permission.update.description,
                    grant_list=grant.permission.update.grant_list,
                    member_list=grant.permission.update.member_list,
                ),
                delete=grant.permission.delete,
            )
            g = model.grant.RoleGrant(filter=filter, permission=permission)
        case 'identity':
            filter = model.grant.IdentityFilter(
                id=None if grant.filter.name is None else converter.from_identity_list([grant.filter.name])[0],
                tag_list=None if grant.filter.tag_list is None else converter.from_tag_list(grant.filter.tag_list),
                boundary_list=None if grant.filter.boundary_list is None else converter.from_boundary_list(grant.filter.boundary_list),
            )
            permission = model.grant.IdentityPermission(
                create=grant.permission.create,
                read=grant.permission.read,
                update=model.grant.IdentityUpdatePermission(
                    name=grant.permission.update.name,
                ),
                delete=grant.permission.delete,
                add_tag_list=None if grant.permission.add_tag_list is None else converter.from_tag_list(grant.permission.add_tag_list),
                del_tag_list=None if grant.permission.del_tag_list is None else converter.from_tag_list(grant.permission.del_tag_list),
                invite_list=grant.permission.invite_list,
            )
            g = schemas.IdentityGrant(filter=filter, permission=permission)
        case 'ssh':
            filter = model.grant.SSHFilter(
                id=None if grant.filter.name is None else converter.from_identity_list([grant.filter.name])[0],
                tag_list=None if grant.filter.tag_list is None else converter.to_tag_list(grant.filter.tag_list),
                boundary_list=None if grant.filter.boundary_list is None else converter.to_boundary_list(grant.filter.boundary_list),
            )
            permission = model.grant.SSHPermission(
                    force_command_list=grant.permission.force_command_list,
                    username_list=grant.permission.username_list,
                    permit_pty=grant.permission.permit_pty,
                    permit_user_rc=grant.permission.permit_user_rc,
                    permit_x11_forwarding=grant.permission.permit_x11_forwarding,
                    permit_agent_forwarding=grant.permission.permit_agent_forwarding,
                    permit_port_forwarding=grant.permission.permit_port_forwarding,
            )
            g = schemas.SSHGrant(filter=filter, permission=permission)
        case _:
            assert False
    return g

def boundary_to_schema(converter: GrantConverter, boundary: model.boundary.Boundary) -> schemas.Boundary:
    return schemas.Boundary(
        id=boundary.id,
        name=boundary.name,
        description=boundary.description,
        ceiling_list=[grant_to_schema(converter, g) for g in boundary.ceiling_list],
        denied_list=[grant_to_schema(converter, g) for g in boundary.denied_list],
    )
