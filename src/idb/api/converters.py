import logging
import base64

from .. import schemas
from .. import jwk
from .. import ssh

from . import model
from .context import ctx


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


def grant_to_schema(converter: GrantConverter, grant: model.grant.Grant) -> schemas.Grant:
    match grant.type:
        case 'invalid':
            g = schemas.InvalidGrant()
        case 'tag':
            filter = schemas.TagFilter(name_value=None if grant.filter.id is None else converter.to_tag_list([grant.filter.id])[0])
            permission = schemas.TagPermission(create=grant.permission.create, read=grant.permission.read, delete=grant.permission.delete)
            g = schemas.TagGrant(filter=filter, permission=permission)
        case 'boundary':
            filter = schemas.BoundaryFilter(name=None if grant.filter.id is None else converter.to_boundary_list([grant.filter.id])[0])
            permission = schemas.BoundaryPermission(
                create=grant.permission.create,
                read=grant.permission.read,
                update=None if grant.permission.update is None else schemas.BoundaryUpdatePermission(
                    name=grant.permission.update.name,
                    description=grant.permission.update.description,
                    ceiling_list=grant.permission.update.ceiling_list,
                    denied_list=grant.permission.update.denied_list,
                ),
                delete=grant.permission.delete,
            )
            g = schemas.BoundaryGrant(filter=filter, permission=permission)
        case 'role':
            filter = schemas.RoleFilter(name=None if grant.filter.id is None else converter.to_role_list([grant.filter.id])[0])
            permission = schemas.RolePermission(
                create=grant.permission.create,
                read=grant.permission.read,
                update=None if grant.permission.update is None else schemas.RoleUpdatePermission(
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
                tag_list=None if grant.filter.tag_id_list is None else converter.to_tag_list(grant.filter.tag_id_list),
                boundary_list=None if grant.filter.boundary_id_list is None else converter.to_boundary_list(grant.filter.boundary_id_list),
            )
            permission = schemas.IdentityPermission(
                create=None if grant.permission.create is None else schemas.IdentityCreatePermission(
                    allowed=grant.permission.create.allowed,
                    allowed_tag_list=None if grant.permission.create.allowed_tag_id_list is None else converter.to_tag_list(grant.permission.create.allowed_tag_id_list),
                    required_boundary_list=None if grant.permission.create.required_boundary_id_list is None else converter.to_boundary_list(grant.permission.create.required_boundary_id_list)
                ),
                read=grant.permission.read,
                update=None if grant.permission.update is None else schemas.IdentityUpdatePermission(
                    name=grant.permission.update.name,
                ),
                delete=grant.permission.delete,
                add_tag_list=None if grant.permission.add_tag_id_list is None else converter.to_tag_list(grant.permission.add_tag_id_list),
                del_tag_list=None if grant.permission.del_tag_id_list is None else converter.to_tag_list(grant.permission.del_tag_id_list),
                invite_list=grant.permission.invite_list,
            )
            g = schemas.IdentityGrant(filter=filter, permission=permission)
        case 'ssh':
            filter = schemas.SSHFilter(
                name=None if grant.filter.id is None else converter.to_identity_list([grant.filter.id])[0],
                tag_list=None if grant.filter.tag_id_list is None else converter.to_tag_list(grant.filter.tag_id_list),
                boundary_list=None if grant.filter.boundary_id_list is None else converter.to_boundary_list(grant.filter.boundary_id_list),
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
            filter = model.grant.TagFilter(id=None if grant.filter.name_value is None else converter.from_tag_list([grant.filter.name_value])[0])
            permission = model.grant.TagPermission(create=grant.create, read=grant.read, delete=grant.delete)
            g = model.grant.TagGrant(filter=filter, permission=permission)
        case 'boundary':
            filter = model.grant.BoundaryFilter(id=None if grant.filter.name is None else converter.from_boundary_list([grant.filter.name])[0])
            permission = model.grant.BoundaryPermission(
                create=grant.permission.create,
                read=grant.permission.read,
                update=None if grant.permission.update is None else model.grant.BoundaryUpdatePermission(
                    name=grant.permission.update.name,
                    description=grant.permission.update.description,
                    ceiling_list=grant.permission.update.ceiling_list,
                    denied_list=grant.permission.update.denied_list,
                ),
                delete=grant.permission.delete,
            )
            g = model.grant.BoundaryGrant(filter=filter, permission=permission)
        case 'role':
            filter = model.grant.RoleFilter(id=None if grant.filter.name is None else converter.from_role_list([grant.filter.name])[0])
            permission = model.grant.RolePermission(
                create=grant.permission.create,
                read=grant.permission.read,
                update=None if grant.permission.update is None else model.grant.RoleUpdatePermission(
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
                tag_id_list=None if grant.filter.tag_list is None else converter.from_tag_list(grant.filter.tag_list),
                boundary_id_list=None if grant.filter.boundary_list is None else converter.from_boundary_list(grant.filter.boundary_list),
            )
            permission = model.grant.IdentityPermission(
                create=None if grant.permission.create is None else model.grant.IdentityCreatePermission(
                    allowed=grant.permission.create.allowed,
                    allowed_tag_id_list=None if grant.permission.create.allowed_tag_list is None else converter.from_tag_list(grant.permission.create.allowed_tag_list),
                    required_boundary_id_list=None if grant.permission.create.required_boundary_list is None else converter.from_boundary_list(grant.permission.create.required_boundary_list),
                ),
                read=grant.permission.read,
                update=None if grant.permission.update is None else model.grant.IdentityUpdatePermission(
                    name=grant.permission.update.name,
                ),
                delete=grant.permission.delete,
                add_tag_id_list=None if grant.permission.add_tag_list is None else converter.from_tag_list(grant.permission.add_tag_list),
                del_tag_id_list=None if grant.permission.del_tag_list is None else converter.from_tag_list(grant.permission.del_tag_list),
                invite_list=grant.permission.invite_list,
            )
            g = schemas.IdentityGrant(filter=filter, permission=permission)
        case 'ssh':
            filter = model.grant.SSHFilter(
                id=None if grant.filter.name is None else converter.from_identity_list([grant.filter.name])[0],
                tag_id_list=None if grant.filter.tag_list is None else converter.to_tag_list(grant.filter.tag_list),
                boundary_id_list=None if grant.filter.boundary_list is None else converter.to_boundary_list(grant.filter.boundary_list),
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


def symmetric_to_schema(key: jwk.Symmetric) -> schemas.SymmetricJWK:
    return schemas.SymmetricJWK(**key.to_dict())


def public_from_schema(key: schemas.PublicJWK) -> jwk.Public:
    return jwk.Public.from_dict(key.model_dump())


def public_to_schema(key: jwk.Public) -> schemas.PublicJWK:
    return schemas.PublicJWK(**key.to_dict())


def cert_to_schema(c: ssh.cert.Cert) -> str:
    return base64.b64encode(c.to_openssh()).decode('utf-8')


def tag_to_schema(tag) -> schemas.Tag:
    return schemas.Tag(id=tag.id, name=tag.name, value=tag.value)


def boundary_to_schema(converter: GrantConverter, boundary: model.boundary.Boundary) -> schemas.Boundary:
    return schemas.Boundary(
        id=boundary.id,
        name=boundary.name,
        description=boundary.description,
        ceiling_list=None if boundary.ceiling_list is None else [grant_to_schema(converter, g) for g in boundary.ceiling_list],
        denied_list=[grant_to_schema(converter, g) for g in boundary.denied_list],
    )

def role_to_schema(converter: GrantConverter, role: model.role.Role) -> schemas.Role:
    members = ctx.db.identity.read_all(id=list(set(role.member_id_list)))
    role_members = [schemas.RoleMember(id=m.id, name=m.name) for m in members]
    return schemas.Role(
        id=role.id,
        name=role.name,
        description=role.description,
        grant_list=[grant_to_schema(converter, g) for g in role.grant_list],
        member_list=role_members,
    )


def identity_list_to_schema(identities: list[model.identity.Identity]) -> list[schemas.Identity]:
    # read the data we need to format fully the output.
    tags = ctx.db.tag.read_all(id=list(set(tag_id for i in identities for tag_id in i.tag_id_list)))
    boundaries = ctx.db.boundary.read_all(id=list(set(boundary_id for i in identities for boundary_id in i.boundary_id_list)))
    tag_by_id = {t.id: tag_to_schema(t) for t in tags}
    boundary_by_id = {b.id: schemas.IdentityBoundary(id=b.id, name=b.name) for b in boundaries}


    def _one(i: model.identity.Identity) -> schemas.Identity:
        return schemas.Identity(
            id=i.id,
            name=i.name,
            tags=[tag_by_id[tag_id] for tag_id in i.tag_id_list],
            boundaries=[boundary_by_id[boundary_id] for boundary_id in i.boundary_id_list],
        )

    return [_one(i) for i in identities]


def identity_to_schema(identity: model.identity.Identity) -> schemas.Identity:
    return identity_list_to_schema([identity])[0]
