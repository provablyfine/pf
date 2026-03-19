import base64
import logging
import typing

import pydantic

from .. import jwk, ssh, wa
from . import model, schemas
from .context import ctx

logger = logging.getLogger(__name__)

Self = typing.TypeVar("Self")
T = typing.TypeVar("T")
R = typing.TypeVar("R")


def return_none_if_none[Self, T, R](func: typing.Callable[[Self, T], R]) -> \
    typing.Callable[[Self, T | None], R | None]:
    """Decorator that returns None if the single argument is None."""

    def wrapper(self: Self, arg: T | None) -> R | None:
        if arg is None:
            return None
        return func(self, arg)

    return wrapper


def cache_list[Self, T, R](f: typing.Callable[[Self, list[T]], dict[T, R]]) ->\
    typing.Callable[[Self, list[T]], list[R]]:
    """This decorator implements a per-object-instance cache of items."""
    attr_name = f"_cache_{f.__name__}"

    def wrapper(self: Self, items: list[T]) -> list[R]:
        cache = getattr(self, attr_name, {})
        missing_items = [i for i in items if i not in cache]
        if len(missing_items) > 0:
            got_items = f(self, missing_items)
            if len(got_items) != len(missing_items):
                logger.debug(f"Unable to find one of the items in the database: {missing_items}")
                raise ValueError
            cache.update(got_items)
            setattr(self, attr_name, cache)
        return [cache[i] for i in items]

    return wrapper


class GrantConverter:
    """This class serves a single purpose: hold the cache of name <-> id mappings"""

    @return_none_if_none
    @cache_list
    def from_tag_list(self, tag_list: list[schemas.TagNameValue]) -> dict[schemas.TagNameValue, int]:
        retval = {}
        for tag in tag_list:
            t = ctx.db.tag.read_one(name=tag.name, value=tag.value)
            if t is None:
                logger.debug(f"Unable to find tag in database: {tag.name}={tag.value}")
                raise ValueError
            retval[tag] = t.id
        return retval

    @return_none_if_none
    def from_tag(self, tag: schemas.TagNameValue) -> int:
        tag_list = self.from_tag_list([tag])
        assert tag_list is not None and len(tag_list) == 1
        return tag_list[0]

    @return_none_if_none
    @cache_list
    def from_boundary_list(self, boundary_list: list[str]) -> dict[str, int]:
        return {t.name: t.id for t in ctx.db.boundary.read_all(name=boundary_list)}

    @return_none_if_none
    def from_boundary(self, boundary: str) -> int:
        boundary_list = self.from_boundary_list([boundary])
        assert boundary_list is not None and len(boundary_list) == 1
        return boundary_list[0]

    @return_none_if_none
    @cache_list
    def from_role_list(self, role_list: list[str]) -> dict[str, int]:
        return {r.name: r.id for r in ctx.db.role.read_all(name=role_list)}

    @return_none_if_none
    def from_role(self, role: str) -> int:
        role_list = self.from_role_list([role])
        assert role_list is not None and len(role_list) == 1
        return role_list[0]

    @return_none_if_none
    @cache_list
    def from_identity_list(self, identity_list: list[str]) -> dict[str, int]:
        return {i.name: i.id for i in ctx.db.identity.read_all(name=identity_list)}

    @return_none_if_none
    def from_identity(self, identity: str) -> int:
        identity_list = self.from_identity_list([identity])
        assert identity_list is not None and len(identity_list) == 1
        return identity_list[0]

    @return_none_if_none
    @cache_list
    def to_tag_list(self, tag_id_list: list[int]) -> dict[int, schemas.TagNameValue]:
        return {t.id: schemas.TagNameValue(name=t.name, value=t.value) for t in ctx.db.tag.read_all(id=tag_id_list)}

    @return_none_if_none
    def to_tag(self, tag_id: int) -> schemas.TagNameValue:
        tag_list = self.to_tag_list([tag_id])
        assert tag_list is not None and len(tag_list) == 1
        return tag_list[0]

    @return_none_if_none
    @cache_list
    def to_boundary_list(self, boundary_id_list: list[int]) -> dict[int, str]:
        return {t.id: t.name for t in ctx.db.boundary.read_all(id=boundary_id_list)}

    @return_none_if_none
    def to_boundary(self, boundary_id: int) -> str:
        boundary_list = self.to_boundary_list([boundary_id])
        assert boundary_list is not None and len(boundary_list) == 1
        return boundary_list[0]

    @return_none_if_none
    @cache_list
    def to_role_list(self, role_id_list: list[int]) -> dict[int, str]:
        return {r.id: r.name for r in ctx.db.role.read_all(id=role_id_list)}

    @return_none_if_none
    def to_role(self, role_id: int) -> str:
        role_list = self.to_role_list([role_id])
        assert role_list is not None and len(role_list) == 1
        return role_list[0]

    @return_none_if_none
    @cache_list
    def to_identity_list(self, identity_id_list: list[int]) -> dict[int, str]:
        return {i.id: i.name for i in ctx.db.identity.read_all(id=identity_id_list)}

    @return_none_if_none
    def to_identity(self, identity_id: int) -> str:
        identity_list = self.to_identity_list([identity_id])
        assert identity_list is not None and len(identity_list) == 1
        return identity_list[0]


def grant_to_schema(converter: GrantConverter, grant: model.grant.Grant) -> schemas.Grant:
    try:
        return _grant_to_schema(converter, grant)
    except ValueError:
        return schemas.InvalidGrant()


def _grant_to_schema(converter: GrantConverter, grant: model.grant.Grant) -> schemas.Grant:
    match grant.type:
        case "tag":
            filter = schemas.TagFilter(name_value=converter.to_tag(grant.filter.id))
            permission = schemas.TagPermission(
                create=grant.permission.create,
                read=grant.permission.read,
                delete=grant.permission.delete,
            )
            g = schemas.TagGrant(filter=filter, permission=permission)
        case "boundary":
            filter = schemas.BoundaryFilter(name=converter.to_boundary(grant.filter.id))
            permission = schemas.BoundaryPermission(
                create=grant.permission.create,
                read=grant.permission.read,
                update=None
                if grant.permission.update is None
                else schemas.BoundaryUpdatePermission(
                    name=grant.permission.update.name,
                    description=grant.permission.update.description,
                    ceiling_list=grant.permission.update.ceiling_list,
                    denied_list=grant.permission.update.denied_list,
                ),
                delete=grant.permission.delete,
            )
            g = schemas.BoundaryGrant(filter=filter, permission=permission)
        case "role":
            filter = schemas.RoleFilter(name=converter.to_role(grant.filter.id))
            permission = schemas.RolePermission(
                create=grant.permission.create,
                read=grant.permission.read,
                update=None
                if grant.permission.update is None
                else schemas.RoleUpdatePermission(
                    name=grant.permission.update.name,
                    description=grant.permission.update.description,
                    grant_list=grant.permission.update.grant_list,
                    member_list=grant.permission.update.member_list,
                ),
                delete=grant.permission.delete,
            )
            g = schemas.RoleGrant(filter=filter, permission=permission)
        case "identity":
            filter = schemas.IdentityFilter(
                name=converter.to_identity(grant.filter.id),
                tag_list=converter.to_tag_list(grant.filter.tag_id_list),
                boundary_list=converter.to_boundary_list(grant.filter.boundary_id_list),
            )
            permission = schemas.IdentityPermission(
                create=None
                if grant.permission.create is None
                else schemas.IdentityCreatePermission(
                    allowed=grant.permission.create.allowed,
                    allowed_tag_list=converter.to_tag_list(grant.permission.create.allowed_tag_id_list),
                    required_boundary_list=converter.to_boundary_list(
                        grant.permission.create.required_boundary_id_list
                    ),
                ),
                read=grant.permission.read,
                update=None
                if grant.permission.update is None
                else schemas.IdentityUpdatePermission(
                    name=grant.permission.update.name,
                ),
                delete=grant.permission.delete,
                add_tag_list=converter.to_tag_list(grant.permission.add_tag_id_list),
                del_tag_list=converter.to_tag_list(grant.permission.del_tag_id_list),
                invite_list=grant.permission.invite_list,
            )
            g = schemas.IdentityGrant(filter=filter, permission=permission)
        case "ssh":
            filter = schemas.SSHFilter(
                name=converter.to_identity(grant.filter.id),
                tag_list=converter.to_tag_list(grant.filter.tag_id_list),
                boundary_list=converter.to_boundary_list(grant.filter.boundary_id_list),
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
    try:
        return _grant_from_schema(converter, grant)
    except ValueError:
        raise wa.HTTPException(wa.ProblemResponse(status_code=400, title="Grant specification is invalid"))


def _grant_from_schema(converter: GrantConverter, grant: schemas.Grant) -> model.grant.Grant:
    match grant.type:
        case "invalid":
            logger.error("Invalid grants cannot be converted back to grants")
            raise ValueError
        case "tag":
            filter = model.grant.TagFilter(id=converter.from_tag(grant.filter.name_value))
            permission = model.grant.TagPermission(
                create=grant.permission.create,
                read=grant.permission.read,
                delete=grant.permission.delete,
            )
            g = model.grant.TagGrant(filter=filter, permission=permission)
        case "boundary":
            filter = model.grant.BoundaryFilter(id=converter.from_boundary(grant.filter.name))
            permission = model.grant.BoundaryPermission(
                create=grant.permission.create,
                read=grant.permission.read,
                update=None
                if grant.permission.update is None
                else model.grant.BoundaryUpdatePermission(
                    name=grant.permission.update.name,
                    description=grant.permission.update.description,
                    ceiling_list=grant.permission.update.ceiling_list,
                    denied_list=grant.permission.update.denied_list,
                ),
                delete=grant.permission.delete,
            )
            g = model.grant.BoundaryGrant(filter=filter, permission=permission)
        case "role":
            filter = model.grant.RoleFilter(id=converter.from_role(grant.filter.name))
            permission = model.grant.RolePermission(
                create=grant.permission.create,
                read=grant.permission.read,
                update=None
                if grant.permission.update is None
                else model.grant.RoleUpdatePermission(
                    name=grant.permission.update.name,
                    description=grant.permission.update.description,
                    grant_list=grant.permission.update.grant_list,
                    member_list=grant.permission.update.member_list,
                ),
                delete=grant.permission.delete,
            )
            g = model.grant.RoleGrant(filter=filter, permission=permission)
        case "identity":
            filter = model.grant.IdentityFilter(
                id=converter.from_identity(grant.filter.name),
                tag_id_list=converter.from_tag_list(grant.filter.tag_list),
                boundary_id_list=converter.from_boundary_list(grant.filter.boundary_list),
            )
            permission = model.grant.IdentityPermission(
                create=None
                if grant.permission.create is None
                else model.grant.IdentityCreatePermission(
                    allowed=grant.permission.create.allowed,
                    allowed_tag_id_list=converter.from_tag_list(grant.permission.create.allowed_tag_list),
                    required_boundary_id_list=converter.from_boundary_list(
                        grant.permission.create.required_boundary_list
                    ),
                ),
                read=grant.permission.read,
                update=None
                if grant.permission.update is None
                else model.grant.IdentityUpdatePermission(
                    name=grant.permission.update.name,
                ),
                delete=grant.permission.delete,
                add_tag_id_list=converter.from_tag_list(grant.permission.add_tag_list),
                del_tag_id_list=converter.from_tag_list(grant.permission.del_tag_list),
                invite_list=grant.permission.invite_list,
            )
            g = model.grant.IdentityGrant(filter=filter, permission=permission)
        case "ssh":
            filter = model.grant.SSHFilter(
                id=converter.from_identity(grant.filter.name),
                tag_id_list=converter.from_tag_list(grant.filter.tag_list),
                boundary_id_list=converter.from_boundary_list(grant.filter.boundary_list),
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
            g = model.grant.SSHGrant(filter=filter, permission=permission)
        case _:
            assert False
    return g


def symmetric_to_schema(key: jwk.Symmetric) -> schemas.SymmetricJWK:
    return schemas.SymmetricJWK(**key.to_dict())


def public_from_schema(key: schemas.PublicJWK) -> jwk.Public:
    return jwk.Public.from_dict(key.model_dump())


def public_to_schema(key: jwk.Public) -> schemas.PublicJWK:
    return pydantic.TypeAdapter(schemas.PublicJWK).validate_python(key.to_dict())


def cert_to_schema(c: ssh.cert.Cert) -> str:
    return base64.b64encode(c.to_openssh()).decode("utf-8")


def tag_to_schema(tag) -> schemas.Tag:
    return schemas.Tag(id=tag.id, name=tag.name, value=tag.value)


def boundary_to_schema(converter: GrantConverter, boundary: model.boundary.Boundary) -> schemas.Boundary:
    return schemas.Boundary(
        id=boundary.id,
        name=boundary.name,
        description=boundary.description,
        ceiling_list=None
        if boundary.ceiling_list is None
        else [grant_to_schema(converter, g) for g in boundary.ceiling_list],
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
    boundaries = ctx.db.boundary.read_all(
        id=list(set(boundary_id for i in identities for boundary_id in i.boundary_id_list))
    )
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
