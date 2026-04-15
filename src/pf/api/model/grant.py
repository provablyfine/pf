from __future__ import annotations

import logging
import typing

import pydantic

from .. import app_db


logger = logging.getLogger(__name__)


class DBBase(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="forbid")


class Filter(DBBase):
    pass


class TripletFilter(Filter):
    id: int | None = None
    tag_id_list: list[int] | None = None
    boundary_id_list: list[int] | None = None

class TripletGrant(DBBase):
    filter: TripletFilter


class CRDPermission(DBBase):
    create: bool
    read: bool
    delete: bool


class BoundaryFilter(Filter):
    id: int | None


class BoundaryUpdatePermission(DBBase):
    name: bool
    description: bool
    ceiling_list: bool
    denied_list: bool


class BoundaryPermission(CRDPermission):
    update: BoundaryUpdatePermission | None


class BoundaryGrant(DBBase):
    type: typing.Literal["boundary"] = "boundary"
    filter: BoundaryFilter
    permission: BoundaryPermission


class TagFilter(Filter):
    id: int | None


class TagPermission(CRDPermission):
    pass


class TagGrant(DBBase):
    type: typing.Literal["tag"] = "tag"
    filter: TagFilter
    permission: TagPermission


class RoleUpdatePermission(DBBase):
    name: bool
    description: bool
    grant_list: bool
    member_list: bool


class RolePermission(CRDPermission):
    update: RoleUpdatePermission | None


class RoleFilter(Filter):
    id: int | None


class RoleGrant(DBBase):
    type: typing.Literal["role"] = "role"
    filter: RoleFilter
    permission: RolePermission


class IdentityCreatePermission(DBBase):
    """
    Attributes:
      allowed:
               Are we allowed to create identities ? This is useful
               if you want to disallow identity creation.
      allowed_tag_id_list:
               The maximal list of tags that can be assigned to the
               newly-created identity at creation time. It is legal
               to create identities with LESS tags than allowed here.
               If None, any tag can be used. If list is empty, no tag
               can be used.
      required_boundary_tag_id_list:
               The minimal list of boundaries that must be
               assigned to the newly-created identity at creation time.
               It is legal to create identities with MORE boundaries
               than required here. If None or empty, no boundaries
               are required.
    """

    allowed: bool
    allowed_tag_id_list: list[int] | None
    required_boundary_id_list: list[int] | None


class IdentityUpdatePermission(DBBase):
    name: bool


class IdentityPermission(DBBase):
    create: IdentityCreatePermission | None
    read: bool
    update: IdentityUpdatePermission | None
    delete: bool
    add_tag_id_list: list[int] | None
    del_tag_id_list: list[int] | None
    invite_list: list[str] | None


class IdentityGrant(TripletGrant):
    type: typing.Literal["identity"] = "identity"
    permission: IdentityPermission


class SSHShellPermission(DBBase):
    username_list: list[str]
    permit_agent_forwarding: bool = False
    permit_x11_forwarding: bool = False


class SSHShellGrant(TripletGrant):
    type: typing.Literal["ssh-shell"] = "ssh-shell"
    permission: SSHShellPermission


class SSHPortForwardingPermission(DBBase):
    username_list: list[str]


class SSHPortForwardingGrant(TripletGrant):
    type: typing.Literal["ssh-port-forwarding"] = "ssh-port-forwarding"
    permission: SSHPortForwardingPermission


class SSHCommandPermission(DBBase):
    username_list: list[str]
    command_list: list[str]


class SSHCommandGrant(TripletGrant):
    type: typing.Literal["ssh-command"] = "ssh-command"
    permission: SSHCommandPermission


class TenantUpdatePermission(DBBase):
    display_name: bool
    is_enabled: bool


class TenantPermission(DBBase):
    create: bool
    read: bool
    delete: bool
    update: TenantUpdatePermission | None


class TenantFilter(Filter):
    id: int | None


class TenantGrant(DBBase):
    type: typing.Literal["tenant"] = "tenant"
    filter: TenantFilter
    permission: TenantPermission


class AuthFilter(Filter):
    id: int | None


class AuthUpdatePermission(DBBase):
    name: bool
    description: bool
    is_enabled: bool
    config: bool


class AuthPermission(CRDPermission):
    update: AuthUpdatePermission | None


class AuthGrant(DBBase):
    type: typing.Literal["auth"] = "auth"
    filter: AuthFilter
    permission: AuthPermission


Grant = typing.Annotated[
    BoundaryGrant
    | TagGrant
    | RoleGrant
    | IdentityGrant
    | SSHShellGrant
    | SSHPortForwardingGrant
    | SSHCommandGrant
    | TenantGrant
    | AuthGrant,
    pydantic.Field(discriminator="type"),
]


def deserialize(data: app_db.SerializedGrant) -> Grant:
    return pydantic.TypeAdapter(Grant).validate_python(data)  # type: ignore[return-value]


def serialize(grant: Grant) -> app_db.SerializedGrant:
    return grant.model_dump()
