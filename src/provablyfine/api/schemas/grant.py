from __future__ import annotations

import enum
import typing

import pydantic

from . import base, tag


class TripletFilter(base.APIBase):
    name: str | None = None
    tag_list: list[tag.TagNameValue] | None = None
    boundary_list: list[str] | None = None


class CRDPermission(base.APIBase):
    create: bool
    read: bool
    delete: bool


class BoundaryFilter(base.APIBase):
    name: str | None


class BoundaryUpdatePermission(base.APIBase):
    name: bool
    description: bool
    ceiling_list: bool
    denied_list: bool


class BoundaryPermission(CRDPermission):
    update: BoundaryUpdatePermission | None


class BoundaryGrant(base.APIBase):
    type: typing.Literal["boundary"] = "boundary"
    filter: BoundaryFilter
    permission: BoundaryPermission


class TagFilter(base.APIBase):
    name_value: tag.TagNameValue | None


class TagPermission(CRDPermission):
    pass


class TagGrant(base.APIBase):
    type: typing.Literal["tag"] = "tag"
    filter: TagFilter
    permission: TagPermission


class RoleUpdatePermission(base.APIBase):
    name: bool
    description: bool
    grant_list: bool
    member_list: bool


class RolePermission(CRDPermission):
    update: RoleUpdatePermission | None


class RoleFilter(base.APIBase):
    name: str | None


class RoleGrant(base.APIBase):
    type: typing.Literal["role"] = "role"
    filter: RoleFilter
    permission: RolePermission


class IdentityCreatePermission(base.APIBase):
    allowed: bool
    allowed_tag_list: list[tag.TagNameValue] | None
    required_boundary_list: list[str] | None


class IdentityUpdatePermission(base.APIBase):
    name: bool
    unix_username: bool = False


class IdentityPermission(base.APIBase):
    create: IdentityCreatePermission | None
    read: bool
    update: IdentityUpdatePermission | None
    delete: bool
    add_tag_list: list[tag.TagNameValue] | None
    del_tag_list: list[tag.TagNameValue] | None
    invite_list: list[str] | None


class IdentityGrant(base.APIBase):
    type: typing.Literal["identity"] = "identity"
    filter: TripletFilter
    permission: IdentityPermission


# Mirrors model.grant.SSHCapability. Duplicated rather than imported: schemas
# must not depend on the model layer.
class SSHCapability(enum.StrEnum):
    SHELL = "shell"
    PTY = "pty"
    USER_RC = "user-rc"
    AGENT_FORWARDING = "agent-forwarding"
    X11_FORWARDING = "x11-forwarding"
    PORT_FORWARDING = "port-forwarding"


class SSHPermission(base.APIBase):
    # None always denotes the whole axis: any username, all capabilities
    # (including future ones), any command.
    username_list: list[str] | None
    capability_list: list[SSHCapability] | None
    command_list: list[str] | None
    # The one ordered dimension: grants raise it, ceilings and denies lower it.
    max_session_ttl_s: int | None = pydantic.Field(gt=0)

    @pydantic.model_validator(mode="after")
    def _reject_empty_atom_set(self) -> SSHPermission:
        if self.capability_list == [] and self.command_list == []:
            raise ValueError("capability_list and command_list must not both be empty")
        return self


class SSHGrant(base.APIBase):
    type: typing.Literal["ssh"] = "ssh"
    filter: TripletFilter
    permission: SSHPermission


class TenantUpdatePermission(base.APIBase):
    display_name: bool
    is_enabled: bool


class TenantPermission(base.APIBase):
    create: bool
    read: bool
    delete: bool
    update: TenantUpdatePermission | None


class TenantFilter(base.APIBase):
    id: int | None


class TenantGrant(base.APIBase):
    type: typing.Literal["tenant"] = "tenant"
    filter: TenantFilter
    permission: TenantPermission


class AuthFilter(base.APIBase):
    name: str | None  # human name of auth config, None = any


class AuthUpdatePermission(base.APIBase):
    name: bool
    description: bool
    is_enabled: bool
    config: bool


class AuthPermission(CRDPermission):
    update: AuthUpdatePermission | None


class AuthGrant(base.APIBase):
    type: typing.Literal["auth"] = "auth"
    filter: AuthFilter
    permission: AuthPermission


class BastionFilter(base.APIBase):
    id: int | None


class BastionUpdatePermission(base.APIBase):
    url: bool
    ssh_proxy_jump: bool
    tag_list: bool


class BastionPermission(CRDPermission):
    update: BastionUpdatePermission | None


class BastionGrant(base.APIBase):
    type: typing.Literal["bastion"] = "bastion"
    filter: BastionFilter
    permission: BastionPermission


class AuditLogFilter(base.APIBase):
    pass


class AuditLogPermission(base.APIBase):
    read: bool


class AuditLogGrant(base.APIBase):
    type: typing.Literal["audit-log"] = "audit-log"
    filter: AuditLogFilter
    permission: AuditLogPermission


class InvalidGrant(base.APIBase):
    type: typing.Literal["invalid"] = "invalid"


Grant = typing.Annotated[
    BoundaryGrant
    | TagGrant
    | RoleGrant
    | IdentityGrant
    | SSHGrant
    | TenantGrant
    | AuthGrant
    | BastionGrant
    | AuditLogGrant
    | InvalidGrant,
    pydantic.Field(discriminator="type"),
]
