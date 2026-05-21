from __future__ import annotations

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


class SSHShellPermission(base.APIBase):
    username_list: list[str]
    permit_agent_forwarding: bool = False
    permit_x11_forwarding: bool = False


class SSHShellGrant(base.APIBase):
    type: typing.Literal["ssh-shell"] = "ssh-shell"
    filter: TripletFilter
    permission: SSHShellPermission


class SSHPortForwardingPermission(base.APIBase):
    username_list: list[str]


class SSHPortForwardingGrant(base.APIBase):
    type: typing.Literal["ssh-port-forwarding"] = "ssh-port-forwarding"
    filter: TripletFilter
    permission: SSHPortForwardingPermission


class SSHCommandPermission(base.APIBase):
    username_list: list[str]
    command_list: list[str]


class SSHCommandGrant(base.APIBase):
    type: typing.Literal["ssh-command"] = "ssh-command"
    filter: TripletFilter
    permission: SSHCommandPermission


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


class InvalidGrant(base.APIBase):
    type: typing.Literal["invalid"] = "invalid"


Grant = typing.Annotated[
    BoundaryGrant
    | TagGrant
    | RoleGrant
    | IdentityGrant
    | SSHShellGrant
    | SSHPortForwardingGrant
    | SSHCommandGrant
    | TenantGrant
    | AuthGrant
    | InvalidGrant,
    pydantic.Field(discriminator="type"),
]
