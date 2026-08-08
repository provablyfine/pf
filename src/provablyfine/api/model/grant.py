from __future__ import annotations

import enum
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
    unix_username: bool = False


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


class SSHCapability(enum.StrEnum):
    SHELL = "shell"  # the session itself; gates shell certificates
    PTY = "pty"  # certificate extension permit-pty
    USER_RC = "user-rc"  # certificate extension permit-user-rc
    AGENT_FORWARDING = "agent-forwarding"  # certificate extension permit-agent-forwarding
    X11_FORWARDING = "x11-forwarding"  # certificate extension permit-X11-forwarding
    PORT_FORWARDING = "port-forwarding"  # certificate extension permit-port-forwarding


class SSHPermission(DBBase):
    """A set of capability atoms: (username, capability) and (username, command).

    Every field is required and nullable: `None` always denotes the whole axis
    (any username, all capabilities including future ones, any command). The
    entry denotes the same atom set wherever it appears; only the operation
    depends on the list it sits in (union in a role grant_list, intersection in
    a boundary ceiling_list, subtraction in a boundary denied_list).
    """

    username_list: list[str] | None
    capability_list: list[SSHCapability] | None
    command_list: list[str] | None

    # An empty username_list is deliberately *not* rejected: the legacy types
    # allow it (the TUI creates grants that way) and upcast must not fail on a
    # stored row. It is fail-closed in every position, unlike an entry with
    # both other axes empty, which is a deny that denies nothing.
    @pydantic.model_validator(mode="after")
    def _reject_empty_atom_set(self) -> SSHPermission:
        if self.capability_list == [] and self.command_list == []:
            raise ValueError("capability_list and command_list must not both be empty")
        return self


class SSHGrant(TripletGrant):
    type: typing.Literal["ssh"] = "ssh"
    permission: SSHPermission


# The implicit shell of a legacy ssh-shell grant: issuance hardcoded
# permit_pty=True, permit_user_rc=True, permit_port_forwarding=False.
_SHELL_CAPABILITIES = [SSHCapability.SHELL, SSHCapability.PTY, SSHCapability.USER_RC]


def upcast(g: SSHShellGrant | SSHPortForwardingGrant | SSHCommandGrant) -> SSHGrant | None:
    """Map a legacy SSH grant to its new-form equivalent.

    Returns None when the legacy grant denotes no atoms at all — an
    ssh-command grant with an empty command_list, which the new schema
    deliberately cannot express. Dropping it is exact in every position: it
    granted nothing, denied nothing, and contributed nothing to a ceiling
    union.

    Position-independent, like the type it produces: an old denied_list entry
    with a dead permit_* bool maps to a superset of atoms that still contains
    SHELL, so it still denies the connection.

    Known consequence once the new checker is live: a caller holding both an
    ssh-shell and an ssh-port-forwarding grant for the same username unions to
    {SHELL, PTY, USER_RC, PORT_FORWARDING}, so their shell certificate gains
    permit-port-forwarding, which the legacy shell issuance hardcoded to False.
    That widening is inherent to merging the three types.
    """
    match g.type:
        case "ssh-shell":
            capability_list = list(_SHELL_CAPABILITIES)
            if g.permission.permit_agent_forwarding:
                capability_list.append(SSHCapability.AGENT_FORWARDING)
            if g.permission.permit_x11_forwarding:
                capability_list.append(SSHCapability.X11_FORWARDING)
            permission = SSHPermission(
                username_list=g.permission.username_list,
                capability_list=capability_list,
                command_list=[],
            )
        case "ssh-port-forwarding":
            permission = SSHPermission(
                username_list=g.permission.username_list,
                capability_list=[SSHCapability.PORT_FORWARDING],
                command_list=[],
            )
        case "ssh-command":
            if len(g.permission.command_list) == 0:
                return None
            permission = SSHPermission(
                username_list=g.permission.username_list,
                capability_list=[],
                command_list=list(g.permission.command_list),
            )
    return SSHGrant(filter=g.filter, permission=permission)


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


class BastionFilter(Filter):
    id: int | None


class BastionUpdatePermission(DBBase):
    url: bool
    ssh_proxy_jump: bool
    tag_list: bool


class BastionPermission(CRDPermission):
    update: BastionUpdatePermission | None


class BastionGrant(DBBase):
    type: typing.Literal["bastion"] = "bastion"
    filter: BastionFilter
    permission: BastionPermission


class AuditLogFilter(Filter):
    pass


class AuditLogPermission(DBBase):
    read: bool


class AuditLogGrant(DBBase):
    type: typing.Literal["audit-log"] = "audit-log"
    filter: AuditLogFilter
    permission: AuditLogPermission


Grant = typing.Annotated[
    BoundaryGrant
    | TagGrant
    | RoleGrant
    | IdentityGrant
    | SSHShellGrant
    | SSHPortForwardingGrant
    | SSHCommandGrant
    | SSHGrant
    | TenantGrant
    | AuthGrant
    | BastionGrant
    | AuditLogGrant,
    pydantic.Field(discriminator="type"),
]


def deserialize(data: app_db.SerializedGrant) -> Grant:
    return pydantic.TypeAdapter[Grant](Grant).validate_python(data)


def serialize(grant: Grant) -> app_db.SerializedGrant:
    return grant.model_dump()
