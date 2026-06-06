# Note: These client-side schema classes mirror the definitions in pf.api.schemas,
# but cannot be shared because:
#  - Server models use extra="ignore" (tolerates unknown fields from DB/JSON) while
#    client models use extra="forbid" (strict validation to catch API contract breaks early).
#  - server models implement to_text() methods for display in the TUI, which the client
#    side does not need.
# Keeping them separate avoids coupling and lets each side evolve its constraints
# independently.

import typing

import pydantic

from . import exceptions


class GrantText(typing.NamedTuple):
    type: str
    filter: str
    permission: str


class _Base(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="ignore")


# --- Grant display helpers ---


def _bool(value: bool, name: str) -> list[str]:
    if not value:
        return []
    return [name]


def _update(update: typing.Any) -> list[str]:
    if update is None:
        return ["update.*"]
    output: list[str] = []
    for k, v in update.model_dump().items():
        if not v:
            continue
        output.append(f"update.{k}")
    return output


def _name_value(nv: typing.Any) -> str:
    return f"{nv.name}={nv.value}"


def _filter_list(val: list[typing.Any] | None, name: str, f: typing.Callable[[typing.Any], str]) -> list[str]:
    if val is None:
        return []
    if len(val) == 0:
        return [f"{name}:!"]
    return [f"{name}:{','.join(f(i) for i in val)}"]


def _permission_list(val: list[typing.Any] | None, name: str, f: typing.Callable[[typing.Any], str]) -> list[str]:
    if val is None:
        return [f"{name}:*"]
    if len(val) == 0:
        return []
    return [f"{name}:{','.join(f(i) for i in val)}"]


class Tag(_Base):
    id: int
    name: str
    value: str


class TagsResponse(_Base):
    tags: list[Tag] = []


class SshHostEntry(_Base):
    hostname: str
    type: str
    username_list: list[str] | None = None
    command_list: list[str] | None = None


class SshHostsResponse(_Base):
    hosts: list[SshHostEntry] = []


class SshCertBastion(_Base):
    url: str
    ssh_proxy_jump: str | None = None


class SshUserCertificateResponse(_Base):
    certificates: list[str]
    bastion_list: list[SshCertBastion] = []
    ip_address_list: list[str] = []


class SshHostCertificateResponse(_Base):
    certificates: list[str]


class IdentitySelfTokenResponse(_Base):
    token: str


class Tenant(_Base):
    id: int
    name: str
    display_name: str
    owner_id: int | None = None
    is_enabled: bool
    is_initialized: bool
    is_deleted: bool
    created_at: int


class TenantsResponse(_Base):
    tenants: list[Tenant] = []


class TagNameValue(_Base):
    name: str
    value: str


class HttpSigConfig(_Base):
    type: typing.Literal["http_sig"]


class OidcConfig(_Base):
    type: typing.Literal["oidc"]
    issuer: str
    client_id: str
    client_secret: str | None = None
    callback_url: str


class OAuth2Config(_Base):
    type: typing.Literal["oauth2-github"]
    client_id: str
    authorization_endpoint: str
    callback_url: str


AuthConfig = typing.Annotated[
    OidcConfig | OAuth2Config | HttpSigConfig,
    pydantic.Field(discriminator="type"),
]


class AuthPublic(_Base):
    name: str
    description: str
    config: AuthConfig


class AuthPublicSummary(_Base):
    name: str
    type: str


class Auth(_Base):
    id: int
    name: str
    description: str
    tags: list[TagNameValue] = []
    created_at: int
    is_enabled: bool
    config: AuthConfig


class AuthListResponse(_Base):
    auths: list[Auth] = []


class Bastion(_Base):
    id: int
    url: str
    ssh_proxy_jump: str | None = None
    tag_list: list[TagNameValue] = []


class BastionListResponse(_Base):
    bastions: list[Bastion] = []


class IdentitySelfBastionListResponse(_Base):
    bastions: list[Bastion] = []


# --- Grant types ---


class TripletFilter(_Base):
    name: str | None = None
    tag_list: list[TagNameValue] | None = None
    boundary_list: list[str] | None = None

    def to_text(self) -> str:
        output: list[str] = []
        if self.name:
            output.append(f"name:{self.name}")
        output += _filter_list(self.tag_list, "tag_list", _name_value)
        output += _filter_list(self.boundary_list, "boundary_list", lambda i: str(i))
        return "*" if len(output) == 0 else " ".join(output)


class BoundaryFilter(_Base):
    name: str | None

    def to_text(self) -> str:
        return f"name:{self.name}" if self.name else "*"


class TagFilter(_Base):
    name_value: TagNameValue | None

    def to_text(self) -> str:
        if self.name_value is None:
            return "*"
        return f"name_value:{_name_value(self.name_value)}"


class RoleFilter(_Base):
    name: str | None

    def to_text(self) -> str:
        return f"name:{self.name}" if self.name is not None else "*"


class TenantFilter(_Base):
    id: int | None

    def to_text(self) -> str:
        return f"id:{self.id}" if self.id is not None else "*"


class AuthFilter(_Base):
    name: str | None

    def to_text(self) -> str:
        return f"name:{self.name}" if self.name is not None else "*"


class TagPermission(_Base):
    create: bool
    read: bool
    delete: bool

    def to_text(self) -> str:
        output = _bool(self.create, "create") + _bool(self.read, "read") + _bool(self.delete, "delete")
        return " ".join(output)


class BoundaryUpdatePermission(_Base):
    name: bool
    description: bool
    ceiling_list: bool
    denied_list: bool

    def to_text(self) -> str:
        output = (
            _bool(self.name, "name")
            + _bool(self.description, "description")
            + _bool(self.ceiling_list, "ceiling_list")
            + _bool(self.denied_list, "denied_list")
        )
        return " ".join(output)


class BoundaryPermission(_Base):
    create: bool
    read: bool
    delete: bool
    update: BoundaryUpdatePermission | None

    def to_text(self) -> str:
        output = (
            _bool(self.create, "create")
            + _bool(self.read, "read")
            + _update(self.update)
            + _bool(self.delete, "delete")
        )
        return " ".join(output)


class RoleUpdatePermission(_Base):
    name: bool
    description: bool
    grant_list: bool
    member_list: bool

    def to_text(self) -> str:
        output = (
            _bool(self.name, "name")
            + _bool(self.description, "description")
            + _bool(self.grant_list, "grant_list")
            + _bool(self.member_list, "member_list")
        )
        return " ".join(output)


class RolePermission(_Base):
    create: bool
    read: bool
    delete: bool
    update: RoleUpdatePermission | None

    def to_text(self) -> str:
        output = (
            _bool(self.create, "create")
            + _bool(self.read, "read")
            + _update(self.update)
            + _bool(self.delete, "delete")
        )
        return " ".join(output)


class IdentityCreatePermission(_Base):
    allowed: bool
    allowed_tag_list: list[TagNameValue] | None
    required_boundary_list: list[str] | None

    def to_text(self) -> str:
        output: list[str] = _permission_list(self.allowed_tag_list, "allowed_tag_list", _name_value) + _permission_list(
            self.required_boundary_list, "required_boundary_list", lambda i: str(i)
        )
        return " ".join(output)


class IdentityUpdatePermission(_Base):
    name: bool

    def to_text(self) -> str:
        return "name" if self.name else ""


class IdentityPermission(_Base):
    create: IdentityCreatePermission | None
    read: bool
    update: IdentityUpdatePermission | None
    delete: bool
    add_tag_list: list[TagNameValue] | None
    del_tag_list: list[TagNameValue] | None
    invite_list: list[str] | None

    def to_text(self) -> str:
        output: list[str] = _bool(self.create is not None, "create")
        output += _bool(self.read, "read")
        output += _update(self.update)
        output += _bool(self.delete, "delete")
        output += _permission_list(self.add_tag_list, "add_tag_list", _name_value)
        output += _permission_list(self.del_tag_list, "del_tag_list", _name_value)
        output += _permission_list(self.invite_list, "invite_list", lambda i: str(i))
        return " ".join(output)


class SSHShellPermission(_Base):
    username_list: list[str]
    permit_agent_forwarding: bool = False
    permit_x11_forwarding: bool = False

    def to_text(self) -> str:
        output = (
            _permission_list(self.username_list, "username_list", lambda i: str(i))
            + _bool(self.permit_agent_forwarding, "permit_agent_forwarding")
            + _bool(self.permit_x11_forwarding, "permit_x11_forwarding")
        )
        return " ".join(output)


class SSHPortForwardingPermission(_Base):
    username_list: list[str]

    def to_text(self) -> str:
        output = _permission_list(self.username_list, "username_list", lambda i: str(i))
        return " ".join(output)


class SSHCommandPermission(_Base):
    username_list: list[str]
    command_list: list[str]

    def to_text(self) -> str:
        output = _permission_list(self.username_list, "username_list", lambda i: str(i))
        output += _permission_list(self.command_list, "command_list", lambda i: str(i))
        return " ".join(output)


class TenantUpdatePermission(_Base):
    display_name: bool
    is_enabled: bool

    def to_text(self) -> str:
        output = _bool(self.display_name, "display_name") + _bool(self.is_enabled, "is_enabled")
        return " ".join(output)


class TenantPermission(_Base):
    create: bool
    read: bool
    delete: bool
    update: TenantUpdatePermission | None

    def to_text(self) -> str:
        output = (
            _bool(self.create, "create")
            + _bool(self.read, "read")
            + _update(self.update)
            + _bool(self.delete, "delete")
        )
        return " ".join(output)


class AuthUpdatePermission(_Base):
    name: bool
    description: bool
    is_enabled: bool
    config: bool

    def to_text(self) -> str:
        output = (
            _bool(self.name, "name")
            + _bool(self.description, "description")
            + _bool(self.is_enabled, "is_enabled")
            + _bool(self.config, "config")
        )
        return " ".join(output)


class AuthPermission(_Base):
    create: bool
    read: bool
    delete: bool
    update: AuthUpdatePermission | None

    def to_text(self) -> str:
        output = (
            _bool(self.create, "create")
            + _bool(self.read, "read")
            + _update(self.update)
            + _bool(self.delete, "delete")
        )
        return " ".join(output)


class TagGrant(_Base):
    type: typing.Literal["tag"] = "tag"
    filter: TagFilter
    permission: TagPermission

    def to_text(self) -> GrantText:
        return GrantText("tag", self.filter.to_text(), self.permission.to_text())


class BoundaryGrant(_Base):
    type: typing.Literal["boundary"] = "boundary"
    filter: BoundaryFilter
    permission: BoundaryPermission

    def to_text(self) -> GrantText:
        return GrantText("boundary", self.filter.to_text(), self.permission.to_text())


class RoleGrant(_Base):
    type: typing.Literal["role"] = "role"
    filter: RoleFilter
    permission: RolePermission

    def to_text(self) -> GrantText:
        return GrantText("role", self.filter.to_text(), self.permission.to_text())


class IdentityGrant(_Base):
    type: typing.Literal["identity"] = "identity"
    filter: TripletFilter
    permission: IdentityPermission

    def to_text(self) -> GrantText:
        return GrantText("identity", self.filter.to_text(), self.permission.to_text())


class SSHShellGrant(_Base):
    type: typing.Literal["ssh-shell"] = "ssh-shell"
    filter: TripletFilter
    permission: SSHShellPermission

    def to_text(self) -> GrantText:
        return GrantText("ssh-shell", self.filter.to_text(), self.permission.to_text())


class SSHPortForwardingGrant(_Base):
    type: typing.Literal["ssh-port-forwarding"] = "ssh-port-forwarding"
    filter: TripletFilter
    permission: SSHPortForwardingPermission

    def to_text(self) -> GrantText:
        return GrantText("ssh-port-forwarding", self.filter.to_text(), self.permission.to_text())


class SSHCommandGrant(_Base):
    type: typing.Literal["ssh-command"] = "ssh-command"
    filter: TripletFilter
    permission: SSHCommandPermission

    def to_text(self) -> GrantText:
        return GrantText("ssh-command", self.filter.to_text(), self.permission.to_text())


class TenantGrant(_Base):
    type: typing.Literal["tenant"] = "tenant"
    filter: TenantFilter
    permission: TenantPermission

    def to_text(self) -> GrantText:
        return GrantText("tenant", self.filter.to_text(), self.permission.to_text())


class AuthGrant(_Base):
    type: typing.Literal["auth"] = "auth"
    filter: AuthFilter
    permission: AuthPermission

    def to_text(self) -> GrantText:
        return GrantText("auth", self.filter.to_text(), self.permission.to_text())


class InvalidGrant(_Base):
    type: typing.Literal["invalid"] = "invalid"

    def to_text(self) -> GrantText:
        return GrantText("invalid", "!", "!")


Grant = typing.Annotated[
    TagGrant
    | BoundaryGrant
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

_grant_adapter: pydantic.TypeAdapter[Grant] = pydantic.TypeAdapter(Grant)


def validate_grant(data: typing.Any) -> Grant:
    try:
        return _grant_adapter.validate_python(data)
    except pydantic.ValidationError as e:
        error = e.errors()[0]
        msg = error["msg"]
        loc = ".".join(map(str, error["loc"]))
        raise exceptions.UI(f"Request invalid. {msg}: {loc}")


class RoleMember(_Base):
    id: int
    name: str


class RoleMemberUpdateRequest(_Base):
    name: str


class Role(_Base):
    id: int
    name: str
    description: str
    grant_list: list[Grant] = []
    member_list: list[RoleMember] = []


class RolesResponse(_Base):
    roles: list[Role] = []


class Boundary(_Base):
    id: int
    name: str
    description: str
    ceiling_list: list[Grant] | None = None
    denied_list: list[Grant] = []


class BoundariesResponse(_Base):
    boundaries: list[Boundary] = []


class IdentityTagOp(_Base):
    type: str
    tag_id_list: list[int] | None = None
    tag_name_value_list: list[TagNameValue] | None = None


class IdentityBoundary(_Base):
    name: str


class Identity(_Base):
    id: int
    name: str
    tags: list[TagNameValue] = []
    boundaries: list[IdentityBoundary] = []


class IdentitiesResponse(_Base):
    identities: list[Identity] = []


class AuditLogEntry(_Base):
    id: int
    at: int
    level: int
    type: str
    by_identity_id: str | None = None
    details: dict[str, typing.Any] = {}


class AuditLogListResponse(_Base):
    entries: list[AuditLogEntry] = []
