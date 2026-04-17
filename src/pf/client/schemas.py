import typing

import pydantic

from . import exceptions


class _Base(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="ignore")


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
    connect_url: str | None = None
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
    register_url: str
    connect_url: str | None = None
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


class BoundaryFilter(_Base):
    name: str | None


class TagFilter(_Base):
    name_value: TagNameValue | None


class RoleFilter(_Base):
    name: str | None


class TenantFilter(_Base):
    id: int | None


class AuthFilter(_Base):
    name: str | None


class TagPermission(_Base):
    create: bool
    read: bool
    delete: bool


class BoundaryUpdatePermission(_Base):
    name: bool
    description: bool
    ceiling_list: bool
    denied_list: bool


class BoundaryPermission(_Base):
    create: bool
    read: bool
    delete: bool
    update: BoundaryUpdatePermission | None


class RoleUpdatePermission(_Base):
    name: bool
    description: bool
    grant_list: bool
    member_list: bool


class RolePermission(_Base):
    create: bool
    read: bool
    delete: bool
    update: RoleUpdatePermission | None


class IdentityCreatePermission(_Base):
    allowed: bool
    allowed_tag_list: list[TagNameValue] | None
    required_boundary_list: list[str] | None


class IdentityUpdatePermission(_Base):
    name: bool


class IdentityPermission(_Base):
    create: IdentityCreatePermission | None
    read: bool
    update: IdentityUpdatePermission | None
    delete: bool
    add_tag_list: list[TagNameValue] | None
    del_tag_list: list[TagNameValue] | None
    invite_list: list[str] | None


class SSHShellPermission(_Base):
    username_list: list[str]
    permit_agent_forwarding: bool = False
    permit_x11_forwarding: bool = False


class SSHPortForwardingPermission(_Base):
    username_list: list[str]


class SSHCommandPermission(_Base):
    username_list: list[str]
    command_list: list[str]


class TenantUpdatePermission(_Base):
    display_name: bool
    is_enabled: bool


class TenantPermission(_Base):
    create: bool
    read: bool
    delete: bool
    update: TenantUpdatePermission | None


class AuthUpdatePermission(_Base):
    name: bool
    description: bool
    is_enabled: bool
    config: bool


class AuthPermission(_Base):
    create: bool
    read: bool
    delete: bool
    update: AuthUpdatePermission | None


class TagGrant(_Base):
    type: typing.Literal["tag"] = "tag"
    filter: TagFilter
    permission: TagPermission


class BoundaryGrant(_Base):
    type: typing.Literal["boundary"] = "boundary"
    filter: BoundaryFilter
    permission: BoundaryPermission


class RoleGrant(_Base):
    type: typing.Literal["role"] = "role"
    filter: RoleFilter
    permission: RolePermission


class IdentityGrant(_Base):
    type: typing.Literal["identity"] = "identity"
    filter: TripletFilter
    permission: IdentityPermission


class SSHShellGrant(_Base):
    type: typing.Literal["ssh-shell"] = "ssh-shell"
    filter: TripletFilter
    permission: SSHShellPermission


class SSHPortForwardingGrant(_Base):
    type: typing.Literal["ssh-port-forwarding"] = "ssh-port-forwarding"
    filter: TripletFilter
    permission: SSHPortForwardingPermission


class SSHCommandGrant(_Base):
    type: typing.Literal["ssh-command"] = "ssh-command"
    filter: TripletFilter
    permission: SSHCommandPermission


class TenantGrant(_Base):
    type: typing.Literal["tenant"] = "tenant"
    filter: TenantFilter
    permission: TenantPermission


class AuthGrant(_Base):
    type: typing.Literal["auth"] = "auth"
    filter: AuthFilter
    permission: AuthPermission


class InvalidGrant(_Base):
    type: typing.Literal["invalid"] = "invalid"


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
        # Format error similarly to server-side RequestValidationError handler
        error = e.errors()[0]
        msg = error["msg"]
        loc = ".".join(map(str, error["loc"]))
        raise exceptions.UI(f"Request invalid. {msg}: {loc}")


class RoleMember(_Base):
    id: int
    name: str


class RoleMemberRef(_Base):
    id: int | None = None
    name: str | None = None


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
