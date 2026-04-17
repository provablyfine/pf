import typing

import pydantic


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


class Grant(_Base):
    type: str
    filter: dict[str, typing.Any] = {}
    permission: dict[str, typing.Any] = {}


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
