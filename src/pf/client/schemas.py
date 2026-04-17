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
