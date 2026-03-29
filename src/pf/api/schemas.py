from __future__ import annotations

import typing

import pydantic


# --- Base Configuration ---
class APIBase(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(from_attributes=True, extra="forbid")


# --- Shared & JWK Schemas ---


class ProblemDocument(APIBase):
    type: str = "about:blank"
    detail: str | None = None
    title: str | None = None
    status: int | None = None


class RSAPublicJWK(APIBase):
    kty: typing.Literal["RSA"]
    e: str
    n: str


class ECDSAPublicJWK(APIBase):
    crv: typing.Literal["P-256"]
    kty: typing.Literal["EC"]
    x: str
    y: str


class ED25519PublicJWK(APIBase):
    crv: typing.Literal["Ed25519"]
    kty: typing.Literal["OKP"]
    x: str


PublicJWK = typing.Annotated[RSAPublicJWK | ECDSAPublicJWK | ED25519PublicJWK, pydantic.Field(discriminator="kty")]


class SymmetricJWK(APIBase):
    kty: typing.Literal["oct"]
    k: str  # base64url encoded


# --- Grant ---


class TripletFilter(APIBase):
    name: str | None = None
    tag_list: list[TagNameValue] | None = None
    boundary_list: list[str] | None = None


class CRDPermission(APIBase):
    create: bool
    read: bool
    delete: bool


class BoundaryFilter(APIBase):
    name: str | None


class BoundaryUpdatePermission(APIBase):
    name: bool
    description: bool
    ceiling_list: bool
    denied_list: bool


class BoundaryPermission(CRDPermission):
    update: BoundaryUpdatePermission | None


class BoundaryGrant(APIBase):
    type: typing.Literal["boundary"] = "boundary"
    filter: BoundaryFilter
    permission: BoundaryPermission


class TagNameValue(APIBase):
    model_config = pydantic.ConfigDict(frozen=True)
    name: str
    value: str


class TagFilter(APIBase):
    name_value: TagNameValue | None


class TagPermission(CRDPermission):
    pass


class TagGrant(APIBase):
    type: typing.Literal["tag"] = "tag"
    filter: TagFilter
    permission: TagPermission


class RoleUpdatePermission(APIBase):
    name: bool
    description: bool
    grant_list: bool
    member_list: bool


class RolePermission(CRDPermission):
    update: RoleUpdatePermission | None


class RoleFilter(APIBase):
    name: str | None


class RoleGrant(APIBase):
    type: typing.Literal["role"] = "role"
    filter: RoleFilter
    permission: RolePermission


class IdentityCreatePermission(APIBase):
    allowed: bool
    allowed_tag_list: list[TagNameValue] | None
    required_boundary_list: list[str] | None


class IdentityUpdatePermission(APIBase):
    name: bool


class IdentityPermission(APIBase):
    create: IdentityCreatePermission | None
    read: bool
    update: IdentityUpdatePermission | None
    delete: bool
    add_tag_list: list[TagNameValue] | None
    del_tag_list: list[TagNameValue] | None
    invite_list: list[str] | None


class IdentityFilter(TripletFilter):
    pass


class IdentityGrant(APIBase):
    type: typing.Literal["identity"] = "identity"
    filter: IdentityFilter
    permission: IdentityPermission


class SSHPermission(APIBase):
    force_command_list: list[str] | None
    username_list: list[str] | None
    permit_pty: bool
    permit_user_rc: bool
    permit_x11_forwarding: bool
    permit_agent_forwarding: bool
    permit_port_forwarding: bool


class SSHFilter(TripletFilter):
    pass


class SSHGrant(APIBase):
    type: typing.Literal["ssh"] = "ssh"
    filter: SSHFilter
    permission: SSHPermission


class TenantUpdatePermission(APIBase):
    display_name: bool
    is_enabled: bool


class TenantPermission(APIBase):
    create: bool
    read: bool
    delete: bool
    update: TenantUpdatePermission | None


class TenantFilter(APIBase):
    id: int | None


class TenantGrant(APIBase):
    type: typing.Literal["tenant"] = "tenant"
    filter: TenantFilter
    permission: TenantPermission


class AuthFilter(APIBase):
    name: str | None  # human name of auth config, None = any


class AuthUpdatePermission(APIBase):
    name: bool
    description: bool
    is_enabled: bool
    config: bool


class AuthPermission(CRDPermission):
    update: AuthUpdatePermission | None


class AuthGrant(APIBase):
    type: typing.Literal["auth"] = "auth"
    filter: AuthFilter
    permission: AuthPermission


class InvalidGrant(APIBase):
    type: typing.Literal["invalid"] = "invalid"


Grant = typing.Annotated[
    BoundaryGrant | TagGrant | RoleGrant | IdentityGrant | SSHGrant | TenantGrant | AuthGrant | InvalidGrant,
    pydantic.Field(discriminator="type"),
]

# --- Tag ---


class Tag(APIBase):
    id: int
    name: str
    value: str


class TagListResponse(APIBase):
    tags: list[Tag]


class TagCreateRequest(APIBase):
    name: str
    value: str


class TagCreateResponse(APIBase):
    pass


# --- Boundary ---


class Boundary(APIBase):
    id: int
    name: str
    description: str
    ceiling_list: list[Grant] | None = None
    denied_list: list[Grant]


class BoundaryListResponse(APIBase):
    boundaries: list[Boundary]


class BoundaryCreateRequest(APIBase):
    name: str
    description: str = ""


class BoundaryCreateResponse(APIBase):
    boundary: Boundary


class BoundaryUpdateRequest(APIBase):
    name: str | None = None
    description: str | None = None
    ceiling_list: list[Grant] | None = None
    denied_list: list[Grant] | None = None

    @pydantic.model_validator(mode="after")
    def reject_explicit_nulls(self):
        for field in ["name", "description", "denied_list"]:
            if field in self.model_fields_set and getattr(self, field) is None:
                raise ValueError(f"{field} cannot be explicitly null")
        return self


class BoundaryUpdateResponse(APIBase):
    boundary: Boundary


# --- Role ---


class RoleMember(APIBase):
    id: int
    name: str


class Role(APIBase):
    id: int
    name: str
    description: str
    grant_list: list[Grant]
    member_list: list[RoleMember]


class RoleListResponse(APIBase):
    roles: list[Role]


class RoleCreateRequest(APIBase):
    name: str
    description: str = ""


class RoleMemberUpdateRequest(APIBase):
    name: str


class RoleUpdateRequest(APIBase):
    name: str | None = None
    description: str | None = None
    grant_list: list[Grant] | None = None
    member_list: list[RoleMemberUpdateRequest] | None = None

    @pydantic.model_validator(mode="after")
    def reject_explicit_nulls(self):
        for field in self.model_fields_set:
            if getattr(self, field) is None:
                raise ValueError(f"{field} cannot be explicitly null")
        return self


# --- Identity ---


class IdentityBoundary(APIBase):
    id: int
    name: str


class IdentityTagNameValue(APIBase):
    name: str
    value: str


class Identity(APIBase):
    id: int
    name: str
    tags: list[Tag]
    boundaries: list[IdentityBoundary]


class IdentityListResponse(APIBase):
    identities: list[Identity]


class IdentityCreateRequest(APIBase):
    name: str
    tag_id_list: list[int] = []
    tag_name_value_list: list[IdentityTagNameValue] = []
    boundary_id_list: list[int] = []
    boundary_name_list: list[str] = []

    @pydantic.model_validator(mode="after")
    def validate_tags_and_boundaries(self):
        if len(self.tag_name_value_list) > 0 and len(self.tag_id_list) > 0:
            raise ValueError("Cannot specify both 'tag_id_list' and 'tag_name_value_list'")
        if len(self.boundary_name_list) > 0 and len(self.boundary_id_list) > 0:
            raise ValueError("Cannot specify both 'boundary_id_list' and 'boundary_name_value_list'")
        return self


class IdentityCreateResponse(Identity):
    pass


class IdentityTagListOperation(APIBase):
    tag_id_list: list[int] = []
    tag_name_value_list: list[IdentityTagNameValue] = []

    @pydantic.model_validator(mode="after")
    def validate_tags_and_boundaries(self):
        if len(self.tag_name_value_list) > 0 and len(self.tag_id_list) > 0:
            raise ValueError("Cannot specify both 'tag_id_list' and 'tag_name_value_list'")
        return self


class IdentityTagAddOperation(IdentityTagListOperation):
    type: typing.Literal["add"] = "add"


class IdentityTagDelOperation(IdentityTagListOperation):
    type: typing.Literal["del"] = "del"


class IdentityTagSetOperation(IdentityTagListOperation):
    type: typing.Literal["set"] = "set"


IdentityTagOperation = typing.Annotated[
    IdentityTagAddOperation | IdentityTagDelOperation | IdentityTagSetOperation, pydantic.Field(discriminator="type")
]


class IdentityUpdateRequest(APIBase):
    name: str | None = None
    tags: list[IdentityTagOperation] | None = None

    @pydantic.model_validator(mode="after")
    def validate_tags_and_boundaries(self):
        for field in self.model_fields_set:
            if getattr(self, field) is None:
                raise ValueError(f"{field} cannot be explicitly null")
        return self


class IdentityInviteRequest(APIBase):
    delivery: typing.Literal["manual", "email"]


class IdentityInviteManualResponse(APIBase):
    key: SymmetricJWK


# --- SSH ---


class SSHHostCertificateRequest(APIBase):
    public_keys: list[PublicJWK]


class SSHCertificateResponse(APIBase):
    certificates: list[str]


class SSHHostCertificateResponse(SSHCertificateResponse):
    pass


class SSHUserCertificateRequest(APIBase):
    hostname: str
    username: str
    public_key: PublicJWK


class SSHUserCertificateResponse(SSHCertificateResponse):
    pass


# --- Initialization/login ---


class HttpSigParams(APIBase):
    pass  # no extra params


class OidcParams(APIBase):
    issuer: str
    client_id: str
    client_secret: str | None = None
    callback_url: str = "http://127.0.0.1/callback"


class OAuth2Params(APIBase):
    """OAuth2 params as returned in API responses — client_secret intentionally omitted."""

    client_id: str
    authorization_endpoint: str
    callback_url: str


class OAuth2CreateParams(APIBase):
    """OAuth2 params for create requests — includes client_secret."""

    client_id: str
    client_secret: str


class Auth(APIBase):
    id: int
    name: str
    description: str
    tag_id_list: list[int]
    created_at: int
    is_enabled: bool
    type: typing.Literal["http_sig", "oidc", "oauth2-github"]
    params: OidcParams | OAuth2Params | HttpSigParams


class AuthListResponse(APIBase):
    auths: list[Auth]


class AuthCreateRequest(APIBase):
    name: str
    description: str = ""
    tag_id_list: list[int] = []
    type: typing.Literal["http_sig", "oidc", "oauth2-github"]
    oidc_params: OidcParams | None = None
    oauth2_params: OAuth2CreateParams | None = None

    @pydantic.model_validator(mode="after")
    def validate_params(self):
        if self.type == "oidc" and self.oidc_params is None:
            raise ValueError("oidc_params is required when type is 'oidc'")
        if self.type == "oauth2-github" and self.oauth2_params is None:
            raise ValueError("oauth2_params is required when type is 'oauth2-github'")
        return self


class AuthUpdateRequest(APIBase):
    name: str | None = None
    description: str | None = None
    tag_id_list: list[int] | None = None
    is_enabled: bool | None = None
    oidc_params: OidcParams | None = None


class AuthPublic(APIBase):
    name: str
    type: typing.Literal["http_sig", "oidc", "oauth2-github"]
    description: str
    params: OidcParams | OAuth2Params | HttpSigParams


class OidcLoginRequest(APIBase):
    auth_name: str
    id_token: str
    session_public_key: PublicJWK


class OAuth2StartRequest(APIBase):
    auth_name: str
    session_public_key: PublicJWK
    client_redirect_uri: str


class OAuth2StartResponse(APIBase):
    auth_url: str


class DirectoryReadResponse(APIBase):
    initialize: str
    accept_invitation: str
    login: str
    login_oidc: str
    login_oauth2_start: str
    auth: str
    boundary: str
    tag: str
    role: str
    identity: str
    ssh: str
    tenant: str


class TenantCreateRequest(APIBase):
    name: str
    display_name: str


class TenantUpdateRequest(APIBase):
    display_name: str | None = None
    is_enabled: bool | None = None


class TenantReadResponse(APIBase):
    id: int
    name: str
    display_name: str
    owner_id: int | None
    is_enabled: bool
    is_initialized: bool
    is_deleted: bool
    created_at: int


class TenantListResponse(APIBase):
    tenants: list[TenantReadResponse]


class InitializeResponse(APIBase):
    key: SymmetricJWK


class AcceptInvitationRequest(APIBase):
    account_public_key: PublicJWK


class LoginRequest(APIBase):
    session_public_key: PublicJWK
