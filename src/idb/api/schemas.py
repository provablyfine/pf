from __future__ import annotations
import typing
import pydantic

# --- Base Configuration ---
class APIBase(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(from_attributes=True, extra='forbid')

# --- Shared & JWK Schemas ---

class ProblemDocument(APIBase):
    type: str = "about:blank"
    detail: str|None = None
    title: str|None = None
    status: int|None = None

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

PublicJWK = typing.Annotated[
    RSAPublicJWK | ECDSAPublicJWK | ED25519PublicJWK,
    pydantic.Field(discriminator="kty")
]

class SymmetricJWK(APIBase):
    kty: typing.Literal["oct"]
    k: str  # base64url encoded

# --- Grant ---

class TripletFilter(APIBase):
    name: str|None = None
    tag_list: list[str]|None = None
    boundary_list: list[str]|None = None

class CRDPermission(APIBase):
    create: bool
    read: bool
    delete: bool

class BoundaryFilter(APIBase):
    name: str|None

class BoundaryUpdatePermission(APIBase):
    name: bool
    description: bool
    ceiling_list: bool
    denied_list: bool

class BoundaryPermission(CRDPermission):
    update: BoundaryUpdatePermission|None

class BoundaryGrant(APIBase):
    type: typing.Literal["boundary"] = "boundary"
    filter: BoundaryFilter
    permission: BoundaryPermission

class TagFilter(APIBase):
    name_value: str|None

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
    update: RoleUpdatePermission|None

class RoleFilter(APIBase):
    name: str|None

class RoleGrant(APIBase):
    type: typing.Literal["role"] = "role"
    filter: RoleFilter
    permission: RolePermission

class IdentityCreatePermission(APIBase):
    allowed: bool
    allowed_tag_list: list[str]|None
    required_boundary_list: list[str]|None

class IdentityUpdatePermission(APIBase):
    name: bool

class IdentityPermission(APIBase):
    create: IdentityCreatePermission|None
    read: bool
    update: IdentityUpdatePermission|None
    delete: bool
    add_tag_list: list[str]|None
    del_tag_list: list[str]|None
    invite_list: list[str]|None

class IdentityFilter(TripletFilter):
    pass

class IdentityGrant(APIBase):
    type: typing.Literal["identity"] = "identity"
    filter: IdentityFilter
    permission: IdentityPermission

class SSHPermission(APIBase):
    force_command_list: list[str]|None
    username_list: list[str]|None
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

class InvalidGrant(APIBase):
    type: typing.Literal["invalid"] = "invalid"

Grant = typing.Annotated[
    BoundaryGrant | TagGrant | RoleGrant | IdentityGrant | SSHGrant | InvalidGrant,
    pydantic.Field(discriminator="type")
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
    description: str = ''

class BoundaryCreateResponse(APIBase):
    boundary: Boundary

class BoundaryUpdateRequest(APIBase):
    name: str | None = None
    description: str | None = None
    ceiling_list: list[Grant] | None = None
    denied_list: list[Grant] | None = None

    @pydantic.model_validator(mode='after')
    def reject_explicit_nulls(self):
        for field in ['name', 'description', 'denied_list']:
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
    description: str = ''

class RoleUpdateRequest(APIBase):
    name: str | None = None
    description: str | None = None
    grant_list: list[Grant] | None = None
    member_list: list[RoleMember] | None = None

    @pydantic.model_validator(mode='after')
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

    @pydantic.model_validator(mode='after')
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
    
    @pydantic.model_validator(mode='after')
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
    IdentityTagAddOperation | IdentityTagDelOperation | IdentityTagSetOperation,
    pydantic.Field(discriminator="type")
]

class IdentityUpdateRequest(APIBase):
    name: str | None = None
    tags: list[IdentityTagOperation] | None = None

    @pydantic.model_validator(mode='after')
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

class DirectoryReadResponse(APIBase):
    initialize: str
    accept_invitation: str
    login: str
    boundary: str
    tag: str
    role: str
    identity: str
    ssh: str


class InitializeResponse(APIBase):
    key: SymmetricJWK


class AcceptInvitationRequest(APIBase):
    account_public_key: PublicJWK


class LoginRequest(APIBase):
    session_public_key: PublicJWK
