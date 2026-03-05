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
    type: typing.Literal["boundary"]
    filter: BoundaryFilter
    permission: BoundaryPermission

class TagFilter(APIBase):
    name_value: str|None

class TagPermission(CRDPermission):
    pass

class TagGrant(APIBase):
    type: typing.Literal["tag"]
    filter: TagFilter
    permission: TagPermission

class RoleUpdatePermission(APIBase):
    name: bool
    description: bool
    grant_list: bool
    member_list: bool

class RolePermission(CRDPermission):
    update: RoleUpdatePermission

class RoleFilter(APIBase):
    name: str|None

class RoleGrant(APIBase):
    type: typing.Literal["role"]
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
    type: typing.Literal["identity"]
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
    type: typing.Literal["ssh"]
    filter: SSHFilter
    permission: SSHPermission

class InvalidGrant(APIBase):
    type: typing.Literal["invalid"]

Grant = typing.Annotated[
    BoundaryGrant | TagGrant | RoleGrant | IdentityGrant | SSHGrant | InvalidGrant,
    pydantic.Field(discriminator="type")
]

# --- Entity Schemas (Read Models) ---

#class Directory(APIBase):
#    initialize: str
#    accept_invitation: str
#    login: str
#    boundary: str
#    tag: str
#    role: str
#    identity: str
#    ssh: str
#
#class TagRead(APIBase):
#    id: int
#    name: str
#    value: str
#
#class BoundaryRead(APIBase):
#    id: int
#    name: str
#    description: str
#    ceiling_list: Optional[List[Grant]] = None
#    denied_list: List[Grant]
#
#class RoleMember(APIBase):
#    id: int
#    name: str
#
#class RoleRead(APIBase):
#    id: int
#    name: str
#    description: str
#    grant_list: List[Grant]
#    member_list: List[RoleMember]
#
#class IdentityTagRead(APIBase):
#    id: int
#    name: str
#    value: str
#
#class IdentityBoundaryRead(APIBase):
#    id: int
#    name: str
#
#class IdentityRead(APIBase):
#    id: int
#    name: str
#    tags: List[IdentityTagRead]
#    boundaries: List[IdentityBoundaryRead]
#
#class InvitationRead(APIBase):
#    key: SymmetricJWK

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
    name: str
    description: str
    ceiling_list: list[Grant] | None = None
    denied_list: list[Grant]

class BoundaryUpdateResponse(APIBase):
    boundary: Boundary


#class AcceptInvitationRequest(BaseModel):
#    account_public_key: PublicJWK
#    nonce: str
#
#class LoginRequest(BaseModel):
#    session_public_key: PublicJWK
#    nonce: str
#
#class CreateBoundaryRequest(BaseModel):
#    name: str
#    description: Optional[str] = None
#
#class UpdateBoundaryRequest(BaseModel):
#    name: Optional[str] = None
#    description: Optional[str] = None
#    denied_list: Optional[List[Grant]] = None
#    ceiling_list: Optional[List[Grant]] = None
#
#class CreateRoleRequest(BaseModel):
#    name: str
#    description: Optional[str] = None
#
#class UpdateRoleRequest(BaseModel):
#    name: Optional[str] = None
#    description: Optional[str] = None
#    grant_list: Optional[List[Grant]] = None
#    member_list: Optional[List[RoleMember]] = None
#
#class IdentityTagId(BaseModel):
#    id: int
#
#class IdentityTagNameValue(BaseModel):
#    name: str
#    value: str
#
#IdentityTagInput = Union[IdentityTagId, IdentityTagNameValue]
#
#class CreateIdentityRequest(BaseModel):
#    name: str
#    boundaries: List[IdentityBoundaryRead] # Using this as it matches {id, name}
#    tags: Optional[List[IdentityTagInput]] = None
#
#class UpdateIdentityTagOperation(BaseModel):
#    type: Literal["set", "add", "del"]
#    values: List[IdentityTagInput]
#
#class UpdateIdentityRequest(BaseModel):
#    name: Optional[str] = None
#    tags: Optional[List[UpdateIdentityTagOperation]] = None
#
#class SshUserCertificateRequest(BaseModel):
#    hostname: str
#    username: str
#    public_key: PublicJWK
#
#class SshHostCertificateRequest(BaseModel):
#    public_keys: List[PublicJWK]
