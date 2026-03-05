from __future__ import annotations
from enum import Enum
from typing import List, Optional, Union, Annotated, Literal, Any
from pydantic import BaseModel, Field, ConfigDict

# --- Base Configuration ---
class APIBase(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra='forbid')

# --- Shared & JWK Schemas ---

class ProblemDocument(APIBase):
    type: str = "about:blank"
    detail: Optional[str] = None
    title: Optional[str] = None
    status: Optional[int] = None

class RSAPublicJWK(APIBase):
    kty: Literal["RSA"]
    e: str
    n: str

class ECDSAPublicJWK(APIBase):
    crv: Literal["P-256"]
    kty: Literal["EC"]
    x: str
    y: str

class ED25519PublicJWK(APIBase):
    crv: Literal["Ed25519"]
    kty: Literal["OKP"]
    x: str

PublicJWK = Annotated[
    Union[RSAPublicJWK, ECDSAPublicJWK, ED25519PublicJWK],
    Field(discriminator="kty")
]

class SymmetricJWK(APIBase):
    kty: Literal["oct"]
    k: str  # base64url encoded

# --- Grant System (Discriminators) ---

class TripletFilter(APIBase):
    name: Optional[str] = None
    tag_list: Optional[List[str]] = None
    boundary_list: Optional[List[str]] = None

class CRDPermission(APIBase):
    create: bool
    read: bool
    delete: bool

class BoundaryFilter(APIBase):
    name: Optional[str]

class BoundaryUpdatePermission(APIBase):
    name: bool
    description: bool
    ceiling_list: bool
    denied_list: bool

class BoundaryPermission(CRDPermission):
    update: Optional[BoundaryUpdatePermission]

class BoundaryGrant(APIBase):
    type: Literal["boundary"]
    filter: BoundaryFilter
    permission: BoundaryPermission

class TagFilter(APIBase):
    name_value: Optional[str]

class TagGrant(APIBase):
    type: Literal["tag"]
    filter: TagFilter
    permission: CRDPermission

class RoleUpdatePermission(APIBase):
    name: bool
    description: bool
    grant_list: bool
    member_list: bool

class RolePermission(CRDPermission):
    update: RoleUpdatePermission

class RoleFilter(APIBase):
    name: Optional[str]

class RoleGrant(APIBase):
    type: Literal["role"]
    filter: RoleFilter
    permission: RolePermission

class IdentityCreatePermission(APIBase):
    allowed: bool
    allowed_tag_list: Optional[list[str]]
    required_boundary_list: Optional[list[str]]

class IdentityUpdatePermission(APIBase):
    name: bool

class IdentityPermission(APIBase):
    create: Optional[IdentityCreatePermission]
    read: bool
    update: Optional[IdentityUpdatePermission]
    delete: bool
    add_tag_list: Optional[list[str]]
    del_tag_list: Optional[list[str]]
    invite_list: Optional[list[str]]

class IdentityGrant(APIBase):
    type: Literal["identity"]
    filter: TripletFilter
    permission: IdentityPermission

class SSHPermission(APIBase):
    force_command_list: Optional[list[str]]
    username_list: Optional[list[str]]
    permit_pty: bool
    permit_user_rc: bool
    permit_x11_forwarding: bool
    permit_agent_forwarding: bool
    permit_port_forwarding: bool

class SSHGrant(APIBase):
    type: Literal["ssh"]
    filter: TripletFilter
    permission: SSHPermission

class InvalidGrant(APIBase):
    type: Literal["invalid"]

Grant = Annotated[
    Union[BoundaryGrant, TagGrant, RoleGrant, IdentityGrant, SSHGrant, InvalidGrant],
    Field(discriminator="type")
]

# --- Entity Schemas (Read Models) ---

class Directory(APIBase):
    initialize: str
    accept_invitation: str
    login: str
    boundary: str
    tag: str
    role: str
    identity: str
    ssh: str

class TagRead(APIBase):
    id: int
    name: str
    value: str

class BoundaryRead(APIBase):
    id: int
    name: str
    description: str
    ceiling_list: Optional[List[Grant]] = None
    denied_list: List[Grant]

class RoleMember(APIBase):
    id: int
    name: str

class RoleRead(APIBase):
    id: int
    name: str
    description: str
    grant_list: List[Grant]
    member_list: List[RoleMember]

class IdentityTagRead(APIBase):
    id: int
    name: str
    value: str

class IdentityBoundaryRead(APIBase):
    id: int
    name: str

class IdentityRead(APIBase):
    id: int
    name: str
    tags: List[IdentityTagRead]
    boundaries: List[IdentityBoundaryRead]

class InvitationRead(APIBase):
    key: SymmetricJWK

# --- Request Schemas (Write Models) ---

class AcceptInvitationRequest(BaseModel):
    account_public_key: PublicJWK
    nonce: str

class LoginRequest(BaseModel):
    session_public_key: PublicJWK
    nonce: str

class CreateBoundaryRequest(BaseModel):
    name: str
    description: Optional[str] = None

class UpdateBoundaryRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    denied_list: Optional[List[Grant]] = None
    ceiling_list: Optional[List[Grant]] = None

class CreateTagRequest(BaseModel):
    name: str
    value: str

class CreateRoleRequest(BaseModel):
    name: str
    description: Optional[str] = None

class UpdateRoleRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    grant_list: Optional[List[Grant]] = None
    member_list: Optional[List[RoleMember]] = None

class IdentityTagId(BaseModel):
    id: int

class IdentityTagNameValue(BaseModel):
    name: str
    value: str

IdentityTagInput = Union[IdentityTagId, IdentityTagNameValue]

class CreateIdentityRequest(BaseModel):
    name: str
    boundaries: List[IdentityBoundaryRead] # Using this as it matches {id, name}
    tags: Optional[List[IdentityTagInput]] = None

class UpdateIdentityTagOperation(BaseModel):
    type: Literal["set", "add", "del"]
    values: List[IdentityTagInput]

class UpdateIdentityRequest(BaseModel):
    name: Optional[str] = None
    tags: Optional[List[UpdateIdentityTagOperation]] = None

class SshUserCertificateRequest(BaseModel):
    hostname: str
    username: str
    public_key: PublicJWK

class SshHostCertificateRequest(BaseModel):
    public_keys: List[PublicJWK]
