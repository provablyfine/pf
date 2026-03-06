from __future__ import annotations
import typing
import logging

import pydantic

logger = logging.getLogger(__name__)

class DBBase(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra='forbid')

class TripletFilter(DBBase):
    id: int|None = None
    tag_id_list: list[int]|None = None
    boundary_id_list: list[int]|None = None

class CRDPermission(DBBase):
    create: bool
    read: bool
    delete: bool

class BoundaryFilter(DBBase):
    id: int|None

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

class TagFilter(DBBase):
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
    update: RoleUpdatePermission|None

class RoleFilter(DBBase):
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

class IdentityPermission(DBBase):
    create: IdentityCreatePermission | None
    read: bool
    update: IdentityUpdatePermission | None
    delete: bool
    add_tag_id_list: list[int] | None
    del_tag_id_list: list[int] | None
    invite_list: list[str] | None

class IdentityFilter(TripletFilter):
    pass

class IdentityGrant(DBBase):
    type: typing.Literal["identity"] = "identity"
    filter: IdentityFilter
    permission: IdentityPermission

class SSHPermission(DBBase):
    force_command_list: list[str] | None
    username_list: list[str] | None
    permit_pty: bool
    permit_user_rc: bool
    permit_x11_forwarding: bool
    permit_agent_forwarding: bool
    permit_port_forwarding: bool

class SSHFilter(TripletFilter):
    pass

class SSHGrant(DBBase):
    type: typing.Literal["ssh"] = "ssh"
    filter: SSHFilter
    permission: SSHPermission

class InvalidGrant(DBBase):
    type: typing.Literal["invalid"] = "invalid"

Grant = typing.Annotated[
    BoundaryGrant | TagGrant | RoleGrant | IdentityGrant | SSHGrant | InvalidGrant,
    pydantic.Field(discriminator="type")
]

def deserialize(data: dict) -> Grant:
    return pydantic.TypeAdapter(Grant).validate_python(data)

def serialize(grant: Grant) -> dict:
    return grant.model_dump()
