from __future__ import annotations

import pydantic

from . import base, grant


class RoleMember(base.APIBase):
    id: int
    name: str


class Role(base.APIBase):
    id: int
    name: str
    description: str
    grant_list: list[grant.Grant]
    member_list: list[RoleMember]


class RoleListResponse(base.APIBase):
    roles: list[Role]


class RoleCreateRequest(base.APIBase):
    name: str
    description: str = ""


class RoleMemberUpdateRequest(base.APIBase):
    name: str


class RoleUpdateRequest(base.APIBase):
    name: str | None = None
    description: str | None = None
    grant_list: list[grant.Grant] | None = None
    member_list: list[RoleMemberUpdateRequest] | None = None

    @pydantic.model_validator(mode="after")
    def reject_explicit_nulls(self):
        for field in self.model_fields_set:
            if getattr(self, field) is None:
                raise ValueError(f"{field} cannot be explicitly null")
        return self
