from __future__ import annotations

import pydantic

from . import base, grant


class Boundary(base.APIBase):
    id: int
    name: str
    description: str
    ceiling_list: list[grant.Grant] | None = None
    denied_list: list[grant.Grant]


class BoundaryListResponse(base.APIBase):
    boundaries: list[Boundary]


class BoundaryCreateRequest(base.APIBase):
    name: str
    description: str = ""


class BoundaryCreateResponse(base.APIBase):
    boundary: Boundary


class BoundaryUpdateRequest(base.APIBase):
    name: str | None = None
    description: str | None = None
    ceiling_list: list[grant.Grant] | None = None
    denied_list: list[grant.Grant] | None = None

    @pydantic.model_validator(mode="after")
    def reject_explicit_nulls(self):
        for field in ["name", "description", "denied_list"]:
            if field in self.model_fields_set and getattr(self, field) is None:
                raise ValueError(f"{field} cannot be explicitly null")
        return self


class BoundaryUpdateResponse(base.APIBase):
    boundary: Boundary
