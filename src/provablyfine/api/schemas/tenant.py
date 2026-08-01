from __future__ import annotations

import typing

import pydantic

from . import base

TenantName = typing.Annotated[str, pydantic.Field(pattern=r"^[a-zA-Z0-9_-]+$")]

UnixMode = typing.Literal["manual", "scim"]


class TenantCreateRequest(base.APIBase):
    name: TenantName
    display_name: str
    unix_mode: UnixMode = "manual"


class TenantUpdateRequest(base.APIBase):
    display_name: str | None = None
    is_enabled: bool | None = None
    unix_mode: UnixMode | None = None


class TenantReadResponse(base.APIBase):
    id: int
    name: str
    display_name: str
    owner_id: int | None
    is_enabled: bool
    is_initialized: bool
    is_deleted: bool
    created_at: int
    unix_mode: UnixMode


class TenantListResponse(base.APIBase):
    tenants: list[TenantReadResponse]
