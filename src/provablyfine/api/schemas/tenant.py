from __future__ import annotations

import typing

import pydantic

from . import base

TenantName = typing.Annotated[str, pydantic.Field(pattern=r"^[a-zA-Z0-9_-]+$")]

UnixMode = typing.Literal["manual", "standalone", "scim"]


class TenantCreateRequest(base.APIBase):
    name: TenantName
    display_name: str
    unix_mode: UnixMode = "manual"
    min_unix_uid: int = 100000
    min_unix_gid: int = 100000


class TenantUpdateRequest(base.APIBase):
    display_name: str | None = None
    is_enabled: bool | None = None
    unix_mode: UnixMode | None = None
    min_unix_uid: int | None = None
    min_unix_gid: int | None = None


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
    min_unix_uid: int
    min_unix_gid: int


class TenantListResponse(base.APIBase):
    tenants: list[TenantReadResponse]


class TenantUnixConfigResponse(base.APIBase):
    unix_mode: UnixMode
    min_unix_uid: int
    min_unix_gid: int
