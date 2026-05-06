from __future__ import annotations

from . import base


class TenantCreateRequest(base.APIBase):
    name: str
    display_name: str


class TenantUpdateRequest(base.APIBase):
    display_name: str | None = None
    is_enabled: bool | None = None


class TenantReadResponse(base.APIBase):
    id: int
    name: str
    display_name: str
    owner_id: int | None
    is_enabled: bool
    is_initialized: bool
    is_deleted: bool
    created_at: int


class TenantListResponse(base.APIBase):
    tenants: list[TenantReadResponse]
