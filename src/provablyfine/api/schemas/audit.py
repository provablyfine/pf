from __future__ import annotations

import typing

import pydantic

from . import base


class AuditLogEntry(base.APIBase):
    id: int
    at: int
    level: int
    type: str
    by_identity_id: str | None
    details: dict[str, typing.Any]


class AuditLogListResponse(base.APIBase):
    entries: list[AuditLogEntry] = pydantic.Field(default_factory=list[AuditLogEntry])
