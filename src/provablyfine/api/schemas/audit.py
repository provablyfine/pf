from __future__ import annotations

import typing

import pydantic

from . import base


class AuditLogRef(base.APIBase):
    """An object that the entry is about, with the name it had when the entry was written."""

    type: str
    id: str
    name: str | None = None


class AuditLogEntry(base.APIBase):
    id: int
    at: int
    level: int
    type: str
    object_type: str
    action: str
    by_identity_id: str | None
    by_identity_name: str | None = None
    refs: list[AuditLogRef] = pydantic.Field(default_factory=list[AuditLogRef])
    details: dict[str, typing.Any]


class AuditLogListResponse(base.APIBase):
    entries: list[AuditLogEntry] = pydantic.Field(default_factory=list[AuditLogEntry])
    # Pass it back as `cursor` to read the next page. None on the last page.
    next_cursor: str | None = None
