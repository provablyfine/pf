from __future__ import annotations

import typing

import pydantic

from .. import model
from . import base


class AuditLogRef(base.APIBase):
    """An object that the entry is about, with the name it had when the entry was written."""

    type: model.audit_types.ObjectType
    id: str
    name: str | None = None


class AuditLogEntry(base.APIBase):
    id: int
    at: int
    level: int
    type: str
    object_type: model.audit_types.ObjectType
    action: model.audit_types.Action
    by_identity_id: str | None
    by_identity_name: str | None = None
    refs: list[AuditLogRef] = pydantic.Field(default_factory=list[AuditLogRef])
    details: dict[str, typing.Any]


class AuditLogListResponse(base.APIBase):
    entries: list[AuditLogEntry] = pydantic.Field(default_factory=list[AuditLogEntry])
    # Pass it back as `cursor` to read the next page. None on the last page.
    next_cursor: str | None = None


class AuditLogObjectTypeInfo(base.APIBase):
    object_type: model.audit_types.ObjectType
    actions: list[model.audit_types.Action]


class AuditLogTypesResponse(base.APIBase):
    """The kinds of entries that the server writes. It is the same for every tenant."""

    object_types: list[AuditLogObjectTypeInfo] = pydantic.Field(default_factory=list[AuditLogObjectTypeInfo])
