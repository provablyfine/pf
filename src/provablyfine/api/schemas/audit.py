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
    # Set when the author belongs to another tenant. Then by_identity_id is None, because it means nothing here.
    # The names are the ones the tenant and the identity had when the entry was written.
    by_tenant_id: int | None = None
    by_tenant_name: str | None = None
    refs: list[AuditLogRef] = pydantic.Field(default_factory=list[AuditLogRef])
    details: dict[str, typing.Any]


class AuditLogListResponse(base.APIBase):
    entries: list[AuditLogEntry] = pydantic.Field(default_factory=list[AuditLogEntry])
    # Pass it back as `cursor` to read what comes after these entries.
    # It is set on the last page too, so that a reader that has caught up can resume from it later.
    next_cursor: str
    # True when nothing came after these entries at the time of the query.
    is_last: bool


class AuditLogObjectTypeInfo(base.APIBase):
    object_type: model.audit_types.ObjectType
    actions: list[model.audit_types.Action]


class AuditLogTypesResponse(base.APIBase):
    """The kinds of entries that the server writes. It is the same for every tenant."""

    object_types: list[AuditLogObjectTypeInfo] = pydantic.Field(default_factory=list[AuditLogObjectTypeInfo])


class AuditLogObject(base.APIBase):
    """An object that had the name, with every name it had. Give its `id` as `ref_id`."""

    type: model.audit_types.ObjectType
    id: str
    names: list[str]
    # When the entry that gave the object its first name was written. None once that entry is gone.
    first_seen: int | None = None


class AuditLogObjectsResponse(base.APIBase):
    objects: list[AuditLogObject] = pydantic.Field(default_factory=list[AuditLogObject])
    # Pass it back as `cursor` to read what comes after these objects. It is set on the last page too.
    next_cursor: str
    # True when no object came after these ones at the time of the query.
    is_last: bool
