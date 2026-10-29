from __future__ import annotations

import time
import uuid

import fastapi
import fastapi.requests
import fastapi.responses

from .. import app_db, db, dependencies, grant, migrate, model, registry_db, responses, schemas, signature
from ..context import ctx

router = fastapi.APIRouter(prefix="/tenant", dependencies=[fastapi.Depends(signature.verify_session)])

_204 = fastapi.responses.Response(status_code=204)

_RETENTION_FIELDS = ("audit_retention_days", "activity_retention_days", "retention_purge_enabled")
_TENANT_FIELDS = ("display_name", "is_enabled")


def _check_retention_days(data: schemas.tenant.TenantUpdateRequest) -> None:
    low, high = ctx.config.retention_min_days, ctx.config.retention_max_days
    for field in ("audit_retention_days", "activity_retention_days"):
        value = getattr(data, field)
        if value is not None and not low <= value <= high:
            raise responses.ProblemHTTPException(
                responses.problem_response(
                    status_code=400,
                    title="Retention period out of range",
                    detail=f"{field} must be between {low} and {high} days",
                )
            )


def _record_change(
    request: fastapi.requests.Request,
    audit_type: model.audit_types.AuditType,
    row: registry_db.TenantRow,
    changes: dict[str, dict[str, int | bool | str]],
    caller_tenant_name: str,
) -> None:
    """Write the change in the audit log of the tenant that it is about.

    The caller may belong to the tenant that owns this one. Its identity id means nothing there,
    so the entry names the caller's tenant and identity instead.
    The caller's own log gets an entry too, which says which tenant was changed.
    """
    if ctx.tenant_id == row.id:
        model.audit_log.create(audit_type, changes=changes)
        return
    author = model.audit_log.caller_as_foreign_author(caller_tenant_name)
    model.audit_log.create(audit_type, changes=changes, tenant_id=row.id, tenant_name=row.display_name)
    # The request already holds the write transaction of its own tenant. This one is for the tenant that changed.
    with (
        db.begin(request.app.state.tenants.engine(row.uuid), write=True) as connection,
        ctx.in_other_tenant(app_db.create(connection)),
        model.audit_log.written_by(author),
    ):
        model.audit_log.create(audit_type, changes=changes)


def _row_to_schema(row: registry_db.TenantRow) -> schemas.tenant.TenantReadResponse:
    return schemas.tenant.TenantReadResponse(
        id=row.id,
        uuid=row.uuid,
        name=row.name,
        display_name=row.display_name,
        owner_id=row.owner_id,
        is_enabled=row.is_enabled,
        is_initialized=row.is_initialized,
        is_deleted=row.is_deleted,
        created_at=row.created_at,
        audit_retention_days=row.audit_retention_days,
        activity_retention_days=row.activity_retention_days,
        retention_purge_enabled=row.retention_purge_enabled,
    )


def _ownership_filter(rows: list[registry_db.TenantRow], tenant_id: int) -> list[registry_db.TenantRow]:
    return [r for r in rows if r.id == tenant_id or r.owner_id == tenant_id]


@router.get("", status_code=200)
def list_endpoint(
    reg_db: registry_db.RegistryDb = dependencies.REGISTRY,
) -> schemas.tenant.TenantListResponse:
    all_rows = reg_db.tenant.read_all()
    rows = _ownership_filter(all_rows, ctx.tenant_id)
    grants = grant.Grants.create()
    output: list[schemas.tenant.TenantReadResponse] = []
    for row in rows:
        if grants.tenant(row.id).can_read():
            output.append(_row_to_schema(row))
    return schemas.tenant.TenantListResponse(tenants=output)


@router.get("/{tenant_id:int}", status_code=200, responses={403: responses.PROBLEM, 404: responses.PROBLEM})
def read_endpoint(
    tenant_id: int,
    reg_db: registry_db.RegistryDb = dependencies.REGISTRY,
) -> schemas.tenant.TenantReadResponse:
    row = reg_db.tenant.read_one(id=tenant_id)

    if row is None or not _ownership_filter([row], ctx.tenant_id):
        raise responses.ProblemHTTPException(responses.problem_response(status_code=404, title="Tenant not found"))

    grants = grant.Grants.create()
    if not grants.tenant(row.id).can_read():
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=403, title="Not allowed to read tenant")
        )

    return _row_to_schema(row)


@router.post("", status_code=200, responses={400: responses.PROBLEM, 403: responses.PROBLEM})
@dependencies.writes_registry
def create_endpoint(
    request: fastapi.requests.Request,
    data: schemas.tenant.TenantCreateRequest,
    reg_db: registry_db.RegistryDb = dependencies.REGISTRY,
) -> schemas.tenant.TenantReadResponse:
    grants = grant.Grants.create()
    if not grants.tenant(None).can_create():
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=403, title="Not allowed to create tenant")
        )

    # new tenant entry
    # The database is named after the UUID because tenant names are not unique.
    tenant_uuid = str(uuid.uuid4())
    tenants = request.app.state.tenants
    database_url = tenants.create(tenant_uuid)
    now = int(time.time())
    new_id = reg_db.tenant.create(
        uuid=tenant_uuid,
        name=data.name,
        display_name=data.display_name,
        owner_id=ctx.tenant_id,
        database_url=database_url,
        is_enabled=True,
        is_initialized=False,
        is_deleted=False,
        created_at=now,
        audit_retention_days=ctx.config.default_retention_days,
        activity_retention_days=ctx.config.default_retention_days,
        retention_purge_enabled=True,
    )
    row = reg_db.tenant.read_one(id=new_id)
    assert row is not None

    # new database
    migrate.create_tenant_tables(tenants, tenant_uuid)

    return _row_to_schema(row)


@router.patch(
    "/{tenant_id:int}",
    status_code=204,
    responses={400: responses.PROBLEM, 403: responses.PROBLEM, 404: responses.PROBLEM},
)
@dependencies.writes_registry
def update_endpoint(
    request: fastapi.requests.Request,
    tenant_id: int,
    data: schemas.tenant.TenantUpdateRequest,
    reg_db: registry_db.RegistryDb = dependencies.REGISTRY,
) -> fastapi.responses.Response:
    row = reg_db.tenant.read_one(id=tenant_id)

    if row is None or not _ownership_filter([row], ctx.tenant_id):
        raise responses.ProblemHTTPException(responses.problem_response(status_code=404, title="Tenant not found"))

    grants = grant.Grants.create()
    for field in data.model_fields_set:
        if not grants.tenant(row.id).can_update(field):
            raise responses.ProblemHTTPException(
                responses.problem_response(status_code=403, title="Not allowed to update tenant field", detail=field)
            )

    _check_retention_days(data)

    update_kwargs = {f: getattr(data, f) for f in data.model_fields_set}
    if update_kwargs:
        reg_db.tenant.update(**update_kwargs).where(id=tenant_id)

    caller_tenant_name: str | None = None
    for audit_type, fields in (
        (model.audit_types.RETENTION_SET, _RETENTION_FIELDS),
        (model.audit_types.TENANT_UPDATE, _TENANT_FIELDS),
    ):
        changes = {
            f: {"old": getattr(row, f), "new": update_kwargs[f]}
            for f in fields
            if f in update_kwargs and update_kwargs[f] != getattr(row, f)
        }
        if changes:
            if caller_tenant_name is None:
                caller_row = reg_db.tenant.read_one(id=ctx.tenant_id)
                assert caller_row is not None
                caller_tenant_name = caller_row.display_name
            _record_change(request, audit_type, row, changes, caller_tenant_name)

    return _204


@router.delete(
    "/{tenant_id:int}",
    status_code=204,
    responses={403: responses.PROBLEM, 404: responses.PROBLEM},
)
@dependencies.writes_registry
def delete_endpoint(
    tenant_id: int,
    reg_db: registry_db.RegistryDb = dependencies.REGISTRY,
) -> fastapi.responses.Response:
    row = reg_db.tenant.read_one(id=tenant_id)

    if row is None or not _ownership_filter([row], ctx.tenant_id):
        raise responses.ProblemHTTPException(responses.problem_response(status_code=404, title="Tenant not found"))

    grants = grant.Grants.create()
    if not grants.tenant(row.id).can_delete():
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=403, title="Not allowed to delete tenant")
        )

    # Soft delete only, for every backend: the tenant's physical database (or file, for
    # sqlite) is never dropped here.
    reg_db.tenant.update(is_enabled=False, is_deleted=True).where(id=tenant_id)

    return _204
