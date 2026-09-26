from __future__ import annotations

import time
import uuid

import fastapi
import fastapi.responses

from .. import db, dependencies, grant, migrate, registry_db, responses, schemas, signature
from ..context import ctx

router = fastapi.APIRouter(prefix="/tenant", dependencies=[fastapi.Depends(signature.verify_session)])

_204 = fastapi.responses.Response(status_code=204)


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
    db_url = db.derive_tenant_url(ctx.config.tenant_registry_url, tenant_uuid)
    db.create_database(db_url)
    now = int(time.time())
    new_id = reg_db.tenant.create(
        uuid=tenant_uuid,
        name=data.name,
        display_name=data.display_name,
        owner_id=ctx.tenant_id,
        database_url=db_url,
        is_enabled=True,
        is_initialized=False,
        is_deleted=False,
        created_at=now,
    )
    row = reg_db.tenant.read_one(id=new_id)
    assert row is not None

    # new database
    migrate.create_tenant(db_url)

    return _row_to_schema(row)


@router.patch(
    "/{tenant_id:int}",
    status_code=204,
    responses={400: responses.PROBLEM, 403: responses.PROBLEM, 404: responses.PROBLEM},
)
@dependencies.writes_registry
def update_endpoint(
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

    update_kwargs = {f: getattr(data, f) for f in data.model_fields_set}
    if update_kwargs:
        reg_db.tenant.update(**update_kwargs).where(id=tenant_id)

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
