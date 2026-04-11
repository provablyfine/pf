from __future__ import annotations

import os
import time

import fastapi
import fastapi.responses

from .. import app_db, dependencies, grant, registry_db, responses, schemas, signature
from ..context import ctx

router = fastapi.APIRouter(prefix="/tenant", dependencies=[fastapi.Depends(signature.verify_session)])

_204 = fastapi.responses.Response(status_code=204)


def _row_to_schema(row) -> schemas.TenantReadResponse:
    return schemas.TenantReadResponse(
        id=row.id,
        name=row.name,
        display_name=row.display_name,
        owner_id=row.owner_id,
        is_enabled=row.is_enabled,
        is_initialized=row.is_initialized,
        is_deleted=row.is_deleted,
        created_at=row.created_at,
    )


def _ownership_filter(rows, tenant_id: int):
    return [r for r in rows if r.id == tenant_id or r.owner_id == tenant_id]


@router.get("", status_code=200)
def list_endpoint(
    reg_db: registry_db.RegistryDb = fastapi.Depends(dependencies.registry),
) -> schemas.TenantListResponse:
    all_rows = reg_db.tenant.read_all()
    rows = _ownership_filter(all_rows, ctx.tenant_id)
    grants = grant.Grants.create()
    output = []
    for row in rows:
        if grants.tenant(row.id).can_read():
            output.append(_row_to_schema(row))
    return schemas.TenantListResponse(tenants=output)


@router.get("/{tenant_id:int}", status_code=200, responses={403: responses.PROBLEM, 404: responses.PROBLEM})
def read_endpoint(
    tenant_id: int,
    reg_db: registry_db.RegistryDb = fastapi.Depends(dependencies.registry),
) -> schemas.TenantReadResponse:
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
def create_endpoint(
    data: schemas.TenantCreateRequest,
    reg_db: registry_db.RegistryDb = fastapi.Depends(dependencies.registry),
) -> schemas.TenantReadResponse:
    grants = grant.Grants.create()
    if not grants.tenant(None).can_create():
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=403, title="Not allowed to create tenant")
        )

    # new tenant entry
    db_path = os.path.join(ctx.config.tenants_dir, f"{data.name}.db")
    db_url = f"sqlite:///{db_path}"
    now = int(time.time())
    new_id = reg_db.tenant.create(
        name=data.name,
        display_name=data.display_name,
        owner_id=ctx.tenant_id,
        database_url=db_url,
        is_enabled=True,
        is_initialized=False,
        created_at=now,
    )
    row = reg_db.tenant.read_one(id=new_id)
    assert row is not None

    # new database
    app_db.create_tables(db_url)

    return _row_to_schema(row)


@router.patch(
    "/{tenant_id:int}",
    status_code=204,
    responses={400: responses.PROBLEM, 403: responses.PROBLEM, 404: responses.PROBLEM},
)
def update_endpoint(
    tenant_id: int,
    data: schemas.TenantUpdateRequest,
    reg_db: registry_db.RegistryDb = fastapi.Depends(dependencies.registry),
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
def delete_endpoint(
    tenant_id: int,
    reg_db: registry_db.RegistryDb = fastapi.Depends(dependencies.registry),
) -> fastapi.responses.Response:
    row = reg_db.tenant.read_one(id=tenant_id)

    if row is None or not _ownership_filter([row], ctx.tenant_id):
        raise responses.ProblemHTTPException(responses.problem_response(status_code=404, title="Tenant not found"))

    grants = grant.Grants.create()
    if not grants.tenant(row.id).can_delete():
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=403, title="Not allowed to delete tenant")
        )

    reg_db.tenant.update(is_enabled=False, is_deleted=True).where(id=tenant_id)

    return _204
