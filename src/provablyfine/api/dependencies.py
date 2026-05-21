from __future__ import annotations

import fastapi
import fastapi.requests
import sqlalchemy

from . import app_db, registry_db, responses
from .context import ctx


async def registry(request: fastapi.requests.Request):
    with request.app.state.tenant_registry_engine.begin() as registry_conn:
        yield registry_db.create(registry_conn)


async def tenant_context(
    request: fastapi.requests.Request,
    tenant_name: str,
    reg_db: registry_db.RegistryDb = fastapi.Depends(registry),
):
    tenant_row = reg_db.tenant.read_one(name=tenant_name)

    if tenant_row is None or not tenant_row.is_enabled:
        raise responses.ProblemHTTPException(responses.problem_response(status_code=404, title="Tenant not found"))

    engines = request.app.state.tenant_engines
    if tenant_name not in engines:
        engines[tenant_name] = sqlalchemy.create_engine(
            tenant_row.database_url, echo=request.app.state.config.debug_sql
        )
    with engines[tenant_name].begin() as conn:
        application_db = app_db.create(conn)
        with ctx.set_tenant_id(tenant_row.id):
            with ctx.set_tenant_name(tenant_name):
                with ctx.set_app_db(application_db):
                    yield
