from __future__ import annotations

import fastapi
import fastapi.requests
import sqlalchemy

from . import dao_factory, db, responses, tenant_db
from .context import ctx


async def registry_dao(request: fastapi.requests.Request):
    with request.app.state.tenant_registry_engine.begin() as registry_conn:
        yield dao_factory.create(registry_conn, tenant_db.tenant_metadata)


async def tenant_context(
    request: fastapi.requests.Request,
    tenant_name: str,
    reg_dao: dao_factory.Dao = fastapi.Depends(registry_dao),
):
    tenant_row = reg_dao.tenant.read_one(name=tenant_name)

    if tenant_row is None or not tenant_row.is_enabled:
        raise responses.ProblemHTTPException(responses.problem_response(status_code=404, title="Tenant not found"))

    engines = request.app.state.tenant_engines
    if tenant_name not in engines:
        engines[tenant_name] = sqlalchemy.create_engine(
            tenant_row.database_url, echo=request.app.state.config.debug_sql
        )
    with engines[tenant_name].begin() as conn:
        dao = dao_factory.create(conn, db.metadata)
        with ctx.set_tenant_id(tenant_row.id):
            with ctx.set_tenant_name(tenant_name):
                with ctx.set_db(dao):
                    yield
