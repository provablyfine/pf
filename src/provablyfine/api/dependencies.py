"""Requests and transactions.

# A request is one all-or-nothing unit of work

Each request gets one transaction on the registry database and one on its tenant database.
They start before your handler runs.
They commit when the handler returns normally.
They roll back if anything raises, including a `ProblemHTTPException`.

Raising an error undoes every write the request made.
Returning a problem response commits them.
`_already_accepted` relies on this to keep its denylist entry while it answers 403.

Your own writes are visible to your later reads in the same request.
Nobody else sees them until the commit.

Anything outside the database is not part of the transaction and cannot be undone.
Examples are the invitation mail or an outbound HTTP call.

# Do not assume that what you read is still true when you write

Other requests commit while yours runs.
So a check followed by a write is unsafe by itself.

Express every invariant as one statement that checks and writes together.
Examples are `UPDATE ... WHERE is_initialized = 0` followed by a look at the row count,
or an insert guarded by a unique constraint.
Then handle the loser cleanly, for example with a 204 or a 409.

SQLite hides this mistake because it queues writers.
Postgres and MySQL do not.
Non-GET requests take the SQLite write lock first (`BEGIN IMMEDIATE`) to avoid "database is locked" errors.
This is only about scheduling.
Correctness must never depend on it.

A GET that writes must be marked with `writes_tenant`.
An endpoint that writes the registry must be marked with `writes_registry`.
The registry is shared by all the tenants, so it takes the write lock only for these endpoints.

A request holds one connection per database until it ends.
The pool has 15, so more concurrent requests wait for a connection.
"""

from __future__ import annotations

import collections.abc

import fastapi
import fastapi.requests

from . import app_db, db, registry_db, responses
from .context import ctx

_REGISTRY_WRITERS: set[collections.abc.Callable[..., object]] = set()
_TENANT_WRITERS: set[collections.abc.Callable[..., object]] = set()


def writes_registry[F: collections.abc.Callable[..., object]](endpoint: F) -> F:
    """Mark an endpoint that writes to the registry database.

    The registry is shared by all the tenants. Its transaction takes the write lock up front
    only for these endpoints. Doing it for every write request would make all tenants wait for each other.

    Put it right under the router decorator, so that it marks the function the router calls.
    """
    _REGISTRY_WRITERS.add(endpoint)
    return endpoint


def writes_tenant[F: collections.abc.Callable[..., object]](endpoint: F) -> F:
    """Mark a GET endpoint that writes to the tenant database.

    Requests that are not GET, HEAD or OPTIONS are already treated as writers.
    Put it right under the router decorator, like `writes_registry`.
    """
    _TENANT_WRITERS.add(endpoint)
    return endpoint


async def registry(request: fastapi.requests.Request):
    write = request.scope["endpoint"] in _REGISTRY_WRITERS
    async with db.abegin(request.app.state.tenant_registry_engine, write=write) as registry_conn:
        yield registry_db.create(registry_conn)


async def tenant_context(
    request: fastapi.requests.Request,
    tenant_uuid: str,
    reg_db: registry_db.RegistryDb = fastapi.Depends(registry),
):
    tenant_row = reg_db.tenant.read_one(uuid=tenant_uuid)

    if tenant_row is None or not tenant_row.is_enabled:
        raise responses.ProblemHTTPException(responses.problem_response(status_code=404, title="Tenant not found"))

    engines = request.app.state.tenant_engines
    if tenant_row.id not in engines:
        engines[tenant_row.id] = db.create_engine(tenant_row.database_url, echo=request.app.state.config.debug_sql)
    write = request.method not in ("GET", "HEAD", "OPTIONS") or request.scope["endpoint"] in _TENANT_WRITERS
    async with db.abegin(engines[tenant_row.id], write=write) as conn:
        application_db = app_db.create(conn)
        with (
            ctx.set_tenant_id(tenant_row.id),
            ctx.set_tenant_uuid(tenant_uuid),
            ctx.set_app_db(application_db),
        ):
            yield
