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

# The response is sent after the commit

The transactions commit before the response is sent.
If the commit fails, the client gets an error.
It is never told "created" for data that is not there.

# Keep slow things out of the transaction

The transaction of a write request holds the write lock of the tenant.
Do not call another service or send an email inside it.

To do something after the commit, use `ctx.after_commit(action)`.
The action runs when the data is committed and before the response is sent.
If it raises a `ProblemHTTPException`, the client gets that error.
The invitation email works this way.

To do something slow before the transaction, use a dependency that runs before `tenant_context`.
It reads the database with `tenant_read`, in short transactions of its own.
The OIDC login works this way.

To keep something when a request is rejected, use `ctx.after_rollback(action)`.
A rejection rolls back everything the request wrote, including its audit entries.
The action runs in its own transaction after the rollback.
`audit_log.create_warning_after_rollback` does this.

# Async code

Never wait for the database on the event loop.
Waiting for a lock would stop every other request.
Use `await asyncio.to_thread(...)` for database calls in `async def` code.
"""

from __future__ import annotations

import asyncio
import collections.abc
import contextlib
import logging

import fastapi
import fastapi.requests
import sqlalchemy

from . import app_db, context, db, registry_db, responses
from .context import ctx

logger = logging.getLogger(__name__)

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


# The transactions commit when these dependencies exit.
# With scope="function" that happens before the response is sent.
# With the default scope it would happen after, and the client could be told "created" for data
# that is not committed yet, or never will be.
# Always use these two objects. The same dependency with another scope would open a second transaction.
REGISTRY = fastapi.Depends(registry, scope="function")


def _tenant_engine(request: fastapi.requests.Request, tenant_row: registry_db.TenantRow) -> sqlalchemy.Engine:
    engines = request.app.state.tenant_engines
    if tenant_row.id not in engines:
        engines[tenant_row.id] = db.create_engine(tenant_row.database_url, echo=request.app.state.config.debug_sql)
    return engines[tenant_row.id]


@contextlib.asynccontextmanager
async def tenant_read(request: fastapi.requests.Request, tenant_uuid: str) -> collections.abc.AsyncGenerator[None]:
    """Read the tenant database in a short transaction of its own, before the request's transaction starts.

    Use it when a request must do something slow first, such as calling another service.
    The request's own transaction holds the tenant's write lock, so it must not be open during that call.
    Model functions work inside the block, as in a handler. Nothing may be written.
    """
    async with db.abegin(request.app.state.tenant_registry_engine) as registry_conn:
        tenant_row = await asyncio.to_thread(registry_db.create(registry_conn).tenant.read_one, uuid=tenant_uuid)
    if tenant_row is None or not tenant_row.is_enabled:
        raise responses.ProblemHTTPException(responses.problem_response(status_code=404, title="Tenant not found"))
    async with db.abegin(_tenant_engine(request, tenant_row)) as conn:
        with (
            ctx.set_tenant_id(tenant_row.id),
            ctx.set_tenant_uuid(tenant_uuid),
            ctx.set_app_db(app_db.create(conn)),
        ):
            yield


async def _run_after_rollback(engine: sqlalchemy.Engine, deferred: context.Deferred) -> None:
    if not deferred.after_rollback:
        return
    try:
        async with db.abegin(engine, write=True) as conn:
            with ctx.set_app_db(app_db.create(conn)):
                for action in deferred.after_rollback:
                    await asyncio.to_thread(action)
    except Exception:
        # The request is rejected anyway. Do not hide the rejection behind a failure to record it.
        logger.exception("Unable to record what a rejected request left behind")


async def tenant_context(
    request: fastapi.requests.Request,
    tenant_uuid: str,
    reg_db: registry_db.RegistryDb = REGISTRY,
):
    # Database calls in async code go to a worker thread: waiting for a lock must not stop the event loop.
    tenant_row = await asyncio.to_thread(reg_db.tenant.read_one, uuid=tenant_uuid)

    if tenant_row is None or not tenant_row.is_enabled:
        raise responses.ProblemHTTPException(responses.problem_response(status_code=404, title="Tenant not found"))

    engine = _tenant_engine(request, tenant_row)
    write = request.method not in ("GET", "HEAD", "OPTIONS") or request.scope["endpoint"] in _TENANT_WRITERS
    deferred = context.Deferred()
    try:
        async with db.abegin(engine, write=write) as conn:
            application_db = app_db.create(conn)
            with (
                ctx.set_tenant_id(tenant_row.id),
                ctx.set_tenant_uuid(tenant_uuid),
                ctx.set_app_db(application_db),
                ctx.set_deferred(deferred),
            ):
                yield
    except responses.ProblemHTTPException:
        await _run_after_rollback(engine, deferred)
        raise
    for action in deferred.after_commit:
        await asyncio.to_thread(action)


TENANT_CONTEXT = fastapi.Depends(tenant_context, scope="function")
