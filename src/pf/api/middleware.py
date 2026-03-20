import collections.abc

import cryptography.fernet
import starlette.middleware.base
import starlette.requests
import starlette.responses

from . import dao_factory, db
from .context import ctx


class BodyReaderMiddleware(starlette.middleware.base.BaseHTTPMiddleware):
    async def dispatch(
        self, request: starlette.requests.Request, call_next: collections.abc.Callable
    ) -> starlette.responses.Response:
        request.state.body = await request.body()
        return await call_next(request)


class KekContextMiddleware(starlette.middleware.base.BaseHTTPMiddleware):
    async def dispatch(
        self, request: starlette.requests.Request, call_next: collections.abc.Callable
    ) -> starlette.responses.Response:
        kek = cryptography.fernet.Fernet(request.app.state.kek)
        with ctx.set_kek(kek):
            return await call_next(request)


class ConfigContextMiddleware(starlette.middleware.base.BaseHTTPMiddleware):
    async def dispatch(
        self, request: starlette.requests.Request, call_next: collections.abc.Callable
    ) -> starlette.responses.Response:
        with ctx.set_config(request.app.state.config):
            return await call_next(request)


class DbContextMiddleware(starlette.middleware.base.BaseHTTPMiddleware):
    async def dispatch(
        self, request: starlette.requests.Request, call_next: collections.abc.Callable
    ) -> starlette.responses.Response:
        with request.app.state.db_engine.begin() as conn:
            dao = dao_factory.create(conn, db.metadata)
            with ctx.set_db(dao):
                return await call_next(request)
