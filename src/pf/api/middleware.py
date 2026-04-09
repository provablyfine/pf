import collections.abc

import cryptography.fernet
import starlette.middleware.base
import starlette.requests
import starlette.responses

from .context import ctx

NextHandler = collections.abc.Callable[
    [starlette.requests.Request], collections.abc.Awaitable[starlette.responses.Response]
]


class BodyReaderMiddleware(starlette.middleware.base.BaseHTTPMiddleware):
    async def dispatch(
        self,
        request: starlette.requests.Request,
        call_next: NextHandler,
    ) -> starlette.responses.Response:
        request.state.body = await request.body()
        return await call_next(request)


class KekContextMiddleware(starlette.middleware.base.BaseHTTPMiddleware):
    async def dispatch(
        self,
        request: starlette.requests.Request,
        call_next: NextHandler,
    ) -> starlette.responses.Response:
        kek = cryptography.fernet.Fernet(request.app.state.kek)
        with ctx.set_kek(kek):
            return await call_next(request)


class ConfigContextMiddleware(starlette.middleware.base.BaseHTTPMiddleware):
    async def dispatch(
        self,
        request: starlette.requests.Request,
        call_next: NextHandler,
    ) -> starlette.responses.Response:
        with ctx.set_config(request.app.state.config):
            return await call_next(request)
