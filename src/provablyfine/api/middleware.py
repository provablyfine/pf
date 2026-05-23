import collections.abc
import time

import cryptography.fernet
import prometheus_client
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


HTTP_REQUESTS_TOTAL = prometheus_client.Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "path", "status_family"],
)
HTTP_REQUEST_DURATION_SECONDS = prometheus_client.Histogram(
    "http_request_duration_seconds",
    "HTTP request duration",
    ["method", "path", "status_family"],
)


class PrometheusMiddleware(starlette.middleware.base.BaseHTTPMiddleware):
    async def dispatch(
        self,
        request: starlette.requests.Request,
        call_next: NextHandler,
    ) -> starlette.responses.Response:
        start = time.perf_counter()
        response = await call_next(request)
        duration = time.perf_counter() - start

        route = request.scope.get("route")
        path = route.path if route is not None else "<unmatched>"
        method = request.method
        status_family = f"{response.status_code // 100}xx"

        HTTP_REQUESTS_TOTAL.labels(method, path, status_family).inc()
        HTTP_REQUEST_DURATION_SECONDS.labels(method, path, status_family).observe(duration)
        return response
