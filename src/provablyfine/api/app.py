import contextlib
import logging
import os
import secrets
import time
import traceback

import fastapi
import fastapi.exceptions
import fastapi.requests
import fastapi.responses
import prometheus_client
import pydantic
import sqlalchemy

from .. import base64url, log
from . import config, dependencies, endpoints, middleware, migrate, registry_db, responses

logger = logging.getLogger(__name__)


def _format_endpoint_traceback(exc: Exception) -> str:
    """Format only the innermost user-code frames of an exception's traceback.

    Walks from the innermost frame outward, collecting contiguous frames whose
    filename is not inside a site-packages directory, then stops at the first
    site-packages frame.  This strips Starlette/anyio/FastAPI infrastructure
    frames that accumulate while the exception bubbles up to the exception
    handler, leaving only the frames that originate in application code.
    """
    frames = list(traceback.walk_tb(exc.__traceback__))
    end = len(frames)
    start = end
    for i in range(end - 1, -1, -1):
        if "site-packages" not in frames[i][0].f_code.co_filename:
            start = i
        else:
            break
    user_frames = frames[start:end] if start < end else frames
    extracted = traceback.StackSummary.extract(user_frames, lookup_lines=True)
    lines: list[str] = ["Traceback (most recent call last):\n"]
    lines.extend(extracted.format())
    lines.extend(traceback.format_exception_only(type(exc), exc))
    return "".join(lines).rstrip("\n")


class _InMemoryDebugStore:
    def __init__(self, prefix: str = "/debug/", max_size: int = 10000):
        self._prefix = prefix
        self._max_size = max_size
        self._store: dict[str, object] = {}

    @property
    def prefix(self) -> str:
        return self._prefix

    def add(self, data: object) -> str:
        if len(self._store) > self._max_size:
            first = next(iter(self._store))
            self._store.pop(first)
        id = secrets.token_hex(4)
        self._store[id] = data
        return self._prefix + id

    def get(self, id: str) -> object | None:
        return self._store.get(id)


class _Backtrace:
    def __init__(self, method: str, path: str, backtrace: str):
        self._method = method
        self._path = path
        self._backtrace = backtrace
        self._at = int(time.time())

    def format(self) -> dict[str, object]:
        return {"method": self._method, "path": self._path, "at": self._at, "backtrace": self._backtrace}


def create(conf: config.Config) -> fastapi.FastAPI:
    log.setup_server("api", conf.log_level, conf.log_filename)

    def _bootstrap_databases(registry_engine: sqlalchemy.Engine) -> None:
        """Create the registry and root tenant databases on first startup."""
        if migrate.is_alembic_versioned(conf.tenant_registry_url):
            return
        migrate.create_registry(conf.tenant_registry_url)
        root_db_url = f"sqlite:///{os.path.join(conf.tenants_dir, 'root.db')}"
        migrate.create_tenant(root_db_url)
        with registry_engine.begin() as registry_conn:
            registry_db.create(registry_conn).tenant.create(
                name="root",
                display_name="root",
                owner_id=None,
                database_url=root_db_url,
                is_enabled=True,
                is_initialized=False,
                created_at=int(time.time()),
                is_deleted=False,
            )

    @contextlib.asynccontextmanager
    async def lifespan(app: fastapi.FastAPI):
        os.makedirs(conf.tenants_dir, exist_ok=True)
        registry_engine = sqlalchemy.create_engine(conf.tenant_registry_url, echo=conf.debug_sql)

        _bootstrap_databases(registry_engine)
        migrate.upgrade_registry(conf.tenant_registry_url)

        kek_filename = conf.kek_filename.format(PF_API_KEK_FILENAME=os.getenv("PF_API_KEK_FILENAME"))
        with open(kek_filename, "rb") as f:
            kek = base64url.encode(f.read()) + "======"
        app.state.config = conf
        app.state.tenant_registry_engine = registry_engine
        app.state.tenant_engines = {}
        app.state.kek = kek
        app.state.debug_store = _InMemoryDebugStore()

        with registry_engine.connect() as registry_conn:
            tenant_rows = registry_db.create(registry_conn).tenant.read_all()
        for tenant_row in tenant_rows:
            migrate.upgrade_tenant(tenant_row.database_url)

        yield

    fastapi_app = fastapi.FastAPI(lifespan=lifespan, docs_url="/docs", redoc_url="/redoc")

    async def problem_exception_handler(
        request: fastapi.requests.Request, exc: Exception
    ) -> fastapi.responses.Response:
        assert isinstance(exc, responses.ProblemHTTPException)
        return exc.response

    async def validation_error_handler(request: fastapi.requests.Request, exc: Exception) -> fastapi.responses.Response:
        assert isinstance(exc, pydantic.ValidationError)
        assert len(exc.errors()) > 0
        error = exc.errors()[0]
        return responses.problem_response(
            status_code=422,
            title="Request invalid.",
            detail=f"{error['msg']}: {'.'.join(map(str, error['loc']))}",
        )

    async def request_validation_error_handler(
        request: fastapi.requests.Request, exc: Exception
    ) -> fastapi.responses.Response:
        assert isinstance(exc, fastapi.exceptions.RequestValidationError)
        assert len(exc.errors()) > 0
        error = exc.errors()[0]
        return responses.problem_response(
            status_code=422,
            title="Request invalid.",
            detail=f"{error['msg']}: {'.'.join(map(str, error['loc']))}",
        )

    async def generic_exception_handler(
        request: fastapi.requests.Request, exc: Exception
    ) -> fastapi.responses.Response:
        tb = _format_endpoint_traceback(exc)
        debug_path = request.app.state.debug_store.add(_Backtrace(request.method, request.url.path, tb).format())
        debug_url = request.app.state.config.base_url + debug_path
        return responses.problem_response(status_code=500, title="Internal Server Error", instance=debug_url)

    fastapi_app.add_exception_handler(responses.ProblemHTTPException, problem_exception_handler)
    fastapi_app.add_exception_handler(pydantic.ValidationError, validation_error_handler)
    fastapi_app.add_exception_handler(fastapi.exceptions.RequestValidationError, request_validation_error_handler)
    fastapi_app.add_exception_handler(Exception, generic_exception_handler)

    # Middleware added in reverse order: last added = outermost
    fastapi_app.add_middleware(middleware.ConfigContextMiddleware)
    fastapi_app.add_middleware(middleware.KekContextMiddleware)
    fastapi_app.add_middleware(middleware.BodyReaderMiddleware)
    fastapi_app.add_middleware(middleware.PrometheusMiddleware)

    fastapi_app.include_router(endpoints.debug.router, tags=["debug"])

    _tenant_dep = fastapi.Depends(dependencies.tenant_context)
    _tenant_prefix = "/pf/t/{tenant_name}"

    fastapi_app.include_router(endpoints.audit_log.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])
    fastapi_app.include_router(endpoints.directory.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])
    fastapi_app.include_router(endpoints.initialize.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])
    fastapi_app.include_router(endpoints.auth_http_sig.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])
    fastapi_app.include_router(endpoints.auth_oidc.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])
    fastapi_app.include_router(endpoints.auth_oauth2.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])
    fastapi_app.include_router(endpoints.auth_endpoint.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])
    fastapi_app.include_router(endpoints.public.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])
    fastapi_app.include_router(endpoints.boundary.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])
    fastapi_app.include_router(endpoints.identity.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])
    fastapi_app.include_router(endpoints.role.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])
    fastapi_app.include_router(endpoints.tag.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])
    fastapi_app.include_router(endpoints.ssh.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])
    fastapi_app.include_router(endpoints.bastion.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])
    fastapi_app.include_router(endpoints.tenant.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])

    @fastapi_app.get("/metrics", include_in_schema=False)
    async def metrics() -> fastapi.responses.Response:  # type: ignore[reportUnusedFunction]
        return fastapi.responses.Response(
            content=prometheus_client.generate_latest(),
            media_type=prometheus_client.CONTENT_TYPE_LATEST,
        )

    return fastapi_app
