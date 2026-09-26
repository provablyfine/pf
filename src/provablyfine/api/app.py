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
import sqlalchemy.exc

from .. import base64url
from . import config, db, dependencies, endpoints, jwt_validator, middleware, migrate, registry_db, responses, signature

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
        id = secrets.token_urlsafe(16)
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
    def _bootstrap_databases(registry_engine: sqlalchemy.Engine) -> None:
        """Create the registry and root tenant databases on first startup."""
        db.create_database(conf.tenant_registry_url, exist_ok=True)
        if migrate.is_alembic_versioned(conf.tenant_registry_url):
            return
        migrate.create_registry(conf.tenant_registry_url)
        root_db_url = db.derive_tenant_url(conf.tenant_registry_url, registry_db.ROOT_TENANT_UUID)
        db.create_database(root_db_url)
        migrate.create_tenant(root_db_url)
        with db.begin(registry_engine, write=True) as registry_conn:
            registry_db.create(registry_conn).tenant.create(
                uuid=registry_db.ROOT_TENANT_UUID,
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
        registry_engine = db.create_engine(conf.tenant_registry_url, echo=conf.debug_sql)

        _bootstrap_databases(registry_engine)
        migrate.upgrade_registry(conf.tenant_registry_url)

        kek_filename = conf.kek_filename.format(PF_SECRET_DIRECTORY=os.getenv("PF_SECRET_DIRECTORY", ""))
        with open(kek_filename, "rb") as f:
            kek = base64url.encode(f.read()) + "======"
        app.state.config = conf
        app.state.trusted_keys = jwt_validator.TrustedKeys(f"{conf.base_url}/pf/t")
        app.state.tenant_registry_engine = registry_engine
        app.state.tenant_engines = {}
        app.state.kek = kek
        app.state.debug_store = _InMemoryDebugStore()
        app.state.nonce_store = signature.NonceStore()

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

    async def database_error_handler(request: fastapi.requests.Request, exc: Exception) -> fastapi.responses.Response:
        assert isinstance(exc, sqlalchemy.exc.OperationalError)
        # "database is locked" is sqlite3's own error text for its whole-file write lock.
        # Postgres and MySQL do row-level locking and never raise this from this driver.
        if "sqlite3" not in type(exc.orig).__module__ or "database is locked" not in str(exc.orig):
            return await generic_exception_handler(request, exc)
        # Writers wait for each other for a few seconds. Getting here means the database is overloaded.
        response = responses.problem_response(status_code=503, title="Database is busy, try again")
        response.headers["Retry-After"] = "1"
        return response

    async def generic_exception_handler(
        request: fastapi.requests.Request, exc: Exception
    ) -> fastapi.responses.Response:
        if not request.app.state.config.debug:
            return responses.problem_response(status_code=500, title="Internal Server Error")
        tb = _format_endpoint_traceback(exc)
        debug_path = request.app.state.debug_store.add(_Backtrace(request.method, request.url.path, tb).format())
        debug_url = request.app.state.config.base_url + debug_path
        return responses.problem_response(status_code=500, title="Internal Server Error", instance=debug_url)

    fastapi_app.add_exception_handler(responses.ProblemHTTPException, problem_exception_handler)
    fastapi_app.add_exception_handler(pydantic.ValidationError, validation_error_handler)
    fastapi_app.add_exception_handler(fastapi.exceptions.RequestValidationError, request_validation_error_handler)
    fastapi_app.add_exception_handler(sqlalchemy.exc.OperationalError, database_error_handler)
    fastapi_app.add_exception_handler(Exception, generic_exception_handler)

    # Middleware added in reverse order: last added = outermost
    fastapi_app.add_middleware(middleware.ConfigContextMiddleware)
    fastapi_app.add_middleware(middleware.KekContextMiddleware)
    fastapi_app.add_middleware(middleware.BodyReaderMiddleware)
    fastapi_app.add_middleware(middleware.PrometheusMiddleware)

    if conf.debug:
        fastapi_app.include_router(endpoints.debug.router, tags=["debug"])
    fastapi_app.include_router(endpoints.frps.router)

    _tenant_dep = dependencies.TENANT_CONTEXT
    _tenant_prefix = "/pf/t/{tenant_uuid}"

    fastapi_app.include_router(endpoints.audit_log.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])
    fastapi_app.include_router(endpoints.directory.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])
    fastapi_app.include_router(endpoints.initialize.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])
    fastapi_app.include_router(endpoints.auth_http_sig.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])
    # The OIDC login calls the identity provider before its transaction starts: it orders its own dependencies.
    fastapi_app.include_router(endpoints.auth_oidc.router, prefix=_tenant_prefix)
    fastapi_app.include_router(endpoints.auth_endpoint.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])
    fastapi_app.include_router(endpoints.public.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])
    fastapi_app.include_router(endpoints.boundary.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])
    fastapi_app.include_router(endpoints.identity.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])
    fastapi_app.include_router(endpoints.role.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])
    fastapi_app.include_router(endpoints.tag.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])
    fastapi_app.include_router(endpoints.ssh.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])
    fastapi_app.include_router(endpoints.bastion.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])
    fastapi_app.include_router(endpoints.tenant.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])
    fastapi_app.include_router(endpoints.ping.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])
    fastapi_app.include_router(endpoints.session.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])

    @fastapi_app.get("/metrics", include_in_schema=False)
    async def metrics() -> fastapi.responses.Response:  # type: ignore[reportUnusedFunction]
        return fastapi.responses.Response(
            content=prometheus_client.generate_latest(),
            media_type=prometheus_client.CONTENT_TYPE_LATEST,
        )

    return fastapi_app


def factory() -> fastapi.FastAPI:
    config_path = os.environ.get("PF_API_CONFIG", "pf-server.yaml")
    conf = config.Config.load(config_path)
    return create(conf)
