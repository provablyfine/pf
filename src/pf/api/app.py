import contextlib
import logging
import os
import random
import sys
import time
import traceback

import fastapi
import fastapi.exceptions
import fastapi.openapi.utils
import fastapi.requests
import fastapi.responses
import pydantic
import sqlalchemy
import yaml

from .. import base64url
from . import dao_factory, db, dependencies, endpoints, middleware, responses, tenant_db

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
        self._id_rng = random.Random()

    @property
    def prefix(self) -> str:
        return self._prefix

    def add(self, data: object) -> str:
        if len(self._store) > self._max_size:
            first = next(iter(self._store))
            self._store.pop(first)
        id = self._id_rng.randbytes(4).hex()
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


def create(conf) -> fastapi.FastAPI:
    match conf.log_level:
        case "DEBUG":
            level = logging.DEBUG
        case "INFO":
            level = logging.INFO
        case "WARNING":
            level = logging.WARN
        case "ERROR":
            level = logging.ERROR
        case _:
            assert False
    logging.basicConfig(stream=sys.stdout, level=level)

    def _bootstrap_root_tenant(registry_engine: sqlalchemy.Engine):
        root_db_url = f"sqlite:///{os.path.join(conf.tenants_dir, 'root.db')}"
        db.create_tables(root_db_url)
        now = int(time.time())
        with registry_engine.begin() as registry_conn:
            registry_dao = dao_factory.create(registry_conn, tenant_db.tenant_metadata)
            registry_dao.tenant.create(
                name="root",
                display_name="root",
                owner_id=None,
                database_url=root_db_url,
                is_enabled=True,
                is_initialized=False,
                created_at=now,
            )

    @contextlib.asynccontextmanager
    async def lifespan(app: fastapi.FastAPI):
        os.makedirs(conf.tenants_dir, exist_ok=True)
        tenant_db.create_tables(conf.tenant_registry_url)
        registry_engine = sqlalchemy.create_engine(conf.tenant_registry_url, echo=conf.debug_sql)
        kek_filename = conf.kek_filename.format(PF_API_KEK_FILENAME=os.getenv("PF_API_KEK_FILENAME"))
        with open(kek_filename, "rb") as f:
            kek = base64url.encode(f.read()) + "======"
        app.state.config = conf
        app.state.tenant_registry_engine = registry_engine
        app.state.tenant_engines = {}
        app.state.kek = kek
        app.state.debug_store = _InMemoryDebugStore()

        with registry_engine.connect() as registry_conn:
            registry_dao = dao_factory.create(registry_conn, tenant_db.tenant_metadata)
            if registry_dao.tenant.read_one() is None:
                _bootstrap_root_tenant(registry_engine)

        yield

    fastapi_app = fastapi.FastAPI(lifespan=lifespan, docs_url="/docs", redoc_url="/redoc")

    @fastapi_app.exception_handler(responses.ProblemHTTPException)
    async def problem_exception_handler(
        request: fastapi.requests.Request, exc: responses.ProblemHTTPException
    ) -> fastapi.responses.Response:
        return exc.response

    @fastapi_app.exception_handler(pydantic.ValidationError)
    async def validation_error_handler(
        request: fastapi.requests.Request, exc: pydantic.ValidationError
    ) -> fastapi.responses.Response:
        assert len(exc.errors()) > 0
        error = exc.errors()[0]
        return responses.problem_response(
            status_code=400,
            title="Request invalid.",
            detail=f"{error['msg']}: {'.'.join(map(str, error['loc']))}",
        )

    @fastapi_app.exception_handler(fastapi.exceptions.RequestValidationError)
    async def request_validation_error_handler(
        request: fastapi.requests.Request, exc: fastapi.exceptions.RequestValidationError
    ) -> fastapi.responses.Response:
        assert len(exc.errors()) > 0
        error = exc.errors()[0]
        return responses.problem_response(
            status_code=400,
            title="Request invalid.",
            detail=f"{error['msg']}: {'.'.join(map(str, error['loc']))}",
        )

    @fastapi_app.exception_handler(Exception)
    async def generic_exception_handler(
        request: fastapi.requests.Request, exc: Exception
    ) -> fastapi.responses.Response:
        tb = _format_endpoint_traceback(exc)
        debug_path = request.app.state.debug_store.add(_Backtrace(request.method, request.url.path, tb).format())
        debug_url = request.app.state.config.base_url + debug_path
        return responses.problem_response(status_code=500, title="Internal Server Error", instance=debug_url)

    # Middleware added in reverse order: last added = outermost
    fastapi_app.add_middleware(middleware.ConfigContextMiddleware)
    fastapi_app.add_middleware(middleware.KekContextMiddleware)
    fastapi_app.add_middleware(middleware.BodyReaderMiddleware)

    def _openapi_schema() -> dict:
        if fastapi_app.openapi_schema:
            return fastapi_app.openapi_schema
        schema = fastapi.openapi.utils.get_openapi(
            title=fastapi_app.title, version=fastapi_app.version, routes=fastapi_app.routes
        )
        for path_item in schema.get("paths", {}).values():
            for operation in path_item.values():
                if isinstance(operation, dict):
                    operation.get("responses", {}).pop("422", None)
        fastapi_app.openapi_schema = schema
        return schema

    fastapi_app.openapi = _openapi_schema  # type: ignore[method-assign]

    @fastapi_app.get("/openapi.yaml", include_in_schema=False)
    def openapi_yaml() -> fastapi.responses.Response:
        return fastapi.responses.Response(
            content=yaml.dump(_openapi_schema(), allow_unicode=True, sort_keys=False),
            media_type="application/yaml",
        )

    @fastapi_app.get("/debug/trigger-error", include_in_schema=False)
    def trigger_error_endpoint() -> fastapi.responses.Response:
        raise RuntimeError("Triggered for testing")

    @fastapi_app.get("/debug/{debug_id}")
    def debug_endpoint(debug_id: str, request: fastapi.requests.Request) -> fastapi.responses.Response:
        data = request.app.state.debug_store.get(debug_id)
        if data is None:
            return responses.problem_response(
                status_code=404, title="Debug data could not be found", detail=f"Missing {debug_id}"
            )
        return fastapi.responses.JSONResponse(status_code=200, content=data)

    _tenant_dep = fastapi.Depends(dependencies.tenant_context)
    _tenant_prefix = "/pf/t/{tenant_name}"

    fastapi_app.include_router(endpoints.directory.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])
    fastapi_app.include_router(endpoints.initialize.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])
    fastapi_app.include_router(endpoints.auth_http_sig.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])
    fastapi_app.include_router(endpoints.auth_oidc.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])
    fastapi_app.include_router(endpoints.auth_endpoint.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])
    fastapi_app.include_router(endpoints.auth_public.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])
    fastapi_app.include_router(endpoints.boundary.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])
    fastapi_app.include_router(endpoints.identity.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])
    fastapi_app.include_router(endpoints.role.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])
    fastapi_app.include_router(endpoints.tag.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])
    fastapi_app.include_router(endpoints.ssh.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])
    fastapi_app.include_router(endpoints.tenant.router, prefix=_tenant_prefix, dependencies=[_tenant_dep])

    return fastapi_app
