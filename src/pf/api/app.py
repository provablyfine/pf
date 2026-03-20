import contextlib
import logging
import os
import random
import sys
import time
import traceback

import fastapi
import fastapi.requests
import fastapi.responses
import pydantic
import sqlalchemy
import yaml

from .. import base64url
from . import db, endpoints, middleware, responses

logger = logging.getLogger(__name__)


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

    @contextlib.asynccontextmanager
    async def lifespan(app: fastapi.FastAPI):
        db.create_tables(conf.database_url)
        engine = sqlalchemy.create_engine(conf.database_url, echo=conf.debug_sql)
        kek_filename = conf.kek_filename.format(PF_API_KEK_FILENAME=os.getenv("PF_API_KEK_FILENAME"))
        with open(kek_filename, "rb") as f:
            kek = base64url.encode(f.read()) + "======"
        app.state.config = conf
        app.state.db_engine = engine
        app.state.kek = kek
        app.state.debug_store = _InMemoryDebugStore()
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

    @fastapi_app.exception_handler(Exception)
    async def generic_exception_handler(
        request: fastapi.requests.Request, exc: Exception
    ) -> fastapi.responses.Response:
        tb = traceback.format_exc()
        debug_path = request.app.state.debug_store.add(_Backtrace(request.method, request.url.path, tb).format())
        debug_url = request.app.state.config.base_url + debug_path
        return responses.problem_response(status_code=500, title="Internal Server Error", instance=debug_url)

    # Middleware added in reverse order: last added = outermost
    fastapi_app.add_middleware(middleware.DbContextMiddleware)
    fastapi_app.add_middleware(middleware.ConfigContextMiddleware)
    fastapi_app.add_middleware(middleware.KekContextMiddleware)
    fastapi_app.add_middleware(middleware.BodyReaderMiddleware)

    @fastapi_app.get("/openapi.yaml", include_in_schema=False)
    def openapi_yaml() -> fastapi.responses.Response:
        return fastapi.responses.Response(
            content=yaml.dump(fastapi_app.openapi(), allow_unicode=True, sort_keys=False),
            media_type="application/yaml",
        )

    @fastapi_app.get("/debug/{debug_id}")
    def debug_endpoint(debug_id: str, request: fastapi.requests.Request) -> fastapi.responses.Response:
        data = request.app.state.debug_store.get(debug_id)
        if data is None:
            return responses.problem_response(
                status_code=404, title="Debug data could not be found", detail=f"Missing {debug_id}"
            )
        return fastapi.responses.JSONResponse(status_code=200, content=data)

    fastapi_app.include_router(endpoints.directory.router)
    fastapi_app.include_router(endpoints.initialize.router)
    fastapi_app.include_router(endpoints.auth.router)
    fastapi_app.include_router(endpoints.boundary.router)
    fastapi_app.include_router(endpoints.identity.router)
    fastapi_app.include_router(endpoints.role.router)
    fastapi_app.include_router(endpoints.tag.router)
    fastapi_app.include_router(endpoints.ssh.router)

    return fastapi_app
