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

from .. import base64url, jwk
from . import converters, crypto_policy, db, endpoints, middleware, model, responses, schemas, signature
from .context import ctx

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


def directory_endpoint() -> fastapi.responses.Response:
    return fastapi.responses.JSONResponse(
        status_code=200,
        content=schemas.DirectoryReadResponse(
            initialize=f"{ctx.config.base_url}/pf/initialize",
            accept_invitation=f"{ctx.config.base_url}/pf/accept-invitation",
            login=f"{ctx.config.base_url}/pf/login",
            boundary=f"{ctx.config.base_url}/pf/boundary",
            tag=f"{ctx.config.base_url}/pf/tag",
            role=f"{ctx.config.base_url}/pf/role",
            identity=f"{ctx.config.base_url}/pf/identity",
            ssh=f"{ctx.config.base_url}/pf/ssh",
        ).model_dump(),
    )


def _create_keys(key_type: db.SigningKeyType, crypto_key_type: jwk.KeyType, rotation_period: int, staging_period: int):
    now = int(time.time())

    # Create a  "current" key
    current_start = now - staging_period - 10
    current_end = current_start + rotation_period
    model.signing_key.create(
        key_type,
        crypto_key_type,
        valid_after=current_start,
        valid_before=current_end,
    )
    # Create a  "staged" key
    staged_start = current_end - staging_period
    staged_end = staged_start + rotation_period
    model.signing_key.create(
        key_type,
        crypto_key_type,
        valid_after=staged_start,
        valid_before=staged_end,
    )


def initialize_endpoint() -> fastapi.responses.Response:
    one = ctx.db.identity.read_one()
    if one is not None:
        return fastapi.responses.Response(status_code=204)

    _create_keys(
        db.SigningKeyType.HOST,
        jwk.KeyType.from_string(ctx.config.host_key_type),
        ctx.config.host_key_rotation_period,
        ctx.config.host_key_staging_period,
    )
    _create_keys(
        db.SigningKeyType.USER,
        jwk.KeyType.from_string(ctx.config.user_key_type),
        ctx.config.user_key_rotation_period,
        ctx.config.user_key_staging_period,
    )

    root_boundary_id = model.boundary.create(
        name="root",
        description="The Root boundary is not a boundary at all.",
        ceiling_list=None,
        denied_list=[],
    )
    root_id = model.identity.create(
        name="root",
        boundary_id_list=[root_boundary_id],
        tag_id_list=[],
    )
    identity_grant_all = model.grant.IdentityGrant(
        filter=model.grant.IdentityFilter(id=None, tag_id_list=None, boundary_id_list=None),
        permission=model.grant.IdentityPermission(
            create=model.grant.IdentityCreatePermission(
                allowed=True, allowed_tag_id_list=None, required_boundary_id_list=None
            ),
            read=True,
            update=None,
            delete=True,
            add_tag_id_list=None,
            del_tag_id_list=None,
            invite_list=None,
        ),
    )
    ssh_grant_all = model.grant.SSHGrant(
        filter=model.grant.SSHFilter(id=None, tag_id_list=None, boundary_id_list=None),
        permission=model.grant.SSHPermission(
            force_command_list=None,
            username_list=None,
            permit_pty=True,
            permit_user_rc=True,
            permit_x11_forwarding=True,
            permit_agent_forwarding=True,
            permit_port_forwarding=True,
        ),
    )
    tag_grant_all = model.grant.TagGrant(
        filter=model.grant.TagFilter(id=None),
        permission=model.grant.TagPermission(
            create=True,
            read=True,
            delete=True,
        ),
    )
    role_grant_all = model.grant.RoleGrant(
        filter=model.grant.RoleFilter(id=None),
        permission=model.grant.RolePermission(
            create=True,
            read=True,
            update=None,
            delete=True,
        ),
    )
    boundary_grant_all = model.grant.BoundaryGrant(
        filter=model.grant.BoundaryFilter(id=None),
        permission=model.grant.BoundaryPermission(
            create=True,
            read=True,
            update=None,
            delete=True,
        ),
    )
    all_grants = [
        identity_grant_all,
        ssh_grant_all,
        tag_grant_all,
        role_grant_all,
        boundary_grant_all,
    ]
    root_role_id = model.role.create(
        name="root",
        description=(
            'The "root" role identifies a user that is able to do anything. '
            "It is created once at startup and should be deleted once a proper "
            "permission model is deployed."
        ),
        grant_list=all_grants,
    )
    ctx.db.role_member.create(role_id=root_role_id, identity_id=root_id)

    identity_invitation_key_id = model.identity_invitation_key.create(identity_id=root_id, expiration_delay_s=600)
    identity_invitation = model.identity_invitation_key.read(identity_invitation_key_id)
    assert identity_invitation is not None, "key has just need created so it cannot possibly be None"

    return fastapi.responses.JSONResponse(
        content=schemas.InitializeResponse(key=converters.symmetric_to_schema(identity_invitation.key)).model_dump(),
        status_code=200,
    )


def accept_invitation_endpoint(
    request: fastapi.requests.Request, data: schemas.AcceptInvitationRequest
) -> fastapi.responses.Response:
    account_key = converters.public_from_schema(data.account_public_key)
    crypto_policy.enforce_key_is_allowed(account_key)

    model.denylist.enforce_not_denied(account_key.thumbprint())

    # we can do the signature verification for the public account key
    signature.verify(request, f"account:{account_key.thumbprint()}", account_key)

    # if invitation has been accepted already, we do some checking to detect malevolent clients
    if ctx.invitation.is_accepted:
        if ctx.invitation.accepted_public_key_id == account_key.thumbprint():
            # The same key already accepted this invitation. This is probably some
            # kind of client-side or proxy retry
            return fastapi.responses.Response(status_code=204)
        else:
            model.denylist.create(
                key_id=account_key.thumbprint(),
                identity_invitation_id=ctx.invitation.id,
            )
            return responses.problem_response(status_code=403, title="Invitation was already accepted")

    # all verification passed. Bind the public account key with the identity
    # that was configured in the invitation.
    model.identity_invitation_key.accept(
        id=ctx.invitation.id,
        public_key_id=account_key.thumbprint(),
    )
    now = int(time.time())
    ctx.db.identity_account_key.create(
        id=account_key.thumbprint(),
        public_key=account_key.to_dict(),
        identity_id=ctx.identity_id,
        created_at=now,
        is_revoked=False,
        revoked_at=None,
    )
    return fastapi.responses.Response(status_code=204)


def login_endpoint(request: fastapi.requests.Request, data: schemas.LoginRequest) -> fastapi.responses.Response:
    session_key = converters.public_from_schema(data.session_public_key)
    crypto_policy.enforce_key_is_allowed(session_key)

    model.denylist.enforce_not_denied(session_key.thumbprint())

    # we can do the signature verification for the public session key
    signature.verify(request, f"session:{session_key.thumbprint()}", session_key)

    # all verification passed. Bind the public session key with the identity
    # that was configured in the account
    now = int(time.time())
    ctx.db.identity_session_key.create(
        id=session_key.thumbprint(),
        public_key=session_key.to_dict(),
        identity_id=ctx.identity_id,
        created_at=now,
        is_revoked=False,
        revoked_at=None,
        expires_at=now + ctx.config.session_duration_s,
    )

    return fastapi.responses.Response(status_code=204)


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

    fastapi_app = fastapi.FastAPI(lifespan=lifespan)

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

    @fastapi_app.get("/debug/{debug_id}")
    def debug_endpoint(debug_id: str, request: fastapi.requests.Request) -> fastapi.responses.Response:
        data = request.app.state.debug_store.get(debug_id)
        if data is None:
            return responses.problem_response(
                status_code=404, title="Debug data could not be found", detail=f"Missing {debug_id}"
            )
        return fastapi.responses.JSONResponse(status_code=200, content=data)

    fastapi_app.add_api_route("/pf/directory", directory_endpoint, methods=["GET"])
    fastapi_app.add_api_route("/pf/initialize", initialize_endpoint, methods=["POST"])
    fastapi_app.add_api_route(
        "/pf/accept-invitation",
        accept_invitation_endpoint,
        methods=["POST"],
        dependencies=[fastapi.Depends(signature.verify_invitation)],
    )
    fastapi_app.add_api_route(
        "/pf/login",
        login_endpoint,
        methods=["POST"],
        dependencies=[fastapi.Depends(signature.verify_account)],
    )
    fastapi_app.include_router(endpoints.boundary.router)
    fastapi_app.include_router(endpoints.identity.router)
    fastapi_app.include_router(endpoints.role.router)
    fastapi_app.include_router(endpoints.tag.router)
    fastapi_app.include_router(endpoints.ssh.router)

    return fastapi_app
