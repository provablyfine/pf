import time

import fastapi
import fastapi.responses

from .. import grant, model, responses, schemas, signature
from ..context import ctx

router = fastapi.APIRouter(prefix="/live", dependencies=[fastapi.Depends(signature.verify_session)])

# The reports of a host about its own sessions. Hosts sign them with their own identity.
report_router = fastapi.APIRouter(
    prefix="/identity/self/live", dependencies=[fastapi.Depends(signature.verify_session)]
)

_204 = fastapi.responses.Response(status_code=204)


@router.get("", status_code=200, responses={403: responses.PROBLEM})
def list_endpoint(
    hostname: str | None = None,
    identity_id: int | None = None,
    active: bool | None = None,
) -> schemas.live.LiveListResponse:
    grants = grant.Grants.create()
    if not grants.live().can_read():
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=403, title="Not allowed to read live sessions")
        )
    rows = model.live.read_all(hostname=hostname, identity_id=identity_id, active=active)
    return schemas.live.LiveListResponse(
        sessions=[
            schemas.live.LiveSession(
                id=r.id,
                connection_id=r.connection_id,
                identity_id=r.identity_id,
                hostname=r.hostname,
                kind="relay" if r.kind == "relay" else "host",
                session_id=r.session_id,
                started_at=r.started_at,
                ended_at=r.ended_at,
                deadline=r.deadline,
            )
            for r in rows
        ]
    )


def _caller_hostname() -> str:
    caller = model.identity.read_one(id=ctx.identity_id)
    assert caller is not None  # because we are authenticated
    return caller.name


@report_router.post("/start", status_code=204, responses={403: responses.PROBLEM})
def start_endpoint(data: schemas.live.LiveReportRequest) -> fastapi.responses.Response:
    try:
        model.live.start(
            connection_id=data.connection_id,
            hostname=_caller_hostname(),
            kind=data.kind,
            session_id=data.session_id,
            at=min(data.at, int(time.time())),
        )
    except model.live.UnknownConnection:
        raise responses.ProblemHTTPException(responses.problem_response(status_code=403, title="Forbidden"))
    return _204


@report_router.post("/end", status_code=204, responses={403: responses.PROBLEM})
def end_endpoint(data: schemas.live.LiveReportRequest) -> fastapi.responses.Response:
    try:
        model.live.end(
            connection_id=data.connection_id,
            hostname=_caller_hostname(),
            kind=data.kind,
            session_id=data.session_id,
            at=min(data.at, int(time.time())),
        )
    except model.live.UnknownConnection:
        raise responses.ProblemHTTPException(responses.problem_response(status_code=403, title="Forbidden"))
    return _204
