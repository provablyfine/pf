import asyncio
import logging
import time

import fastapi
import fastapi.responses
import provablyfine_client as pfc
import provablyfine_client.bastion_visitor as visitor

from .. import grant, model, responses, schemas, signature
from ..context import ctx

logger = logging.getLogger(__name__)

# The host needs a few seconds to end a session. A bastion that does not answer must not hold the request.
_HOST_TIMEOUT_S = 15

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


async def _send_to_first_bastion(urls: list[str], hostname: str, token: str) -> None:
    """Send the command through the first bastion where the host is registered."""
    errors: list[str] = []
    for url in urls:
        try:
            async with asyncio.timeout(_HOST_TIMEOUT_S):
                await visitor.send_command(url, hostname, token)
        except (pfc.exceptions.UI, OSError, EOFError) as e:
            logger.info(f"terminate: bastion={url} did not carry out the command: {e}")
            errors.append(str(e))
            continue
        return
    raise responses.ProblemHTTPException(
        responses.problem_response(
            status_code=502, title=f"Unable to end the session: {errors[-1] if errors else 'no bastion'}"
        )
    )


@router.post(
    "/{id}/terminate",
    status_code=204,
    responses={403: responses.PROBLEM, 404: responses.PROBLEM, 502: responses.PROBLEM},
)
def terminate_endpoint(id: str) -> fastapi.responses.Response:
    grants = grant.Grants.create()
    if not grants.live().can_terminate():
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=403, title="Not allowed to end live sessions")
        )
    row = model.live.read_one(id)
    if row is None or row.ended_at is not None:
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=404, title="Live session does not exist")
        )
    token = model.bastion.generate_terminate_token(row.hostname, row.connection_id, row.kind, row.session_id)
    urls = [b.url for b in model.bastion.read_all()]
    model.audit_log.create(
        "live-session-terminate",
        live_session_id=row.id,
        connection_id=row.connection_id,
        hostname=row.hostname,
        kind=row.kind,
        session_id=row.session_id,
    )
    hostname = row.hostname

    def send() -> None:
        asyncio.run(_send_to_first_bastion(urls, hostname, token))

    # The call to the host is slow, so it waits for the commit.
    ctx.after_commit(send)
    return _204


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
