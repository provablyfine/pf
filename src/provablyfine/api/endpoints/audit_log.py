import typing

import fastapi

from .. import grant, model, responses, schemas, signature

router = fastapi.APIRouter(prefix="/audit-log", dependencies=[fastapi.Depends(signature.verify_session)])


@router.get("", status_code=200, responses={400: responses.PROBLEM, 403: responses.PROBLEM})
def list_endpoint(
    level: int | None = None,
    object_type: typing.Annotated[list[str] | None, fastapi.Query()] = None,
    action: typing.Annotated[list[str] | None, fastapi.Query()] = None,
    type_prefix: str | None = None,
    by_identity_id: str | None = None,
    start_time: int | None = None,
    end_time: int | None = None,
    ref_type: str | None = None,
    ref_id: str | None = None,
    ref_name: str | None = None,
    order: typing.Literal["asc", "desc"] = "desc",
    limit: typing.Annotated[int, fastapi.Query(ge=1, le=model.audit_log.MAX_LIMIT)] = model.audit_log.DEFAULT_LIMIT,
    cursor: str | None = None,
) -> schemas.audit.AuditLogListResponse:
    """List audit entries, newest first by default.

    Filters apply together. `object_type` and `action` take several values.
    `ref_type` with `ref_id` or `ref_name` finds the entries about one object.
    Follow `next_cursor` to read the next page.
    """
    grants = grant.Grants.create()
    if not grants.audit_log().can_read():
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=403, title="Not allowed to read audit log")
        )
    try:
        page = model.audit_log.read_page(
            level=level,
            object_type=object_type,
            action=action,
            type_prefix=type_prefix,
            by_identity_id=by_identity_id,
            start_time=start_time,
            end_time=end_time,
            ref_type=ref_type,
            ref_id=ref_id,
            ref_name=ref_name,
            descending=order == "desc",
            limit=limit,
            cursor=cursor,
        )
    except model.audit_log.InvalidCursor as e:
        raise responses.ProblemHTTPException(responses.problem_response(status_code=400, title=str(e))) from e
    entries = [
        schemas.audit.AuditLogEntry(
            id=r.id,
            at=r.at,
            level=r.level,
            type=r.type,
            object_type=r.object_type,
            action=r.action,
            by_identity_id=r.by_identity_id,
            by_identity_name=r.by_identity_name,
            refs=[
                schemas.audit.AuditLogRef(type=ref.object_type, id=ref.object_id, name=ref.object_name)
                for ref in page.refs[r.id]
            ],
            details=r.details,
        )
        for r in page.entries
    ]
    return schemas.audit.AuditLogListResponse(entries=entries, next_cursor=page.next_cursor)
