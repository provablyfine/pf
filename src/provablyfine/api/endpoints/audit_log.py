import fastapi

from .. import grant, model, responses, schemas, signature

router = fastapi.APIRouter(prefix="/audit-log", dependencies=[fastapi.Depends(signature.verify_session)])


@router.get("", status_code=200, responses={403: responses.PROBLEM})
def list_endpoint(
    level: int | None = None,
    object_type: str | None = None,
    by_identity_id: str | None = None,
    start_time: int | None = None,
    end_time: int | None = None,
) -> schemas.audit.AuditLogListResponse:
    grants = grant.Grants.create()
    if not grants.audit_log().can_read():
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=403, title="Not allowed to read audit log")
        )
    rows = model.audit_log.read_all(level, object_type, by_identity_id, start_time, end_time)
    entries = [
        schemas.audit.AuditLogEntry(
            id=r.id, at=r.at, level=r.level, type=r.type, by_identity_id=r.by_identity_id, details=r.details
        )
        for r in rows
    ]
    return schemas.audit.AuditLogListResponse(entries=entries)
