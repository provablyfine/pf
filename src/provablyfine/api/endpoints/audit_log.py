import typing

import fastapi

from .. import grant, model, responses, schemas, signature

router = fastapi.APIRouter(prefix="/audit-log", dependencies=[fastapi.Depends(signature.verify_session)])


@router.get("/types", status_code=200)
def types_endpoint() -> schemas.audit.AuditLogTypesResponse:
    """The object types and actions that entries can have.

    Any logged in identity may read this, because it needs no audit log permission.
    That is only safe while the answer is the same for every tenant.
    Never put anything in it that comes from a tenant's data.
    """
    return schemas.audit.AuditLogTypesResponse(
        object_types=[
            schemas.audit.AuditLogObjectTypeInfo(object_type=object_type, actions=actions)
            for object_type, actions in sorted(model.audit_types.actions_by_object_type().items())
        ]
    )


@router.get(
    "/objects", status_code=200, responses={400: responses.PROBLEM, 403: responses.PROBLEM, 422: responses.PROBLEM}
)
def objects_endpoint(
    ref_type: model.audit_types.ObjectType,
    ref_name: str,
    order: typing.Literal["asc", "desc"] = "desc",
    limit: typing.Annotated[int, fastapi.Query(ge=1, le=model.audit_log.MAX_LIMIT)] = model.audit_log.DEFAULT_LIMIT,
    cursor: str | None = None,
) -> schemas.audit.AuditLogObjectsResponse:
    """The objects that ever had this name, even if they are deleted or renamed since.

    Use it to find the `ref_id` of the one you mean, when several objects used the same name over time.
    They are ordered by when they first got the name, newest first by default, and paged like the entries.
    Pass `next_cursor` back as `cursor` to read what comes after the page.
    """
    grants = grant.Grants.create()
    if not grants.audit_log().can_read():
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=403, title="Not allowed to read audit log")
        )
    try:
        page = model.audit_log.objects_with_name(
            ref_type, ref_name, descending=order == "desc", limit=limit, cursor=cursor
        )
    except model.audit_log.InvalidCursor as e:
        raise responses.ProblemHTTPException(responses.problem_response(status_code=400, title=str(e))) from e
    return schemas.audit.AuditLogObjectsResponse(
        objects=[
            schemas.audit.AuditLogObject(
                type=model.audit_types.ObjectType(o.object_type),
                id=o.object_id,
                names=o.names,
                first_seen=o.first_seen,
            )
            for o in page.objects
        ],
        next_cursor=page.next_cursor,
        is_last=page.is_last,
    )


@router.get("", status_code=200, responses={400: responses.PROBLEM, 403: responses.PROBLEM, 422: responses.PROBLEM})
def list_endpoint(
    level: int | None = None,
    object_type: typing.Annotated[list[model.audit_types.ObjectType] | None, fastapi.Query()] = None,
    action: typing.Annotated[list[model.audit_types.Action] | None, fastapi.Query()] = None,
    type_prefix: str | None = None,
    by_identity_id: str | None = None,
    by_tenant_id: int | None = None,
    start_time: int | None = None,
    end_time: int | None = None,
    ref_type: model.audit_types.ObjectType | None = None,
    ref_id: str | None = None,
    ref_name: str | None = None,
    ref_follow: bool = False,
    order: typing.Literal["asc", "desc"] = "desc",
    limit: typing.Annotated[int, fastapi.Query(ge=1, le=model.audit_log.MAX_LIMIT)] = model.audit_log.DEFAULT_LIMIT,
    cursor: str | None = None,
) -> schemas.audit.AuditLogListResponse:
    """List audit entries, newest first by default.

    Filters apply together. `by_tenant_id` finds the entries written by an author of that other tenant.
    `object_type` and `action` take several values.
    `ref_type` with `ref_id` or `ref_name` finds the entries about one object.
    With `ref_follow`, `ref_name` finds every object that ever had that name, and all the entries about them,
    even if they were renamed or deleted.
    Pass `next_cursor` back as `cursor` to read what comes after the page.
    `is_last` says that nothing came after it at the time of the query.
    The cursor stays valid, so a reader that has caught up can save it and resume later.
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
            by_tenant_id=by_tenant_id,
            start_time=start_time,
            end_time=end_time,
            ref_type=ref_type,
            ref_id=ref_id,
            ref_name=ref_name,
            ref_follow=ref_follow,
            descending=order == "desc",
            limit=limit,
            cursor=cursor,
        )
    except (model.audit_log.InvalidCursor, model.audit_log.InvalidFilter) as e:
        raise responses.ProblemHTTPException(responses.problem_response(status_code=400, title=str(e))) from e
    entries = [
        schemas.audit.AuditLogEntry(
            id=r.id,
            at=r.at,
            level=r.level,
            type=r.type,
            object_type=model.audit_types.ObjectType(r.object_type),
            action=model.audit_types.Action(r.action),
            by_identity_id=r.by_identity_id,
            by_identity_name=r.by_identity_name,
            by_tenant_id=r.by_tenant_id,
            by_tenant_name=r.by_tenant_name,
            refs=[
                schemas.audit.AuditLogRef(
                    type=model.audit_types.ObjectType(ref.object_type), id=ref.object_id, name=ref.object_name
                )
                for ref in page.refs[r.id]
            ],
            details=r.details,
        )
        for r in page.entries
    ]
    return schemas.audit.AuditLogListResponse(entries=entries, next_cursor=page.next_cursor, is_last=page.is_last)
