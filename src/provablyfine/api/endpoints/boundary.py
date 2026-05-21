import typing

import fastapi
import fastapi.responses
import sqlalchemy.exc

from .. import converters, grant, model, responses, schemas, signature
from ..context import ctx

router = fastapi.APIRouter(prefix="/boundary", dependencies=[fastapi.Depends(signature.verify_session)])

_204 = fastapi.responses.Response(status_code=204)


@router.get("", status_code=200, responses={400: responses.PROBLEM, 403: responses.PROBLEM})
def list_endpoint(id: int | None = None, name: str | None = None) -> schemas.boundary.BoundaryListResponse:
    query = {}
    if id is not None:
        query["id"] = id
    if name is not None:
        query["name"] = name
    boundaries = model.boundary.read_all(**query)

    grants = grant.Grants.create()
    output: list[model.boundary.Boundary] = []
    for boundary in boundaries:
        if not grants.boundary(boundary.id).can_read():
            continue
        output.append(boundary)

    converter = converters.GrantConverter()
    return schemas.boundary.BoundaryListResponse(
        boundaries=[converters.boundary_to_schema(converter, b) for b in output]
    )


@router.post("", status_code=201, responses={400: responses.PROBLEM, 403: responses.PROBLEM})
def create_endpoint(data: schemas.boundary.BoundaryCreateRequest) -> schemas.boundary.BoundaryCreateResponse:
    grants = grant.Grants.create()
    if not grants.boundary(None).can_create():
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=403, title="Not allowed to create boundary")
        )

    try:
        boundary_id = model.boundary.create(
            name=data.name,
            description=data.description,
            ceiling_list=None,
            denied_list=[],
        )
    except sqlalchemy.exc.IntegrityError:
        raise responses.ProblemHTTPException(
            responses.problem_response(
                status_code=400,
                title="Boundary already exists. Name must be unique.",
                detail=data.name,
            )
        )

    boundary = model.boundary.read_one(id=boundary_id)
    assert boundary is not None, "Boundary has just need created"
    converter = converters.GrantConverter()
    return schemas.boundary.BoundaryCreateResponse(boundary=converters.boundary_to_schema(converter, boundary))


@router.delete(
    "/{boundary_id:int}",
    status_code=204,
    responses={400: responses.PROBLEM, 403: responses.PROBLEM, 404: responses.PROBLEM},
)
def delete_endpoint(boundary_id: int) -> fastapi.responses.Response:
    boundary = model.boundary.read_one(id=boundary_id)
    if boundary is None:
        raise responses.ProblemHTTPException(responses.problem_response(status_code=404, title="Boundary not found"))
    identity = ctx.app_db.identity_boundary.read_one(boundary_id=boundary.id)
    if identity is not None:
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=400, title="Boundary is still in use")
        )

    grants = grant.Grants.create()
    if not grants.boundary(boundary.id).can_delete():
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=403, title="Not allowed to delete boundary")
        )

    ctx.app_db.boundary.delete(id=boundary.id)
    return _204


@router.patch(
    "/{boundary_id:int}",
    status_code=200,
    responses={400: responses.PROBLEM, 403: responses.PROBLEM, 404: responses.PROBLEM},
)
def update_endpoint(
    boundary_id: int, data: schemas.boundary.BoundaryUpdateRequest
) -> schemas.boundary.BoundaryUpdateResponse:
    identity = model.identity.read_one(id=ctx.identity_id)
    assert identity is not None

    boundary = model.boundary.read_one(id=boundary_id)
    if boundary is None:
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=404, title="Boundary does not exist", detail=str(boundary_id))
        )

    grants = grant.Grants.create()
    for field in data.model_fields_set:
        if not grants.boundary(boundary.id).can_update(field):
            raise responses.ProblemHTTPException(
                responses.problem_response(status_code=403, title="Not allowed to update boundary field", detail=field)
            )

    update_query: dict[str, typing.Any] = {}
    converter = converters.GrantConverter()
    if "name" in data.model_fields_set:
        update_query["name"] = data.name
    if "description" in data.model_fields_set:
        update_query["description"] = data.description
    if "denied_list" in data.model_fields_set:
        assert data.denied_list is not None  # pydantic validation guarantees this
        if boundary_id in identity.boundary_id_list:
            raise responses.ProblemHTTPException(
                responses.problem_response(
                    status_code=403, title="Not allowed to update denied list on boundary that applies to self"
                )
            )
        update_query["denied_list"] = [converters.grant_from_schema(converter, g) for g in data.denied_list]
    if "ceiling_list" in data.model_fields_set:
        if boundary_id in identity.boundary_id_list:
            raise responses.ProblemHTTPException(
                responses.problem_response(
                    status_code=403, title="Not allowed to update ceiling list on boundary that applies to self"
                )
            )
        # We explicitely allow ceiling_list to be null to mean:
        # "no ceiling is set, so nothing is disallowed by the ceiling"
        # which is different from being an empty list which means:
        # "ceiling is set to an empty list so, everything is disallowed by the ceiling"
        update_query["ceiling_list"] = (
            None
            if data.ceiling_list is None
            else [converters.grant_from_schema(converter, g) for g in data.ceiling_list]
        )
    model.boundary.update(id=boundary_id, **update_query)

    boundary = model.boundary.read_one(id=boundary_id)
    assert boundary is not None  # "We re-read what we read before"
    return schemas.boundary.BoundaryUpdateResponse(boundary=converters.boundary_to_schema(converter, boundary))
