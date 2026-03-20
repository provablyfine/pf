import fastapi.requests
import fastapi.responses
import sqlalchemy.exc

from .. import converters, grant, model, responses, schemas, signature
from ..context import ctx


@signature.verify_session
def list_endpoint(request: fastapi.requests.Request) -> fastapi.responses.Response:
    query = {}
    if "id" in request.query_params:
        query["id"] = int(request.query_params["id"])
    if "name" in request.query_params:
        query["name"] = request.query_params["name"]
    boundaries = model.boundary.read_all(**query)

    grants = grant.Grants.create()
    output = []
    for boundary in boundaries:
        if not grants.boundary(boundary.id).can_read():
            continue
        output.append(boundary)

    converter = converters.GrantConverter()
    return fastapi.responses.JSONResponse(
        status_code=200,
        content=schemas.BoundaryListResponse(
            boundaries=[converters.boundary_to_schema(converter, b) for b in output]
        ).model_dump(),
    )


@signature.verify_session
def create_endpoint(request: fastapi.requests.Request) -> fastapi.responses.Response:
    grants = grant.Grants.create()
    if not grants.boundary(None).can_create():
        return responses.problem_response(status_code=403, title="Not allowed to create boundary")

    data = schemas.BoundaryCreateRequest.model_validate_json(request.state.body)
    try:
        boundary_id = model.boundary.create(
            name=data.name,
            description=data.description,
            ceiling_list=None,
            denied_list=[],
        )
    except sqlalchemy.exc.IntegrityError:
        return responses.problem_response(
            status_code=400,
            title="Boundary already exists. Name must be unique.",
            detail=data.name,
        )

    boundary = model.boundary.read_one(id=boundary_id)
    assert boundary is not None, "Boundary has just need created"
    converter = converters.GrantConverter()
    return fastapi.responses.JSONResponse(
        status_code=201,
        content=schemas.BoundaryCreateResponse(
            boundary=converters.boundary_to_schema(converter, boundary)
        ).model_dump(),
    )


@signature.verify_session
def delete_endpoint(request: fastapi.requests.Request) -> fastapi.responses.Response:
    boundary = model.boundary.read_one(id=request.path_params["boundary_id"])
    if boundary is None:
        return responses.problem_response(status_code=404, title="Boundary not found")
    identity = ctx.db.identity_boundary.read_one(boundary_id=boundary.id)
    if identity is not None:
        return responses.problem_response(status_code=400, title="Boundary is still in use")

    grants = grant.Grants.create()
    if not grants.boundary(boundary.id).can_delete():
        return responses.problem_response(status_code=403, title="Not allowed to delete boundary")

    ctx.db.boundary.delete(id=boundary.id)
    return fastapi.responses.Response(status_code=204)


@signature.verify_session
def update_endpoint(request: fastapi.requests.Request) -> fastapi.responses.Response:
    identity = model.identity.read_one(id=ctx.identity_id)
    assert identity is not None

    boundary = model.boundary.read_one(id=request.path_params["boundary_id"])
    if boundary is None:
        return responses.problem_response(
            status_code=404, title="Boundary does not exist", detail=request.path_params["boundary_id"]
        )

    data = schemas.BoundaryUpdateRequest.model_validate_json(request.state.body)

    grants = grant.Grants.create()
    for field in data.model_fields_set:
        if not grants.boundary(boundary.id).can_update(field):
            return responses.problem_response(
                status_code=403, title="Not allowed to update boundary field", detail=field
            )

    update_query = {}
    converter = converters.GrantConverter()
    if "name" in data.model_fields_set:
        update_query["name"] = data.name
    if "description" in data.model_fields_set:
        update_query["description"] = data.description
    if "denied_list" in data.model_fields_set:
        assert data.denied_list is not None  # pydantic validation guarantees this
        if request.path_params["boundary_id"] in identity.boundary_id_list:
            return responses.problem_response(
                status_code=403, title="Not allowed to update denied list on boundary that applies to self"
            )
        update_query["denied_list"] = [converters.grant_from_schema(converter, g) for g in data.denied_list]
    if "ceiling_list" in data.model_fields_set:
        if request.path_params["boundary_id"] in identity.boundary_id_list:
            return responses.problem_response(
                status_code=403, title="Not allowed to update ceiling list on boundary that applies to self"
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
    model.boundary.update(id=request.path_params["boundary_id"], **update_query)

    boundary = model.boundary.read_one(id=request.path_params["boundary_id"])
    assert boundary is not None  # "We re-read what we read before"
    return fastapi.responses.JSONResponse(
        status_code=200,
        content=schemas.BoundaryUpdateResponse(
            boundary=converters.boundary_to_schema(converter, boundary)
        ).model_dump(),
    )
