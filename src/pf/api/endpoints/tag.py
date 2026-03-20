import fastapi.requests
import fastapi.responses
import sqlalchemy.exc

from .. import converters, grant, responses, schemas, signature
from ..context import ctx


@signature.verify_session
def list_endpoint(request: fastapi.requests.Request) -> fastapi.responses.Response:
    query = {}
    if "id" in request.query_params:
        query["id"] = int(request.query_params["id"])
    if "name" in request.query_params:
        query["name"] = request.query_params["name"]
    if "value" in request.query_params:
        query["value"] = request.query_params["value"]
    tags = ctx.db.tag.read_all(**query)

    grants = grant.Grants.create()
    output = []
    for tag in tags:
        if not grants.tag(tag.id).can_read():
            continue
        output.append(tag)

    return fastapi.responses.JSONResponse(
        status_code=200,
        content=schemas.TagListResponse(tags=[converters.tag_to_schema(tag) for tag in output]).model_dump(),
    )


@signature.verify_session
def create_endpoint(request: fastapi.requests.Request) -> fastapi.responses.Response:
    grants = grant.Grants.create()
    if not grants.tag(None).can_create():
        return responses.problem_response(status_code=403, title="Not allowed to create tag")

    data = schemas.TagCreateRequest.model_validate_json(request.state.body)
    try:
        tag_id = ctx.db.tag.create(name=data.name, value=data.value)
    except sqlalchemy.exc.IntegrityError:
        return responses.problem_response(status_code=400, title="Tag already exists")
    tag = ctx.db.tag.read_one(id=tag_id)
    return fastapi.responses.JSONResponse(
        status_code=201,
        content=converters.tag_to_schema(tag).model_dump(),
    )


@signature.verify_session
def delete_endpoint(request: fastapi.requests.Request) -> fastapi.responses.Response:
    tag = ctx.db.tag.read_one(id=request.path_params["tag_id"])
    if tag is None:
        return responses.problem_response(status_code=404, title="Tag does not exist")

    grants = grant.Grants.create()
    if not grants.tag(tag.id).can_delete():
        return responses.problem_response(status_code=403, title="Not allowed to delete tag")

    ctx.db.tag.delete(id=request.path_params["tag_id"])

    return fastapi.responses.Response(status_code=204)
