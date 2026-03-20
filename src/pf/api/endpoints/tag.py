import fastapi.responses
import sqlalchemy.exc

from .. import converters, grant, responses, schemas
from ..context import ctx


def list_endpoint(
    id: int | None = None, name: str | None = None, value: str | None = None
) -> fastapi.responses.Response:
    query = {}
    if id is not None:
        query["id"] = id
    if name is not None:
        query["name"] = name
    if value is not None:
        query["value"] = value
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


def create_endpoint(data: schemas.TagCreateRequest) -> fastapi.responses.Response:
    grants = grant.Grants.create()
    if not grants.tag(None).can_create():
        return responses.problem_response(status_code=403, title="Not allowed to create tag")

    try:
        tag_id = ctx.db.tag.create(name=data.name, value=data.value)
    except sqlalchemy.exc.IntegrityError:
        return responses.problem_response(status_code=400, title="Tag already exists")
    tag = ctx.db.tag.read_one(id=tag_id)
    return fastapi.responses.JSONResponse(
        status_code=201,
        content=converters.tag_to_schema(tag).model_dump(),
    )


def delete_endpoint(tag_id: int) -> fastapi.responses.Response:
    tag = ctx.db.tag.read_one(id=tag_id)
    if tag is None:
        return responses.problem_response(status_code=404, title="Tag does not exist")

    grants = grant.Grants.create()
    if not grants.tag(tag.id).can_delete():
        return responses.problem_response(status_code=403, title="Not allowed to delete tag")

    ctx.db.tag.delete(id=tag_id)

    return fastapi.responses.Response(status_code=204)
