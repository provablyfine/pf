import json
import sqlalchemy

from ... import wa

from .. import signature
from .. import permission
from .. import model
from ..context import ctx


@signature.verify_session
def list_endpoint(request: wa.Request) -> wa.Response:
    query = {}
    if 'id' in request.query_params:
        query['id'] = int(request.query_params['id'])
    if 'name' in request.query_params:
        query['name'] = request.query_params['name']
    if 'value' in request.query_params:
        query['value'] = request.query_params['value']
    tags = ctx.db.tag.read_all(**query)

    verifier = permission.Verifier()
    output = []
    for tag in tags:
        request = permission.TagChecker(tag.id).read()
        if verifier.is_allowed(request):
            output.append(tag)

    return wa.JSONResponse(
        status_code=200,
        json={'tags': [model.tag.serialize(tag) for tag in output]}
    )


@signature.verify_session
def create_endpoint(request: wa.Request) -> wa.Response:
    verifier = permission.Verifier()
    create_request = permission.TagChecker(None).create()
    if not verifier.is_allowed(create_request):
        return wa.ProblemResponse(status_code=403, title='Not allowed to create tag')

    data = json.loads(request.body)
    try:
        tag_id = ctx.db.tag.create(name=data['name'], value=data['value'])
    except sqlalchemy.exc.IntegrityError:
        return wa.ProblemResponse(status_code=400, title='Tag already exists')
    tag = ctx.db.tag.read_one(id=tag_id)
    return wa.JSONResponse(
        status_code=201,
        json=model.tag.serialize(tag),
    )


@signature.verify_session
def delete_endpoint(request: wa.Request) -> wa.Response:
    tag = ctx.db.tag.read_one(id=request.path_params.tag_id)
    if tag is None:
        return wa.ProblemResponse(status_code=404, title='Tag does not exist')

    verifier = permission.Verifier()
    delete_request = permission.TagChecker(tag.id).delete()
    if not verifier.is_allowed(delete_request):
        return wa.ProblemResponse(status_code=403, title='Not allowed to delete tag')

    ctx.db.tag.delete(id=request.path_params.tag_id)

    return wa.Response(status_code=204)
