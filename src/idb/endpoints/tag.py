import json
import sqlalchemy

from .. import signature
from .. import wa
from .. import permission
from .. import model
from ..context import ctx


@signature.verify_session
def list(request) -> wa.Response:
    query = {}
    if 'id' in request.query_params:
        query['id'] = int(request.query_params['id'])
    if 'name' in request.query_params:
        query['name'] = request.query_params['name']
    if 'value' in request.query_params:
        query['value'] = request.query_params['value']
    verifier = permission.Verifier()
    tags = ctx.db.tag.read_all(**query)

    output = []
    for tag in tags:
        request = verifier.create_tag_request(tag=tag, action='read')
        if verifier.is_allowed(request):
            output.append(tag)

    return wa.JSONResponse(
        status_code=200,
        json={'boundaries': [model.tag.serialize(tag) for tag in output]}
    )


@signature.verify_session
def create(request) -> wa.Response:
    pass


@signature.verify_session
def delete(request) -> wa.Response:
    pass


@signature.verify_session
def read(request) -> wa.Response:
    pass


@signature.verify_session
def update(request) -> wa.Response:
    padd
