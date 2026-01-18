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
    boundaries = model.boundary.read_all(**query)

    output = []
    verifier = permission.Verifier()
    for boundary in boundaries:
        request = verifier.boundary(boundary=boundary).read()
        if verifier.is_allowed(request):
            output.append(boundary)

    client_converter = model.permission.to_client()
    boundaries = [model.boundary.serialize(b, client_converter) for b in output]
    return wa.JSONResponse(
        status_code=200,
        json={'boundaries': boundaries},
    )


@signature.verify_session
def create(request) -> wa.Response:
    data = json.loads(request.body)
    verifier = permission.Verifier()
    permission_request = verifier.boundary(None).create()
    if not verifier.is_allowed(permission_request):
        return wa.ProblemResponse(status_code=403, title='Not allowed to create boundary')

    try:
        boundary_id = model.boundary.create(name=data['name'], description=data.get('description'))
    except sqlalchemy.exc.IntegrityError:
        return wa.ProblemResponse(status_code=400, title='Boundary already exists. Name must be unique.', detail=data['name'])

    boundary = model.boundary.read_one(id=boundary_id)
    client_converter = model.permission.to_client()
    return wa.JSONResponse(
        status_code=201,
        json=model.boundary.serialize(boundary, client_converter),
    )


@signature.verify_session
def delete(request) -> wa.Response:
    boundary = model.boundary.read_one(id=request.path_params.boundary_id)
    if boundary is None:
        return wa.ProblemResponse(status_code=404, title='Boundary not found')
    identity = ctx.db.identity_boundary.read_one(boundary_id=boundary.id)
    if identity is not None:
        return wa.ProblemResponse(status_code=400, title='Unable to delete boundary: it is still in use')

    verifier = permission.Verifier()
    request = verifier.boundary(boundary).delete()
    if not verifier.is_allowed(request):
        return wa.ProblemResponse(status_code=403, title='Not allowed to delete boundary')

    ctx.db.boundary.delete(id=boundary.id)
    return wa.Response(
        status_code=204
    )


@signature.verify_session
def update(request) -> wa.Response:
    identity = model.identity.read_one(ctx.identity_id)
    if request.path_params.boundary_id in identity.boundary_ids:
        return wa.ProblemResponse(status_code=403, title='Not allowed to update boundary that applies to self')

    boundary = model.boundary.read_one(id=request.path_params.boundary_id)

    verifier = permission.Verifier()
    data = json.loads(request.body)
    for name, value in data.items():
        permission_request = verifier.boundary(boundary).update(name)
        if not verifier.is_allowed(permission_request):
            return wa.ProblemResponse(status_code=403, title='Not allowed to update boundary field', detail=name)

    update_query = {}
    from_client = model.permission.from_client()
    if 'name' in data:
        update_query['name'] = data['name']
    if 'description' in data:
        update_query['description'] = data['description']
    if 'denied_list' in data:
        update_query['denied_list'] = [model.permission.deserialize(p, from_client) for p in data['denied_list']]
    if 'ceiling_list' in data:
        update_query['ceiling_list'] = [model.permission.deserialize(p, from_client) for p in data['ceiling_list']]
    model.boundary.update(id=request.path_params.boundary_id, **update_query)

    boundary = model.boundary.read_one(id=request.path_params.boundary_id)
    to_client = model.permission.to_client()
    return wa.JSONResponse(
        status_code=200,
        json=model.boundary.serialize(boundary, to_client),
    )
