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
    if 'name' in request.query_params:
        query['name'] = request.query_params['name']
    if 'id' in request.query_params:
        query['id'] = int(request.query_params['id'])
    verifier = permission.Verifier()
    boundaries = model.boundary.read_all(**query)

    output = []
    for boundary in boundaries:
        request = verifier.create_boundary_request(boundary=boundary, action='read')
        if verifier.is_allowed(request):
            output.append(boundary)

    client_converter = model.permission.to_client()
    return wa.JSONResponse(
        status_code=200,
        json={'boundaries': [model.boundary.serialize(b, client_converter) for b in output]}
    )


@signature.verify_session
def create(request) -> wa.Response:
    data = json.loads(request.body)
    verifier = permission.Verifier()
    permission_request = verifier.create_boundary_request(boundary=None, action='create')
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
    request = verifier.create_boundary_request(boundary=boundary, action='delete')
    if not verifier.is_allowed(request):
        return wa.ProblemResponse(status_code=403, title='Not allowed to delete boundary')
    ctx.db.boundary.delete(id=boundary.id)
    return wa.Response(
        status_code=204
    )


@signature.verify_session
def read(request) -> wa.Response:
    boundary = model.boundary.read_one(id=request.path_params.boundary_id)
    if boundary is None:
        return wa.ProblemResponse(status_code=404, title='Boundary not found')
    verifier = permission.Verifier()
    permission_request = verifier.create_boundary_request(boundary=boundary, action='read')
    if not verifier.is_allowed(permission_request):
        return wa.ProblemResponse(status_code=403, title='Not allowed to read boundary')
    client_converter = model.permission.to_client()
    return wa.JSONResponse(
        status_code=200,
        json=model.boundary.serialize(boundary, client_converter),
    )


@signature.verify_session
def update(request) -> wa.Response:
    data = json.loads(request.body)
    verifier = permission.Verifier()
    boundary = model.boundary.read_one(id=request.path_params.boundary_id)
    for name, value in data.items():
        permission_request = verifier.create_boundary_request(boundary=boundary, action='update', field=name)
        if not verifier.is_allowed(permission_request):
            return wa.ProblemResponse(status_code=403, title='Not allowed to update boundary field', detail=name)
    ctx.db.boundary.update(**data).where(id=request.path_params.boundary_id)
    boundary = model.boundary.read_one(id=request.path_params.boundary_id)
    client_converter = model.permission.to_client()
    return wa.JSONResponse(
        status_code=200,
        json=model.boundary.serialize(boundary, client_converter),
    )
