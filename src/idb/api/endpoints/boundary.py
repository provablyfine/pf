import json
import sqlalchemy

from ... import wa

from .. import signature
from .. import grant
from .. import model
from ..context import ctx


@signature.verify_session
def list_endpoint(request: wa.Request) -> wa.Response:
    query = {}
    if 'id' in request.query_params:
        query['id'] = int(request.query_params['id'])
    if 'name' in request.query_params:
        query['name'] = request.query_params['name']
    boundaries = model.boundary.read_all(**query)

    grants = grant.Grants.create()
    output = []
    for boundary in boundaries:
        if not grants.boundary(boundary.id).can_read():
            continue
        output.append(boundary)

    serializer = model.grant.ClientSerializer()
    boundaries = [model.boundary.to_client_dict(b, serializer) for b in output]
    return wa.JSONResponse(
        status_code=200,
        json={'boundaries': boundaries},
    )


@signature.verify_session
def create_endpoint(request: wa.Request) -> wa.Response:
    data = json.loads(request.body)
    grants = grant.Grants.create()
    if not grants.boundary(None).can_create():
        return wa.ProblemResponse(status_code=403, title='Not allowed to create boundary')

    try:
        boundary_id = model.boundary.create(
            name=data['name'],
            description=data.get('description'),
            ceiling_list=[],
            denied_list=[],
        )
    except sqlalchemy.exc.IntegrityError:
        return wa.ProblemResponse(status_code=400, title='Boundary already exists. Name must be unique.', detail=data['name'])

    boundary = model.boundary.read_one(id=boundary_id)
    serializer = model.grant.ClientSerializer()
    return wa.JSONResponse(
        status_code=201,
        json=model.boundary.to_client_dict(boundary, serializer),
    )


@signature.verify_session
def delete_endpoint(request: wa.Request) -> wa.Response:
    boundary = model.boundary.read_one(id=request.path_params.boundary_id)
    if boundary is None:
        return wa.ProblemResponse(status_code=404, title='Boundary not found')
    identity = ctx.db.identity_boundary.read_one(boundary_id=boundary.id)
    if identity is not None:
        return wa.ProblemResponse(status_code=400, title='Boundary is still in use')

    grants = grant.Grants.create()
    if not grants.boundary(boundary.id).can_delete():
        return wa.ProblemResponse(status_code=403, title='Not allowed to delete boundary')

    ctx.db.boundary.delete(id=boundary.id)
    return wa.Response(
        status_code=204
    )


@signature.verify_session
def update_endpoint(request: wa.Request) -> wa.Response:
    identity = model.identity.read_one(id=ctx.identity_id)

    boundary = model.boundary.read_one(id=request.path_params.boundary_id)

    data = json.loads(request.body)

    grants = grant.Grants.create()
    for name, value in data.items():
        if not grants.boundary(boundary.id).can_update(name):
            return wa.ProblemResponse(status_code=403, title='Not allowed to update boundary field', detail=name)

    update_query = {}
    deserializer = model.grant.ClientDeserializer()
    if 'name' in data:
        update_query['name'] = data['name']
    if 'description' in data:
        update_query['description'] = data['description']
    if 'denied_list' in data:
        if request.path_params.boundary_id in identity.boundary_id_list:
            return wa.ProblemResponse(status_code=403, title='Not allowed to update denied list on boundary that applies to self')
        update_query['denied_list'] = [model.grant.Grant.from_client_dict(p, deserializer) for p in data['denied_list']]
    if 'ceiling_list' in data:
        if request.path_params.boundary_id in identity.boundary_id_list:
            return wa.ProblemResponse(status_code=403, title='Not allowed to update ceiling list on boundary that applies to self')
        update_query['ceiling_list'] = [model.grant.Grant.from_client_dict(p, deserializer) for p in data['ceiling_list']]
    model.boundary.update(id=request.path_params.boundary_id, **update_query)

    boundary = model.boundary.read_one(id=request.path_params.boundary_id)
    serializer = model.grant.ClientSerializer()
    return wa.JSONResponse(
        status_code=200,
        json=model.boundary.to_client_dict(boundary, serializer),
    )
