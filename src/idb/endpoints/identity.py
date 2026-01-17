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
    if 'tag_id' in request.query_params:
        query['tag_id'] = int(request.query_params['tag_id'])
    if 'tag_name' in request.query_params:
        query['tag_name'] = request.query_params['tag_name']
    if 'boundary_id' in request.query_params:
        query['boundary_id'] = int(request.query_params['boundary_id'])
    if 'boundary_name' in request.query_params:
        query['boundary_name'] = request.query_params['boundary_name']
    identities = model.identity.read_all(**query)

    output = []
    verifier = permission.Verifier()
    for identity in identities:
        request = verifier.identity(identity=identity).read()
        if verifier.is_allowed(request):
            output.append(identity)

    identities_by_id = model.identity.serialize(output)
    return wa.JSONResponse(
        status_code=200,
        json={'identities': [i for i in identities_by_id.values()]},
    )


@signature.verify_session
def create(request) -> wa.Response:
    data = json.loads(request.body)
    verifier = permission.Verifier()
    permission_request = verifier.identity(None).create()
    if not verifier.is_allowed(permission_request):
        return wa.ProblemResponse(status_code=403, title='Not allowed to create identity')

    identity = ctx.db.identity.read_one(id=ctx.identity_id)
    boundary_ids = data.get('boundary_ids', [])
    boundaries = ctx.db.boundary.read_all(id=boundary_ids)
    if len(boundaries) != len(boundary_ids):
        return wa.ProblemResponse(status_code=400, title='Boundary does not exist')
    
    try:
        identity_id = model.identity.create(name=data['name'], boundary_ids=identity.boundary_ids + boundary_ids)
    except sqlalchemy.exc.IntegrityError:
        return wa.ProblemResponse(status_code=400, title='Boundary already exists. Name must be unique.', detail=data['name'])

    identity = model.identity.read_one(id=identity_id)
    return wa.JSONResponse(
        status_code=201,
        json=model.identity.serialize_one(identity),
    )


@signature.verify_session
def delete(request) -> wa.Response:
    identity = model.identity.read_one(id=request.path_params.identity_id)
    if identity is None:
        return wa.ProblemResponse(status_code=404, title='Boundary not found')
    identity = ctx.db.identity_identity.read_one(identity_id=identity.id)
    if identity is not None:
        return wa.ProblemResponse(status_code=400, title='Unable to delete identity: it is still in use')

    verifier = permission.Verifier()
    request = verifier.identity(identity).delete()
    if not verifier.is_allowed(request):
        return wa.ProblemResponse(status_code=403, title='Not allowed to delete identity')

    ctx.db.identity.delete(id=identity.id)
    # XXX: delete all rows in other tables that reference this
    return wa.Response(
        status_code=204
    )


@signature.verify_session
def update(request) -> wa.Response:
    identity = model.identity.read_one(ctx.identity_id)
    if request.path_params.identity_id in identity.identity_ids:
        return wa.ProblemResponse(status_code=403, title='Not allowed to update identity that applies to self')

    identity = model.identity.read_one(id=request.path_params.identity_id)

    # XXX: Must code from scratch
    verifier = permission.Verifier()
    data = json.loads(request.body)
    for name, value in data.items():
        permission_request = verifier.identity(identity).update(name)
        if not verifier.is_allowed(permission_request):
            return wa.ProblemResponse(status_code=403, title='Not allowed to update identity field', detail=name)

    ctx.db.identity.update(**data).where(id=request.path_params.identity_id)
    identity = model.identity.read_one(id=request.path_params.identity_id)

    return wa.JSONResponse(
        status_code=200,
        json=model.identity.serialize_one(identity),
    )
