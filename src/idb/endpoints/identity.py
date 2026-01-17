from __future__ import annotations
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


def _read_boundary_ids(boundaries) -> list[int]:
    # This code is definitely more complicated than it should but:
    # - we want to allow users to provide boundaries either as ids or as names
    # - we want to refuse boundaries that do not exist either as ids or as names
    # - we want to refuse boundaries if there are duplicates to help users
    #   detect potential security problems early in case of a typo or something else
    # --> This is painfully complex to do

    # Check that boundaries provided as names exist and are not provided more than once
    boundary_names = [b['name'] for b in boundaries if 'name' in b]
    if len(boundary_names) > 0:
        b_by_name = {b.name: b for b in ctx.db.boundary.read_all(name=boundary_names)}
        if not all(name in b_by_name for name in boundary_names):
            raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='Unable to find boundary'))
        if len(b_by_name) != len(boundary_names):
            raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='A boundary is duplicated'))
    else:
        b_by_name = {}

    # Check that boundaries provided as id exist and are not provided more than once
    boundary_ids = [b['id'] for b in boundaries if 'id' in b]
    if len(boundary_ids) > 0:
        b_by_id = {b.id: b for b in ctx.db.boundary.read_all(id=boundary_ids)}
        if not all(id in b_by_id for id in boundary_ids):
            raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='Unable to find boundary'))
        if len(b_by_id) != len(boundary_ids):
            raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='A boundary is duplicated'))
    else:
        b_by_id = {}

    # Check that we did not provide a boundary more than once, once as an id and once as a name
    for b in b_by_id.values():
        if b.name in b_by_name:
            raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='A boundary is duplicated'))

    additional_boundary_ids = [bid for bid in b_by_id.keys()] + [b.id for b in b_by_name.values()]
    identity = model.identity.read_one(id=ctx.identity_id)
    current_boundary_ids = set(identity.boundary_ids)
    if any(bid in current_boundary_ids for bid in additional_boundary_ids):
        # Technically, we could ignore this silently but we really want the user
        # to notice if this happens.
        raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='One (or more than one) of the additional boundary requested is already enforced'))

    # The line of code below is CRITICAL to our security model.
    # It ensures that identities cannot escape the boundaries that apply to them
    # by creating a new identity with a smaller boundary. The boundaries
    # of newly-created identities are always a superset of the boundaries
    # that apply to the identity that is creating an identity.
    return identity.boundary_ids + additional_boundary_ids


@signature.verify_session
def create(request) -> wa.Response:
    verifier = permission.Verifier()
    permission_request = verifier.identity(None).create()
    if not verifier.is_allowed(permission_request):
        return wa.ProblemResponse(status_code=403, title='Not allowed to create identity')

    data = json.loads(request.body)
    boundary_ids = _read_boundary_ids(data.get('boundaries', []))

    try:
        identity_id = model.identity.create(name=data['name'], boundary_ids=boundary_ids)
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
