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
    roles = model.role.read_all(**query)

    output = []
    verifier = permission.Verifier()
    for role in roles:
        request = verifier.role(role=role).read()
        if verifier.is_allowed(request):
            output.append(role)

    client_converter = model.permission.to_client()
    roles = [model.role.serialize(b, client_converter) for b in output]
    return wa.JSONResponse(
        status_code=200,
        json={'roles': roles},
    )


@signature.verify_session
def create(request) -> wa.Response:
    verifier = permission.Verifier()
    permission_request = verifier.role(None).create()
    if not verifier.is_allowed(permission_request):
        return wa.ProblemResponse(status_code=403, title='Not allowed to create role')

    data = json.loads(request.body)
    try:
        role_id = model.role.create(name=data['name'], description=data.get('description'), permission_list=[])
    except sqlalchemy.exc.IntegrityError:
        return wa.ProblemResponse(status_code=400, title='Role already exists. Name must be unique.', detail=data['name'])

    role = model.role.read_one(id=role_id)
    client_converter = model.permission.to_client()
    return wa.JSONResponse(
        status_code=201,
        json=model.role.serialize(role, client_converter),
    )


@signature.verify_session
def delete(request) -> wa.Response:
    role = model.role.read_one(id=request.path_params.role_id)
    if role is None:
        return wa.ProblemResponse(status_code=404, title='Role not found')

    verifier = permission.Verifier()
    request = verifier.role(role).delete()
    if not verifier.is_allowed(request):
        return wa.ProblemResponse(status_code=403, title='Not allowed to delete role')

    member = ctx.db.role_member.read_one(role_id=role.id)
    if member is not None:
        return wa.ProblemResponse(status_code=400, title='Unable to delete role: it is still in use')

    ctx.db.role.delete(id=role.id)
    return wa.Response(
        status_code=204
    )


@signature.verify_session
def update(request) -> wa.Response:
    role_ids = [member.role_id for member in ctx.db.role_member.read_all(identity_id=ctx.identity_id)]
    if request.path_params.role_id in role_ids:
        return wa.ProblemResponse(status_code=403, title='Not allowed to update role that applies to self')

    role = model.role.read_one(id=request.path_params.role_id)

    data = json.loads(request.body)
    verifier = permission.Verifier()
    for field_name, value in data.items():
        permission_request = verifier.role(role).update(field_name)
        if not verifier.is_allowed(permission_request):
            return wa.ProblemResponse(status_code=403, title='Not allowed to update role field', detail=field_name)

    role_update = {}
    if 'description' in data:
        role_update['description'] = data['description']
    if 'permissions' in data:
        from_client = model.permission.from_client()
        permission_list = [model.permission.Grant.from_dict(p) for p in data['permissions']]
        role_update['permission_list'] = [from_client.convert(p) for p in permission_list]
    if 'members' in data:
        role_update['member_id_list'] = [m['id'] for m in data['members']]

    model.role.update(role, **role_update)
    role = model.role.read_one(id=request.path_params.role_id)

    to_client = model.permission.to_client()
    return wa.JSONResponse(
        status_code=200,
        json=model.role.serialize(role, to_client),
    )

