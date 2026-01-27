from __future__ import annotations
import json
import sqlalchemy

from .. import signature
from .. import wa
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
        permission_request = permission.IdentityChecker(identity.id, identity.tag_id_list, identity.boundary_id_list).read()
        if verifier.is_allowed(permission_request):
            output.append(identity)

    identities_by_id = model.identity.serialize(output)
    return wa.JSONResponse(
        status_code=200,
        json={'identities': [i for i in identities_by_id.values()]},
    )


def _read_boundary_ids(boundaries) -> list[int]:
    boundary_id_list = []
    for boundary in boundaries:
        if 'id' in boundary:
            db_boundary = ctx.db.boundary.read_one(id=boundary['id'])
            if db_boundary is None:
                raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='Request contains invalid fields'))
            boundary_id_list.append(boundary['id'])
        else:
            if not 'name' in boundary:
                raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='Boundary is missing a name', detail=str(boundary)))
            db_boundary = ctx.db.boundary.read_one(name=boundary['name'])
            if db_boundary is None:
                raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='Request contains invalid fields'))
            boundary_id_list.append(db_boundary.id)
    if len(set(boundary_id_list)) != len(boundary_id_list):
        raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='Request contains invalid fields'))
    return boundary_id_list



def _read_tag_ids(tags) -> list[int]:
    tag_id_list = []
    for tag in tags:
        if 'id' in tag:
            db_tag = ctx.db.tag.read_one(id=tag['id'])
            if db_tag is None:
                raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='Request contains invalid fields'))
            tag_id_list.append(tag['id'])
        else:
            if 'name' not in tag or 'value' not in tag:
                raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='Tag is missing a name or value', detail=str(tag)))
            db_tag = ctx.db.tag.read_one(name=tag['name'], value=tag['value'])
            if db_tag is None:
                raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='Request contains invalid fields'))
            tag_id_list.append(db_tag.id)
    if len(set(tag_id_list)) != len(tag_id_list):
        raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='Request contains invalid fields'))
    return tag_id_list



@signature.verify_session
def create_endpoint(request: wa.Request) -> wa.Response:
    data = json.loads(request.body)
    additional_boundary_ids = _read_boundary_ids(data.get('boundaries', []))
    tag_ids = _read_tag_ids(data.get('tags', []))

    verifier = permission.Verifier()
    permission_request = permission.IdentityChecker(None, tag_id_list=tag_ids, boundary_id_list=additional_boundary_ids).create()
    if not verifier.is_allowed(permission_request):
        return wa.ProblemResponse(status_code=403, title='Not allowed to create identity')

    # The line of code below is CRITICAL to our security model.
    # It ensures that identities cannot escape the boundaries that apply to them
    # by creating a new identity with a smaller boundary. The boundaries
    # of newly-created identities are always a superset of the boundaries
    # that apply to the identity that is creating an identity.
    identity = model.identity.read_one(id=ctx.identity_id)
    identity_boundary_ids = identity.boundary_id_list + additional_boundary_ids
    try:
        identity_id = model.identity.create(name=data['name'], boundary_id_list=identity_boundary_ids, tag_id_list=tag_ids)
    except sqlalchemy.exc.IntegrityError:
        return wa.ProblemResponse(status_code=400, title='Boundary already exists. Name must be unique.', detail=data['name'])

    identity = model.identity.read_one(id=identity_id)
    return wa.JSONResponse(
        status_code=201,
        json=model.identity.serialize_one(identity),
    )


@signature.verify_session
def delete_endpoint(request: wa.Request) -> wa.Response:
    identity = model.identity.read_one(id=request.path_params.identity_id)
    if identity is None:
        return wa.ProblemResponse(status_code=404, title='Boundary not found')
    if ctx.identity_id == request.path_params.identity_id:
        return wa.ProblemResponse(status_code=400, title='You cannot delete yourself')
    # XXX: Should we check that this identity cannot be deleted because
    # someone depends on it in some way ?

    verifier = permission.Verifier()
    permission_request = permission.IdentityChecker(identity.id, identity.tag_id_list, identity.boundary_id_list).delete()
    if not verifier.is_allowed(permission_request):
        return wa.ProblemResponse(status_code=403, title='Not allowed to delete identity')

    ctx.db.identity.delete(id=identity.id)
    # XXX: delete all rows in other tables that reference this
    return wa.Response(
        status_code=204
    )


@signature.verify_session
def update_endpoint(request: wa.Request) -> wa.Response:
    if request.path_params.identity_id == ctx.identity_id:
        return wa.ProblemResponse(status_code=403, title='Not allowed to update self')

    identity = model.identity.read_one(id=request.path_params.identity_id)

    verifier = permission.Verifier()
    data = json.loads(request.body)
    permission_request = permission.IdentityChecker(identity.id, identity.tag_id_list, identity.boundary_id_list)
    update_params = {}
    if 'name' in data:
        if not verifier.is_allowed(permission_request.update('name')):
            return wa.ProblemResponse(status_code=403, title='Not allowed to update identity field', detail='name')
        update_params['name'] = data['name']
    if 'tags' in data:
        tag_ids = []
        for tag in data['tags']:
            if 'id' in tag:
                tag_ids.append(tag['id'])
            else:
                db_tag = ctx.db.tag.read_one(name=tag['name'], value=tag['value'])
                if db_tag is None:
                    return wa.ProblemResponse(status_code=400, title='Tag does not exist', detail=f'{tag["name"]}={tag["value"]}')
                tag_ids.append(db_tag.id)
        new_tag_ids = set(tag_ids)
        current_tag_ids = set(identity.tag_id_list)
        added_tag_ids = new_tag_ids.difference(current_tag_ids)
        deleted_tag_ids = current_tag_ids.difference(new_tag_ids)
        for tag_id in added_tag_ids:
            if not verifier.is_allowed(permission_request.add_tag(tag_id)):
                return wa.ProblemResponse(status_code=403, title='Not allowed to add tag to identity', detail=tag_id)
        for tag_id in deleted_tag_ids:
            if not verifier.is_allowed(permission_request.del_tag(tag_id)):
                return wa.ProblemResponse(status_code=403, title='Not allowed to delete tag from identity', detail=tag_id)
        update_params['added_tag_id_list'] = list(added_tag_ids)
        update_params['deleted_tag_id_list'] = list(deleted_tag_ids)

    model.identity.update(id=request.path_params.identity_id, **update_params)
    identity = model.identity.read_one(id=request.path_params.identity_id)

    return wa.JSONResponse(
        status_code=200,
        json=model.identity.serialize_one(identity),
    )
