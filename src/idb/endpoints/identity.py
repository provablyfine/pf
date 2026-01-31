from __future__ import annotations
import json
import logging

import sqlalchemy

from .. import signature
from .. import wa
from .. import permission
from .. import model
from ..context import ctx


logger = logging.getLogger(__name__)

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

def _403_tag() -> wa.HTTPException:
    # We purposedly do not return detailed information to the client
    # to make sure we do not leak information that the client should not know
    return wa.HTTPException(wa.ProblemResponse(status_code=403, title='Not allowed to update tag'))

def _read_tag_id_list(tags):
    tag_ids = []
    for tag in tags:
        if 'id' in tag:
            tag_ids.append(tag['id'])
        else:
            db_tag = ctx.db.tag.read_one(name=tag['name'], value=tag['value'])
            if db_tag is None:
                raise _403_tag()
            tag_ids.append(db_tag.id)
    return tag_ids


def _check_set_tags(verifier, permission_request, current_tag_id_list, new_tag_ids):
    current_tag_ids = set(current_tag_id_list)
    added_tag_id_list = list(new_tag_ids.difference(current_tag_ids))
    deleted_tag_id_list = list(current_tag_ids.difference(new_tag_ids))
    _check_add_tags(verifier, permission_request, added_tag_id_list)
    _check_del_tags(verifier, permission_request, deleted_tag_id_list)
    return added_tag_id_list, deleted_tag_id_list


def _check_add_tags(verifier, permission_request, tag_id_list):
    for tag_id in tag_id_list:
        if not verifier.is_allowed(permission_request.add_tag(tag_id)):
            raise _403_tag()


def _check_del_tags(verifier, permission_request, tag_id_list):
    for tag_id in tag_id_list:
        if not verifier.is_allowed(permission_request.del_tag(tag_id)):
            raise _403_tag()


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
        # 1. We need to have native add and del operations because we have an identity:add-tag
        #    permission. If we did not have add and del operations, the client would need to be
        #    able to read the identity before it is able to add tag so, implicitely using the
        #    the add-tag permission would also require using the read permission. We want to make
        #    sure permissions DO NOT DEPEND UPON EACH OTHER
        # 2. I am fully aware that this operation data structure looks a lot like
        #    application/json-patch+json. I decided against bringing in the entire json-patch+json
        #    stuff because this is really a one-off. If we decide to have more operations with
        #    fine-grained set/add/delete, we should reconsider more generally the use of json-patch+json
        new_tag_ids = set(identity.tag_id_list)
        for operation in data['tags']:
            match operation['type']:
                case 'set':
                    new_tag_ids = set(_read_tag_id_list(operation['tags']))
                    _, _ =_check_set_tags(verifier, permission_request, identity.tag_id_list, new_tag_ids)
                case 'add':
                    add_tag_ids = _read_tag_id_list(operation['values'])
                    _check_add_tags(verifier, permission_request, add_tag_ids)
                    new_tag_ids = new_tag_ids.union(set(add_tag_ids))
                case 'del':
                    del_tag_ids = _read_tag_id_list(operation['values'])
                    _check_del_tags(verifier, permission_request, del_tag_ids)
                    new_tag_ids = new_tag_ids.difference(set(del_tag_ids))

        # No, you are not hallucinating, we are checking permissions here
        # even though we did it above. We do this in both locations to catch
        # weird corner cases. For example, if the user wants to delete a tag that
        # is not here and for which the user does not have permission, 
        # we need to check it above to catch it.
        added_tag_id_list, deleted_tag_id_list = _check_set_tags(verifier, permission_request, identity.tag_id_list, new_tag_ids)
        update_params['added_tag_id_list'] = added_tag_id_list
        update_params['deleted_tag_id_list'] = deleted_tag_id_list

    model.identity.update(id=request.path_params.identity_id, **update_params)
    identity = model.identity.read_one(id=request.path_params.identity_id)
    print(model.identity.serialize_one(identity))

    return wa.JSONResponse(
        status_code=200,
        json=model.identity.serialize_one(identity),
    )


@signature.verify_session
def invite_endpoint(request: wa.Request) -> wa.Response:
    identity = model.identity.read_one(id=request.path_params.identity_id)
    delivery = request.query_params['delivery']

    verifier = permission.Verifier()
    permission_request = permission.IdentityChecker(identity.id, identity.tag_id_list, identity.boundary_id_list)
    if not verifier.is_allowed(permission_request.invite(delivery=delivery)):
        return wa.ProblemResponse(status_code=403, title='Not allowed to invite identity', detail=delivery)

    identity_invitation_key_id = model.identity_invitation_key.create(
        identity_id=identity.id,
        # XXX Should be a security policy parameter
        expiration_delay_s=600
    )

    if delivery == 'manual':
        return wa.JSONResponse(
            json=model.identity_invitation_key.format(identity_invitation_key_id),
            status_code=200
        )
    return wa.Response(
        status_code=204,
    )
