from __future__ import annotations
import json
import logging

import sqlalchemy.exc

from ... import wa
from ... import schemas

from .. import signature
from .. import grant
from .. import model
from .. import converters
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
    grants = grant.Grants.create()
    for identity in identities:
        if not grants.identity(identity.id, identity.tag_id_list, identity.boundary_id_list).can_read():
            continue
        output.append(identity)

    identities = converters.identity_list_to_schema(output)
    return wa.JSONResponse(
        status_code=200,
        json=schemas.IdentityListResponse(identities=identities).model_dump(),
    )


@signature.verify_session
def read_self_endpoint(request: wa.Request) -> wa.Response:
    identity = model.identity.read_one(id=ctx.identity_id)
    assert identity is not None

    return wa.JSONResponse(
        status_code=200,
        json=converters.identity_to_schema(identity).model_dump(),
    )


def _read_boundary_ids(boundary_id_list: list[int], boundary_name_list: list[str]) -> list[int]:
    # The input schema validator makes sure that the client provides only one non-empty list:
    # either boundary_id_list or boundary_name_list is empty.
    boundaries = ctx.db.boundary.read_all(name=boundary_name_list)
    if len(boundaries) != len(boundary_name_list):
        logger.info(f'No boundary found for one of={boundary_name_list}')
        raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='Request contains invalid fields'))
    return [b.id for b in boundaries] + boundary_id_list


def _read_tag_ids(tag_id_list: list[int], tag_name_value_list: list[schemas.IdentityTagNameValue]) -> list[int]:
    id_list = []
    for tag in tag_name_value_list:
        db_tag = ctx.db.tag.read_one(name=tag.name, value=tag.value)
        if db_tag is None:
            logger.info(f'No tag found for {tag.name}={tag.value}')
            raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='Request contains invalid fields'))
        id_list.append(db_tag.id)
    if len(id_list) != len(tag_name_value_list):
        logger.info(f'No tag found for one of={tag_name_value_list}')
        raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='Request contains invalid fields'))
    return id_list + tag_id_list



@signature.verify_session
def create_endpoint(request: wa.Request) -> wa.Response:
    data = schemas.IdentityCreateRequest.model_validate_json(request.body)
    additional_boundary_ids = _read_boundary_ids(data.boundary_id_list, data.boundary_name_list)
    tag_ids = _read_tag_ids(data.tag_id_list, data.tag_name_value_list)

    grants = grant.Grants.create()
    if not grants.identity().can_create(tag_ids, additional_boundary_ids):
        return wa.ProblemResponse(status_code=403, title='Not allowed to create identity')

    identity = model.identity.read_one(id=ctx.identity_id)
    assert identity is not None
    # The line of code below is CRITICAL to our security model.
    # It ensures that identities cannot escape the boundaries that apply to them
    # by creating a new identity with a smaller boundary. The boundaries
    # of newly-created identities are always a superset of the boundaries
    # that apply to the identity that is creating an identity.
    identity_boundary_ids = identity.boundary_id_list + additional_boundary_ids
    if len(set(identity_boundary_ids)) != len(identity_boundary_ids):
        logger.info('Some boundaries are specified twice, once in the parent boundary and once in the user-requested boundaries')
        return wa.ProblemResponse(status_code=400, title='Request contains invalid fields')
    try:
        identity_id = model.identity.create(name=data.name, boundary_id_list=identity_boundary_ids, tag_id_list=tag_ids)
    except sqlalchemy.exc.IntegrityError:
        return wa.ProblemResponse(status_code=400, title='Identity already exists. Name must be unique.', detail=data.name)

    identity = model.identity.read_one(id=identity_id)
    assert identity is not None
    return wa.JSONResponse(
        status_code=201,
        json=converters.identity_to_schema(identity).model_dump(),
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

    grants = grant.Grants.create()
    if not grants.identity(identity.id, identity.tag_id_list, identity.boundary_id_list).can_delete():
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

def _check_set_tags(permission_request, current_tag_id_list, new_tag_ids):
    current_tag_ids = set(current_tag_id_list)
    added_tag_id_list = list(new_tag_ids.difference(current_tag_ids))
    deleted_tag_id_list = list(current_tag_ids.difference(new_tag_ids))
    _check_add_tags(permission_request, added_tag_id_list)
    _check_del_tags(permission_request, deleted_tag_id_list)
    return added_tag_id_list, deleted_tag_id_list


def _check_add_tags(permission_request, tag_id_list):
    for tag_id in tag_id_list:
        if not permission_request.can_add_tag(tag_id):
            raise _403_tag()


def _check_del_tags(permission_request, tag_id_list):
    for tag_id in tag_id_list:
        if not permission_request.can_del_tag(tag_id):
            raise _403_tag()


@signature.verify_session
def update_endpoint(request: wa.Request) -> wa.Response:
    if request.path_params.identity_id == ctx.identity_id:
        return wa.ProblemResponse(status_code=403, title='Not allowed to update self')

    identity = model.identity.read_one(id=request.path_params.identity_id)
    if identity is None:
        return wa.ProblemResponse(status_code=404, title='Unable to find identity', detail=str(request.path_params.identity_id))

    data = schemas.IdentityUpdateRequest.model_validate_json(request.body)
    grants = grant.Grants.create()
    permission_request = grants.identity(identity.id, identity.tag_id_list, identity.boundary_id_list)
    update_params = {}
    if 'name' in data.model_fields_set:
        if not permission_request.can_update('name'):
            return wa.ProblemResponse(status_code=403, title='Not allowed to update identity field', detail='name')
        update_params['name'] = data.name
    if 'tags' in data.model_fields_set:
        assert data.tags is not None # Guaranteed by "after" pydantic validation
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
        for operation in data.tags:
            match operation.type:
                case 'set':
                    new_tag_ids = set(_read_tag_ids(operation.tag_id_list, operation.tag_name_value_list))
                    _, _ =_check_set_tags(permission_request, identity.tag_id_list, new_tag_ids)
                case 'add':
                    add_tag_ids = _read_tag_ids(operation.tag_id_list, operation.tag_name_value_list)
                    _check_add_tags(permission_request, add_tag_ids)
                    new_tag_ids = new_tag_ids.union(set(add_tag_ids))
                case 'del':
                    del_tag_ids = _read_tag_ids(operation.tag_id_list, operation.tag_name_value_list)
                    _check_del_tags(permission_request, del_tag_ids)
                    new_tag_ids = new_tag_ids.difference(set(del_tag_ids))

        # No, you are not hallucinating, we are checking permissions here
        # even though we did it above. We do this in both locations to catch
        # weird corner cases. For example, if the user wants to delete a tag that
        # is not here and for which the user does not have permission to delete,
        # we need to check it above to catch it.
        added_tag_id_list, deleted_tag_id_list = _check_set_tags(permission_request, identity.tag_id_list, new_tag_ids)
        update_params['added_tag_id_list'] = added_tag_id_list
        update_params['deleted_tag_id_list'] = deleted_tag_id_list

    model.identity.update(id=request.path_params.identity_id, **update_params)
    identity = model.identity.read_one(id=request.path_params.identity_id)
    assert identity is not None

    return wa.JSONResponse(
        status_code=200,
        json=converters.identity_to_schema(identity).model_dump(),
    )


@signature.verify_session
def invite_endpoint(request: wa.Request) -> wa.Response:
    identity = model.identity.read_one(id=request.path_params.identity_id)
    if identity is None:
        return wa.ProblemResponse(status_code=404, title='Unable to find identity', detail=str(request.path_params.identity_id))

    data = schemas.IdentityInviteRequest.model_validate_json(request.body)

    grants = grant.Grants.create()
    if not grants.identity(identity.id, identity.tag_id_list, identity.boundary_id_list).can_invite(data.delivery):
        return wa.ProblemResponse(status_code=403, title='Not allowed to invite identity', detail=data.delivery)

    identity_invitation_key_id = model.identity_invitation_key.create(
        identity_id=identity.id,
        # XXX Should be a security policy parameter
        expiration_delay_s=600
    )
    identity_invitation = model.identity_invitation_key.read(identity_invitation_key_id)
    assert identity_invitation is not None # We just created it

    if data.delivery == 'manual':
        return wa.JSONResponse(
            json=schemas.IdentityInviteManualResponse(key=converters.symmetric_to_schema(identity_invitation.key)).model_dump(),
            status_code=200
        )
    return wa.Response(
        status_code=204,
    )
