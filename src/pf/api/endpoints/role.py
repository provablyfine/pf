import fastapi
import fastapi.responses
import sqlalchemy.exc

from .. import converters, grant, model, responses, schemas, signature
from ..context import ctx

router = fastapi.APIRouter(prefix="/pf/role", dependencies=[fastapi.Depends(signature.verify_session)])

_204 = fastapi.responses.Response(status_code=204)


@router.get("", status_code=200, responses={400: responses.PROBLEM, 403: responses.PROBLEM})
def list_endpoint(name: str | None = None, id: int | None = None) -> schemas.RoleListResponse:
    query = {}
    if name is not None:
        query["name"] = name
    if id is not None:
        query["id"] = id
    roles = model.role.read_all(**query)

    output = []
    grants = grant.Grants.create()
    for role in roles:
        if not grants.role(role.id).can_read():
            continue
        output.append(role)

    converter = converters.GrantConverter()
    return schemas.RoleListResponse(roles=[converters.role_to_schema(converter, r) for r in output])


@router.post("", status_code=201, responses={400: responses.PROBLEM, 403: responses.PROBLEM})
def create_endpoint(data: schemas.RoleCreateRequest) -> schemas.Role:
    grants = grant.Grants.create()
    if not grants.role(None).can_create():
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=403, title="Not allowed to create role")
        )

    try:
        role_id = model.role.create(name=data.name, description=data.description, grant_list=[])
    except sqlalchemy.exc.IntegrityError:
        raise responses.ProblemHTTPException(
            responses.problem_response(
                status_code=400, title="Role already exists. Name must be unique.", detail=data.name
            )
        )

    role = model.role.read_one(id=role_id)
    assert role is not None  # we just created it

    converter = converters.GrantConverter()
    return converters.role_to_schema(converter, role)


@router.delete(
    "/{role_id:int}",
    status_code=204,
    responses={400: responses.PROBLEM, 403: responses.PROBLEM, 404: responses.PROBLEM},
)
def delete_endpoint(role_id: int) -> fastapi.responses.Response:
    role = model.role.read_one(id=role_id)
    if role is None:
        raise responses.ProblemHTTPException(responses.problem_response(status_code=404, title="Role not found"))

    grants = grant.Grants.create()
    if not grants.role(role.id).can_delete():
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=403, title="Not allowed to delete role")
        )

    member = ctx.db.role_member.read_one(role_id=role.id)
    if member is not None:
        raise responses.ProblemHTTPException(responses.problem_response(status_code=400, title="Role is still in use"))

    ctx.db.role.delete(id=role.id)
    return _204


@router.patch(
    "/{role_id:int}",
    status_code=200,
    responses={400: responses.PROBLEM, 403: responses.PROBLEM, 404: responses.PROBLEM},
)
def update_endpoint(role_id: int, data: schemas.RoleUpdateRequest) -> schemas.Role:
    role = model.role.read_one(id=role_id)
    if role is None:
        raise responses.ProblemHTTPException(responses.problem_response(status_code=404, title="Role not found"))

    grants = grant.Grants.create()
    for field_name in data.model_fields_set:
        if not grants.role(role.id).can_update(field_name):
            raise responses.ProblemHTTPException(
                responses.problem_response(status_code=403, title="Not allowed to update role field", detail=field_name)
            )

    converter = converters.GrantConverter()
    role_update = {}
    if "name" in data.model_fields_set and data.name != role.name:
        role_update["name"] = data.name
    if "description" in data.model_fields_set and data.description != role.description:
        role_update["description"] = data.description
    if "grant_list" in data.model_fields_set:
        assert data.grant_list is not None  # pydantic validation guarantees this
        if ctx.identity_id in role.member_id_list:
            raise responses.ProblemHTTPException(
                responses.problem_response(
                    status_code=403, title="Not allowed to update grants on a role that applies to self"
                )
            )
        role_update["grant_list"] = [converters.grant_from_schema(converter, g) for g in data.grant_list]
    if "member_list" in data.model_fields_set:
        assert data.member_list is not None  # pydantic validation guarantees this
        members = ctx.db.identity.read_all(name=[m.name for m in data.member_list])
        member_by_name = {m.name: m for m in members}
        unresolved_members = [m.name for m in data.member_list if m.name not in member_by_name]
        if len(unresolved_members) > 0:
            raise responses.ProblemHTTPException(
                responses.problem_response(
                    status_code=400, title="Unable to resolve members", detail=", ".join(unresolved_members)
                )
            )
        new_member_id_list = set(member_by_name[m.name].id for m in data.member_list)
        current_member_id_list = set(role.member_id_list)
        deleted_member_id_list = current_member_id_list.difference(new_member_id_list)
        added_member_id_list = new_member_id_list.difference(current_member_id_list)
        if ctx.identity_id in deleted_member_id_list:
            raise responses.ProblemHTTPException(
                responses.problem_response(status_code=403, title="Not allowed to remove self from role")
            )
        role_update["added_member_id_list"] = list(added_member_id_list)
        role_update["deleted_member_id_list"] = list(deleted_member_id_list)
    model.role.update(role.id, **role_update)

    role = model.role.read_one(id=role_id)
    assert role is not None  # We just updated it

    return converters.role_to_schema(converter, role)
