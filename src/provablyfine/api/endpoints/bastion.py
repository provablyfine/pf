from __future__ import annotations

import typing

import fastapi
import fastapi.responses

from .. import converters as converter_module
from .. import grant, model, responses, schemas, signature
from ..context import ctx

router = fastapi.APIRouter(prefix="/bastion", dependencies=[fastapi.Depends(signature.verify_session)])

_204 = fastapi.responses.Response(status_code=204)


def _read_tag_ids(tag_id_list: list[int], tag_name_value_list: list[schemas.tag.TagNameValue]) -> list[int]:
    id_list: list[int] = []
    for tag in tag_name_value_list:
        db_tag = ctx.app_db.tag.read_one(name=tag.name, value=tag.value)
        if db_tag is None:
            raise responses.ProblemHTTPException(
                responses.problem_response(status_code=400, title="Request contains invalid field")
            )
        id_list.append(db_tag.id)
    return id_list + tag_id_list


@router.get("", status_code=200, responses={400: responses.PROBLEM, 403: responses.PROBLEM})
def list_endpoint(id: int | None = None) -> schemas.bastion.BastionListResponse:
    query = {}
    if id is not None:
        query["id"] = id
    bastions = model.bastion.read_all(**query)

    grants = grant.Grants.create()
    bastions = [b for b in bastions if grants.bastion(b.id).can_read()]

    return schemas.bastion.BastionListResponse(bastions=converter_module.bastion_list_to_schema(bastions))


@router.post("", status_code=201, responses={400: responses.PROBLEM, 403: responses.PROBLEM})
def create_endpoint(data: schemas.bastion.BastionCreateRequest) -> schemas.bastion.Bastion:
    grants = grant.Grants.create()
    if not grants.bastion(None).can_create():
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=403, title="Not allowed to create bastion")
        )

    tag_ids = _read_tag_ids(data.tag_id_list, data.tag_name_value_list)

    bastion_id = model.bastion.create(
        url=data.url,
        ssh_proxy_jump=data.ssh_proxy_jump,
        tag_id_list=tag_ids,
    )

    bastion = model.bastion.read_one(id=bastion_id)
    assert bastion is not None
    return converter_module.bastion_to_schema(converter_module.GrantConverter(), bastion)


@router.patch(
    "/{bastion_id:int}",
    status_code=200,
    responses={400: responses.PROBLEM, 403: responses.PROBLEM, 404: responses.PROBLEM},
)
def update_endpoint(bastion_id: int, data: schemas.bastion.BastionUpdateRequest) -> schemas.bastion.Bastion:
    bastion = model.bastion.read_one(id=bastion_id)
    if bastion is None:
        raise responses.ProblemHTTPException(responses.problem_response(status_code=404, title="Bastion not found"))

    grants = grant.Grants.create()
    for field in data.model_fields_set:
        checked_field = "tag_list" if field in ("tag_id_list", "tag_name_value_list") else field
        if not grants.bastion(bastion.id).can_update(checked_field):
            raise responses.ProblemHTTPException(
                responses.problem_response(status_code=403, title="Not allowed to update bastion field", detail=field)
            )

    update_params: dict[str, typing.Any] = {}
    if "url" in data.model_fields_set:
        update_params["url"] = data.url
    if "ssh_proxy_jump" in data.model_fields_set:
        update_params["ssh_proxy_jump"] = data.ssh_proxy_jump
    if "tag_id_list" in data.model_fields_set or "tag_name_value_list" in data.model_fields_set:
        tag_ids = _read_tag_ids(data.tag_id_list or [], data.tag_name_value_list or [])
        update_params["tag_id_list"] = tag_ids

    model.bastion.update(id=bastion_id, **update_params)

    bastion = model.bastion.read_one(id=bastion_id)
    assert bastion is not None
    return converter_module.bastion_to_schema(converter_module.GrantConverter(), bastion)


@router.delete(
    "/{bastion_id:int}",
    status_code=204,
    responses={400: responses.PROBLEM, 403: responses.PROBLEM, 404: responses.PROBLEM},
)
def delete_endpoint(bastion_id: int) -> fastapi.responses.Response:
    bastion = model.bastion.read_one(id=bastion_id)
    if bastion is None:
        raise responses.ProblemHTTPException(responses.problem_response(status_code=404, title="Bastion not found"))

    grants = grant.Grants.create()
    if not grants.bastion(bastion.id).can_delete():
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=403, title="Not allowed to delete bastion")
        )

    model.bastion.delete(id=bastion_id)
    return _204
