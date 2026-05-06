from __future__ import annotations

import fastapi
import fastapi.responses

from .. import converters as converter_module
from .. import model, responses, schemas, signature
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
def list_endpoint() -> schemas.bastion.BastionListResponse:
    bastions = model.bastion.read_all()
    return schemas.bastion.BastionListResponse(bastions=converter_module.bastion_list_to_schema(bastions))


@router.post("", status_code=201, responses={400: responses.PROBLEM, 403: responses.PROBLEM})
def create_endpoint(data: schemas.bastion.BastionCreateRequest) -> schemas.bastion.Bastion:
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

    tag_ids: list[int] | None = None
    if data.tag_name_value_list is not None or data.tag_id_list is not None:
        tag_ids = _read_tag_ids(data.tag_id_list or [], data.tag_name_value_list or [])

    model.bastion.update(
        id=bastion_id,
        url=data.url,
        ssh_proxy_jump=data.ssh_proxy_jump,
        tag_id_list=tag_ids,
    )

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

    model.bastion.delete(id=bastion_id)
    return _204
