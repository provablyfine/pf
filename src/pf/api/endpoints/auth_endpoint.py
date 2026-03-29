import fastapi
import fastapi.responses
import sqlalchemy.exc

from .. import converters, grant, model, responses, schemas, signature

router = fastapi.APIRouter(prefix="/auth", dependencies=[fastapi.Depends(signature.verify_session)])

_204 = fastapi.responses.Response(status_code=204)


def _build_config(data: schemas.AuthCreateRequest) -> dict:
    if data.type == "oidc":
        assert data.oidc_params is not None
        config: dict = {"issuer": data.oidc_params.issuer, "client_id": data.oidc_params.client_id}
        if data.oidc_params.client_secret is not None:
            config["client_secret"] = data.oidc_params.client_secret
        return config
    if data.type == "oauth2-github":
        assert data.oauth2_params is not None
        return {
            "client_id": data.oauth2_params.client_id,
            "client_secret": data.oauth2_params.client_secret,
        }
    return {}


@router.get("", status_code=200, responses={403: responses.PROBLEM})
def list_endpoint(tenant_name: str) -> schemas.AuthListResponse:
    auths = model.auth_config.read_all()
    grants = grant.Grants.create()
    output = []
    for ac in auths:
        if not grants.auth(ac.id).can_read():
            continue
        output.append(converters.auth_config_to_schema(ac, tenant_name))
    return schemas.AuthListResponse(auths=output)


@router.post("", status_code=201, responses={400: responses.PROBLEM, 403: responses.PROBLEM})
def create_endpoint(data: schemas.AuthCreateRequest, tenant_name: str) -> schemas.Auth:
    # Auth config names must not be pure integers to avoid shadowing GET /auth/{id:int}
    if data.name.isdigit():
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=400, title="Auth config name must not be a pure integer")
        )

    grants = grant.Grants.create()
    if not grants.auth(None).can_create():
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=403, title="Not allowed to create auth config")
        )

    config = _build_config(data)
    try:
        auth_id = model.auth_config.create(
            name=data.name,
            description=data.description,
            tag_id_list=data.tag_id_list,
            type=data.type,
            config=config,
        )
    except sqlalchemy.exc.IntegrityError:
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=400, title="Auth config already exists")
        )
    ac = model.auth_config.read_one(id=auth_id)
    assert ac is not None
    return converters.auth_config_to_schema(ac, tenant_name)


@router.get("/{auth_id:int}", status_code=200, responses={403: responses.PROBLEM, 404: responses.PROBLEM})
def read_endpoint(auth_id: int, tenant_name: str) -> schemas.Auth:
    ac = model.auth_config.read_one(id=auth_id)
    if ac is None:
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=404, title="Auth config does not exist")
        )
    grants = grant.Grants.create()
    if not grants.auth(ac.id).can_read():
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=403, title="Not allowed to read auth config")
        )
    return converters.auth_config_to_schema(ac, tenant_name)


@router.patch(
    "/{auth_id:int}",
    status_code=200,
    responses={400: responses.PROBLEM, 403: responses.PROBLEM, 404: responses.PROBLEM},
)
def update_endpoint(auth_id: int, data: schemas.AuthUpdateRequest, tenant_name: str) -> schemas.Auth:
    ac = model.auth_config.read_one(id=auth_id)
    if ac is None:
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=404, title="Auth config does not exist")
        )

    grants = grant.Grants.create()
    fields_to_update: dict = {}

    if data.name is not None:
        if not grants.auth(ac.id).can_update("name"):
            raise responses.ProblemHTTPException(
                responses.problem_response(status_code=403, title="Not allowed to update auth config name")
            )
        if data.name.isdigit():
            raise responses.ProblemHTTPException(
                responses.problem_response(status_code=400, title="Auth config name must not be a pure integer")
            )
        fields_to_update["name"] = data.name

    if data.description is not None:
        if not grants.auth(ac.id).can_update("description"):
            raise responses.ProblemHTTPException(
                responses.problem_response(status_code=403, title="Not allowed to update auth config description")
            )
        fields_to_update["description"] = data.description

    if data.tag_id_list is not None:
        if not grants.auth(ac.id).can_update("config"):
            raise responses.ProblemHTTPException(
                responses.problem_response(status_code=403, title="Not allowed to update auth config")
            )
        fields_to_update["tag_id_list"] = data.tag_id_list

    if data.is_enabled is not None:
        if not grants.auth(ac.id).can_update("is_enabled"):
            raise responses.ProblemHTTPException(
                responses.problem_response(status_code=403, title="Not allowed to update auth config is_enabled")
            )
        fields_to_update["is_enabled"] = data.is_enabled

    if data.oidc_params is not None:
        if not grants.auth(ac.id).can_update("config"):
            raise responses.ProblemHTTPException(
                responses.problem_response(status_code=403, title="Not allowed to update auth config")
            )
        config = dict(ac.config)
        config["issuer"] = data.oidc_params.issuer
        config["client_id"] = data.oidc_params.client_id
        if data.oidc_params.client_secret is not None:
            config["client_secret"] = data.oidc_params.client_secret
        fields_to_update["config"] = config

    if fields_to_update:
        model.auth_config.update(id=auth_id, **fields_to_update)

    updated = model.auth_config.read_one(id=auth_id)
    assert updated is not None
    return converters.auth_config_to_schema(updated, tenant_name)


@router.delete("/{auth_id:int}", status_code=204, responses={403: responses.PROBLEM, 404: responses.PROBLEM})
def delete_endpoint(auth_id: int) -> fastapi.responses.Response:
    ac = model.auth_config.read_one(id=auth_id)
    if ac is None:
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=404, title="Auth config does not exist")
        )
    grants = grant.Grants.create()
    if not grants.auth(ac.id).can_delete():
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=403, title="Not allowed to delete auth config")
        )
    model.auth_config.delete(id=auth_id)
    return _204
