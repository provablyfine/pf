import fastapi

from ... import jwk
from .. import converters, model, responses, schemas

router = fastapi.APIRouter()


@router.get("/public/oidc/.well-known/jwks.json", status_code=200)
def public_oidc_jwks() -> schemas.auth.OidcJwksResponse:
    public_keys = model.oidc_key.get_public_keys()
    assert all(k.type == jwk.KeyType.ED25519 for k in public_keys)
    keys = [schemas.auth.OidcED25519PublicJwk(kid=k.thumbprint(), x=k.to_dict()["x"]) for k in public_keys]
    return schemas.auth.OidcJwksResponse(keys=keys)


@router.get("/public/auth", status_code=200)
def public_auth_list(client_type: str) -> schemas.auth.AuthPublicListResponse:
    acs = model.auth_config.read_all(is_enabled=True, client_type=client_type)
    return schemas.auth.AuthPublicListResponse(
        auths=[
            schemas.auth.AuthPublicSummary.model_validate(
                {"name": ac.name, "client_type": ac.client_type, "type": ac.type}
            )
            for ac in acs
        ]
    )


@router.get("/public/auth/{name}", status_code=200, responses={404: responses.PROBLEM})
def public_auth_detail(name: str, client_type: str) -> schemas.auth.AuthPublic:
    ac = model.auth_config.read_one(name=name, client_type=client_type)
    if ac is None or not ac.is_enabled:
        raise responses.ProblemHTTPException(responses.problem_response(status_code=404, title="Auth config not found"))
    return converters.auth_config_to_public_schema(ac)
