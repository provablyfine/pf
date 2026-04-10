import fastapi

from ... import jwk
from .. import model, oauth2_providers, responses, schemas
from ..context import ctx

router = fastapi.APIRouter()


@router.get("/public/oidc/.well-known/jwks.json", status_code=200)
def public_oidc_jwks(tenant_name: str) -> schemas.OidcJwksResponse:
    public_keys = model.oidc_key.get_public_keys()
    assert all(k.type == jwk.KeyType.ED25519 for k in public_keys)
    keys = [schemas.OidcED25519PublicJwk(kid=k.thumbprint(), x=k.to_dict()["x"]) for k in public_keys]
    return schemas.OidcJwksResponse(keys=keys)


@router.get("/public/auth", status_code=200)
def public_auth_list(tenant_name: str) -> schemas.AuthPublicListResponse:
    acs = model.auth_config.read_all(is_enabled=True)
    return schemas.AuthPublicListResponse(
        auths=[schemas.AuthPublicSummary(name=ac.name, type=ac.type) for ac in acs]  # type: ignore[arg-type]
    )


@router.get("/public/auth/{name}", status_code=200, responses={404: responses.PROBLEM})
def public_auth_detail(name: str, tenant_name: str) -> schemas.AuthPublic:
    ac = model.auth_config.read_one(name=name)
    if ac is None or not ac.is_enabled:
        raise responses.ProblemHTTPException(responses.problem_response(status_code=404, title="Auth config not found"))
    if ac.type == "oidc":
        params: schemas.OidcParams | schemas.OAuth2Params | schemas.HttpSigParams = schemas.OidcParams(
            issuer=ac.config["issuer"],
            client_id=ac.config["client_id"],
            client_secret=ac.config.get("client_secret"),
        )
    elif ac.type in oauth2_providers.PROVIDER_CONFIG:
        callback_url = f"{ctx.config.base_url}/pf/t/{tenant_name}/auth/oauth2/callback"
        params = schemas.OAuth2Params(
            client_id=ac.config["client_id"],
            authorization_endpoint=oauth2_providers.PROVIDER_CONFIG[ac.type]["authorization_endpoint"],
            callback_url=callback_url,
        )
    else:
        params = schemas.HttpSigParams()
    return schemas.AuthPublic(
        name=ac.name,
        type=ac.type,  # type: ignore[arg-type]
        description=ac.description,
        params=params,
    )
