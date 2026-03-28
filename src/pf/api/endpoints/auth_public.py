import fastapi

from .. import model, oauth2_providers, responses, schemas

router = fastapi.APIRouter()


@router.get("/auth/{name}", status_code=200, responses={404: responses.PROBLEM})
def auth_public_endpoint(name: str) -> schemas.AuthPublic:
    ac = model.auth_config.read_one(name=name)
    if ac is None or not ac.is_enabled:
        raise responses.ProblemHTTPException(responses.problem_response(status_code=404, title="Auth config not found"))
    issuer = ac.config.get("issuer") if ac.type == "oidc" else None
    client_id = ac.config.get("client_id") if ac.type in ("oidc", *oauth2_providers.PROVIDER_CONFIG) else None
    client_secret = ac.config.get("client_secret") if ac.type == "oidc" else None
    authorization_endpoint = (
        oauth2_providers.PROVIDER_CONFIG[ac.type]["authorization_endpoint"]
        if ac.type in oauth2_providers.PROVIDER_CONFIG
        else None
    )
    return schemas.AuthPublic(
        name=ac.name,
        type=ac.type,  # type: ignore[arg-type]
        description=ac.description,
        issuer=issuer,
        client_id=client_id,
        client_secret=client_secret,
        authorization_endpoint=authorization_endpoint,
    )
