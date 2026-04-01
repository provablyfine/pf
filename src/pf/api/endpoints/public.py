import fastapi

from .. import model, responses, schemas

router = fastapi.APIRouter()


@router.get("/public/auth", status_code=200)
def public_auth_list(tenant_name: str) -> schemas.AuthPublicListResponse:
    acs = model.auth_config.read_all(is_enabled=True)
    return schemas.AuthPublicListResponse(
        auths=[schemas.AuthPublicSummary(name=ac.name, type=ac.type) for ac in acs]  # type: ignore[arg-type]
    )


@router.get("/public/auth/{name}", status_code=200, responses={404: responses.PROBLEM})
def public_auth_detail(name: str, tenant_name: str) -> schemas.AuthPublic:
    from . import auth_public

    return auth_public.auth_public_endpoint(name=name, tenant_name=tenant_name)
