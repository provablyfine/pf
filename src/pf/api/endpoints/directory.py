import fastapi

from .. import schemas
from ..context import ctx

router = fastapi.APIRouter()


@router.get("/directory", status_code=200)
def directory_endpoint(tenant_name: str) -> schemas.DirectoryReadResponse:
    base = ctx.config.base_url
    p = f"{base}/pf/t/{tenant_name}"
    return schemas.DirectoryReadResponse(
        initialize=f"{p}/initialize",
        accept_invitation=f"{p}/auth/http_sig/accept-invitation",
        login=f"{p}/auth/http_sig/login",
        login_oidc=f"{p}/auth/oidc/login",
        login_oauth2=f"{p}/auth/oauth2/login",
        auth=f"{p}/auth",
        boundary=f"{p}/boundary",
        tag=f"{p}/tag",
        role=f"{p}/role",
        identity=f"{p}/identity",
        ssh=f"{p}/ssh",
        tenant=f"{p}/tenant",
    )
