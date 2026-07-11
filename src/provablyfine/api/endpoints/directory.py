import fastapi

from .. import schemas
from ..context import ctx

router = fastapi.APIRouter()


@router.get("/directory", status_code=200)
def directory_endpoint(tenant_name: str) -> schemas.directory.DirectoryReadResponse:
    base = ctx.config.base_url
    p = f"{base}/pf/t/{tenant_name}"
    return schemas.directory.DirectoryReadResponse(
        initialize=f"{p}/initialize",
        accept_invitation=f"{p}/auth/http_sig/accept-invitation",
        login=f"{p}/auth/http_sig/login",
        login_oidc=f"{p}/auth/oidc/login",
        auth=f"{p}/auth",
        public_auth=f"{p}/public/auth",
        boundary=f"{p}/boundary",
        tag=f"{p}/tag",
        role=f"{p}/role",
        identity=f"{p}/identity",
        ssh=f"{p}/ssh",
        bastion=f"{p}/bastion",
        tenant=f"{p}/tenant",
        audit_log=f"{p}/audit-log",
        ping=f"{p}/ping",
        session=f"{p}/session",
    )
