import fastapi

from .. import schemas
from ..context import ctx

router = fastapi.APIRouter()


@router.get("/pf/directory", status_code=200)
def directory_endpoint() -> schemas.DirectoryReadResponse:
    return schemas.DirectoryReadResponse(
        initialize=f"{ctx.config.base_url}/pf/initialize",
        accept_invitation=f"{ctx.config.base_url}/pf/accept-invitation",
        login=f"{ctx.config.base_url}/pf/login",
        boundary=f"{ctx.config.base_url}/pf/boundary",
        tag=f"{ctx.config.base_url}/pf/tag",
        role=f"{ctx.config.base_url}/pf/role",
        identity=f"{ctx.config.base_url}/pf/identity",
        ssh=f"{ctx.config.base_url}/pf/ssh",
    )
