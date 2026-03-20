import fastapi
import fastapi.responses

from .. import schemas
from ..context import ctx

router = fastapi.APIRouter()


@router.get("/pf/directory")
def directory_endpoint() -> fastapi.responses.Response:
    return fastapi.responses.JSONResponse(
        status_code=200,
        content=schemas.DirectoryReadResponse(
            initialize=f"{ctx.config.base_url}/pf/initialize",
            accept_invitation=f"{ctx.config.base_url}/pf/accept-invitation",
            login=f"{ctx.config.base_url}/pf/login",
            boundary=f"{ctx.config.base_url}/pf/boundary",
            tag=f"{ctx.config.base_url}/pf/tag",
            role=f"{ctx.config.base_url}/pf/role",
            identity=f"{ctx.config.base_url}/pf/identity",
            ssh=f"{ctx.config.base_url}/pf/ssh",
        ).model_dump(),
    )
