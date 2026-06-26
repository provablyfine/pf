import fastapi

from .. import schemas, signature

router = fastapi.APIRouter(prefix="/ping", dependencies=[fastapi.Depends(signature.verify_session)])


@router.get("", status_code=200)
def ping_endpoint() -> schemas.ping.PingResponse:
    return schemas.ping.PingResponse(message="pong")
