import fastapi
import fastapi.responses

from .. import responses, schemas, signature
from ..context import ctx

router = fastapi.APIRouter(prefix="/session", dependencies=[fastapi.Depends(signature.verify_session)])

PROBLEM = responses.PROBLEM


@router.patch("/self", status_code=204, responses={403: PROBLEM, 409: PROBLEM})
def update_session_self(data: schemas.session.SessionSelfUpdateRequest) -> fastapi.responses.Response:
    if ctx.active_role_id is not None:
        raise responses.ProblemHTTPException(responses.problem_response(409, "Session role already set"))
    member = ctx.app_db.role_member.read_one(role_id=data.role_id, identity_id=ctx.identity_id)
    if member is None:
        raise responses.ProblemHTTPException(responses.problem_response(403, "Identity is not a member of this role"))
    ctx.app_db.identity_session_key.update(role_id=data.role_id).where(id=ctx.session_key_id)
    return fastapi.responses.Response(status_code=204)
