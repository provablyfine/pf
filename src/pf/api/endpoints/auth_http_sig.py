import time

import fastapi
import fastapi.requests
import fastapi.responses

from .. import converters, crypto_policy, model, responses, schemas, signature
from ..context import ctx

router = fastapi.APIRouter()

_204 = fastapi.responses.Response(status_code=204)


@router.post(
    "/auth/http_sig/accept-invitation",
    status_code=204,
    dependencies=[fastapi.Depends(signature.verify_invitation)],
    responses={400: responses.PROBLEM, 403: responses.PROBLEM},
)
def accept_invitation_endpoint(
    request: fastapi.requests.Request, data: schemas.AcceptInvitationRequest
) -> fastapi.responses.Response:
    account_key = converters.public_from_schema(data.account_public_key)
    crypto_policy.enforce_key_is_allowed(account_key)

    model.denylist.enforce_not_denied(account_key.thumbprint())

    # we can do the signature verification for the public account key
    signature.verify(request, f"account:{account_key.thumbprint()}", account_key)

    # if invitation has been accepted already, we do some checking to detect malevolent clients
    if ctx.invitation.is_accepted:
        if ctx.invitation.accepted_public_key_id == account_key.thumbprint():
            # The same key already accepted this invitation. This is probably some
            # kind of client-side or proxy retry
            return _204
        else:
            model.denylist.create(
                key_id=account_key.thumbprint(),
                identity_invitation_id=ctx.invitation.id,
            )
            return responses.problem_response(status_code=403, title="Invitation was already accepted")

    # all verification passed. Bind the public account key with the identity
    # that was configured in the invitation.
    model.identity_invitation_key.accept(
        id=ctx.invitation.id,
        public_key_id=account_key.thumbprint(),
    )
    now = int(time.time())
    ctx.db.identity_account_key.create(
        id=account_key.thumbprint(),
        public_key=account_key.to_dict(),
        identity_id=ctx.identity_id,
        created_at=now,
        is_revoked=False,
        revoked_at=None,
    )
    return _204


@router.post(
    "/auth/http_sig/login",
    status_code=204,
    dependencies=[fastapi.Depends(signature.verify_account)],
    responses={400: responses.PROBLEM, 403: responses.PROBLEM},
)
def login_endpoint(request: fastapi.requests.Request, data: schemas.LoginRequest) -> fastapi.responses.Response:
    session_key = converters.public_from_schema(data.session_public_key)
    crypto_policy.enforce_key_is_allowed(session_key)

    model.denylist.enforce_not_denied(session_key.thumbprint())

    # we can do the signature verification for the public session key
    signature.verify(request, f"session:{session_key.thumbprint()}", session_key)

    # all verification passed. Bind the public session key with the identity
    # that was configured in the account
    now = int(time.time())
    ctx.db.identity_session_key.create(
        id=session_key.thumbprint(),
        public_key=session_key.to_dict(),
        identity_id=ctx.identity_id,
        created_at=now,
        is_revoked=False,
        revoked_at=None,
        expires_at=now + ctx.config.session_duration_s,
    )
    return _204
