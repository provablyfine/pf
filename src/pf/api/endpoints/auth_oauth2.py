import hashlib
import logging
import secrets
import time
import urllib.parse

import fastapi
import fastapi.requests
import fastapi.responses
import requests

from ... import base64url, jwk
from .. import converters, crypto_policy, model, oauth2_providers, responses, schemas, signature
from ..context import ctx

logger = logging.getLogger(__name__)

router = fastapi.APIRouter()

_204 = fastapi.responses.Response(status_code=204)

_HTML_ERROR = """\
<!DOCTYPE html>
<html><body><h1>Login failed</h1><p>{reason}</p></body></html>"""


def _github_exchange_code_for_emails(
    token_endpoint: str,
    client_id: str,
    client_secret: str,
    code: str,
    redirect_uri: str,
    code_verifier: str,
) -> list[str]:
    """Exchange a GitHub authorization code server-side; return list of email addresses."""
    token_resp = requests.post(
        token_endpoint,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
            "client_id": client_id,
            "client_secret": client_secret,
        },
        headers={"Accept": "application/json"},
        timeout=10,
    )
    token_resp.raise_for_status()
    access_token = token_resp.json().get("access_token")
    if not access_token:
        raise ValueError("Token response missing access_token")
    emails_resp = requests.get(
        "https://api.github.com/user/emails",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        timeout=10,
    )
    emails_resp.raise_for_status()
    return [e["email"] for e in emails_resp.json() if e.get("email")]


def _redirect_error(client_redirect_uri: str, reason: str) -> fastapi.responses.RedirectResponse:
    url = f"{client_redirect_uri}?status=error&reason={urllib.parse.quote(reason)}"
    return fastapi.responses.RedirectResponse(url, status_code=302)


@router.post(
    "/auth/oauth2/start",
    status_code=200,
    responses={403: responses.PROBLEM},
)
def oauth2_start_endpoint(
    request: fastapi.requests.Request, data: schemas.auth.OAuth2StartRequest, tenant_name: str
) -> schemas.auth.OAuth2StartResponse:
    session_key = converters.public_from_schema(data.session_public_key)
    crypto_policy.enforce_key_is_allowed(session_key)
    model.denylist.enforce_not_denied(session_key.thumbprint())

    signature.verify(request, f"session:{session_key.thumbprint()}", session_key)

    ac = model.auth_config.read_one(name=data.auth_name)
    if ac is None or not ac.is_enabled:
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=403, title="Auth config not found or disabled")
        )
    if ac.type not in oauth2_providers.PROVIDER_CONFIG:
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=403, title="Auth config is not a supported oauth2 type")
        )

    provider = oauth2_providers.PROVIDER_CONFIG[ac.type]

    login_id = secrets.token_urlsafe(32)
    code_verifier = base64url.encode(secrets.token_bytes(32))
    code_challenge = base64url.encode(hashlib.sha256(code_verifier.encode()).digest())

    redirect_uri = f"{ctx.config.base_url}/pf/t/{tenant_name}/auth/oauth2/callback"
    auth_url = (
        f"{provider['authorization_endpoint']}"
        f"?client_id={urllib.parse.quote(ac.config['client_id'])}"
        f"&redirect_uri={urllib.parse.quote(redirect_uri)}"
        f"&response_type=code"
        f"&scope=user:email"
        f"&state={urllib.parse.quote(login_id)}"
        f"&code_challenge={urllib.parse.quote(code_challenge)}"
        f"&code_challenge_method=S256"
    )

    now = int(time.time())
    ctx.app_db.oauth2_login_request.create(
        id=login_id,
        session_key_thumbprint=session_key.thumbprint(),
        session_public_key=session_key.to_dict(),
        auth_config_id=ac.id,
        code_verifier=ctx.kek.encrypt(code_verifier.encode()),
        redirect_uri=redirect_uri,
        client_redirect_uri=data.client_redirect_uri,
        created_at=now,
        expires_at=now + 600,
    )

    return schemas.auth.OAuth2StartResponse(auth_url=auth_url)


@router.get(
    "/auth/oauth2/callback",
    status_code=302,
)
def oauth2_callback_endpoint(
    request: fastapi.requests.Request,
    code: str | None = None,
    state: str | None = None,
) -> fastapi.responses.Response:
    if code is None or state is None:
        return fastapi.responses.HTMLResponse(
            content=_HTML_ERROR.format(reason="Missing code or state parameter"),
            status_code=400,
        )

    row = ctx.app_db.oauth2_login_request.read_one(id=state)
    now = int(time.time())
    if row is None or now > row.expires_at:
        return fastapi.responses.HTMLResponse(
            content=_HTML_ERROR.format(reason="Login request not found or expired"),
            status_code=400,
        )

    client_redirect_uri = row.client_redirect_uri
    ctx.app_db.oauth2_login_request.delete(id=state)

    ac = model.auth_config.read_one(id=row.auth_config_id)
    if ac is None or not ac.is_enabled:
        return _redirect_error(client_redirect_uri, "Auth config no longer available")

    if ac.type not in oauth2_providers.PROVIDER_CONFIG:
        return _redirect_error(client_redirect_uri, "Unsupported auth type")

    provider = oauth2_providers.PROVIDER_CONFIG[ac.type]
    code_verifier = ctx.kek.decrypt(row.code_verifier).decode()

    try:
        emails = _github_exchange_code_for_emails(
            token_endpoint=provider["token_endpoint"],
            client_id=ac.config["client_id"],
            client_secret=ac.config["client_secret"],
            code=code,
            redirect_uri=row.redirect_uri,
            code_verifier=code_verifier,
        )
    except Exception as exc:
        logger.info(f"Code exchange failed: {exc}")
        return _redirect_error(client_redirect_uri, "Code exchange failed")

    identity = None
    for email in emails:
        identity = model.identity.read_one(name=email)
        if identity is not None:
            break
    if identity is None:
        return _redirect_error(client_redirect_uri, "No identity for this account")

    if ac.tag_id_list:
        if not any(tag_id in identity.tag_id_list for tag_id in ac.tag_id_list):
            return _redirect_error(client_redirect_uri, "Identity does not have a required tag")

    session_key = jwk.Public.from_dict(row.session_public_key)
    try:
        crypto_policy.enforce_key_is_allowed(session_key)
        model.denylist.enforce_not_denied(session_key.thumbprint())
    except Exception:
        return _redirect_error(client_redirect_uri, "Session key not allowed")

    ctx.app_db.identity_session_key.create(
        id=session_key.thumbprint(),
        public_key=session_key.to_dict(),
        identity_id=identity.id,
        created_at=now,
        is_revoked=False,
        revoked_at=None,
        expires_at=now + ctx.config.session_duration_s,
        login_ip=request.client.host if request.client else None,
    )

    return fastapi.responses.RedirectResponse(
        f"{client_redirect_uri}?status=ok",
        status_code=302,
    )
