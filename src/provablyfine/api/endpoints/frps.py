from __future__ import annotations

import logging
import typing

import fastapi
import jwt
import pydantic

from .. import jwt_validator

logger = logging.getLogger(__name__)

router = fastapi.APIRouter()


class _PluginRequest(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="ignore")
    op: str
    # content structure differs by op: Login has user:str, others have user:{...}
    content: dict[str, object] = {}


class _PluginResponse(pydantic.BaseModel):
    reject: bool
    reject_reason: str = ""
    unchange: bool = True


@router.post("/frps/plugin")
def frps_plugin_endpoint(request: fastapi.Request, data: _PluginRequest) -> _PluginResponse:
    if data.op != "Login":
        return _PluginResponse(reject=False)

    user = data.content.get("user")
    if not isinstance(user, str):
        logger.debug("frps plugin: missing or non-string user field")
        return _PluginResponse(reject=True, reject_reason="invalid user field")

    metas_raw = data.content.get("metas")
    jwt_token: str | None = None
    if isinstance(metas_raw, dict):
        metas = typing.cast("dict[str, object]", metas_raw)
        jwt_val = metas.get("jwt")
        if isinstance(jwt_val, str):
            jwt_token = jwt_val
    if not jwt_token:
        logger.debug("frps plugin: missing jwt in metas")
        return _PluginResponse(reject=True, reject_reason="missing jwt in metas")

    trusted_keys: jwt_validator.TrustedKeys = request.app.state.trusted_keys
    trusted_key = trusted_keys.lookup(jwt_token)
    if trusted_key is None:
        logger.debug("frps plugin: unknown issuer or invalid jwt")
        return _PluginResponse(reject=True, reject_reason="unknown issuer or invalid jwt")

    try:
        jwt.decode(
            jwt_token,
            trusted_key.key,
            algorithms=["EdDSA"],
            audience=user,
            issuer=trusted_key.issuer,
            options={"require": ["sub", "name", "tenant_id"]},
        )
    except jwt.exceptions.InvalidTokenError as e:
        logger.debug(f"frps plugin: jwt validation failed: {e}")
        return _PluginResponse(reject=True, reject_reason=str(e))

    return _PluginResponse(reject=False)
