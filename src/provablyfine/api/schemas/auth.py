from __future__ import annotations

import typing

import pydantic

from . import base, jwk, tag


class HttpSigConfig(base.APIBase):
    type: typing.Literal["http_sig"] = "http_sig"


class OidcConfig(base.APIBase):
    issuer: str
    client_id: str
    client_secret: str | None = None
    callback_url: str = "http://127.0.0.1/callback"
    type: typing.Literal["oidc"] = "oidc"


class OidcDeviceCodeConfig(base.APIBase):
    issuer: str
    client_id: str
    client_secret: str | None = None
    type: typing.Literal["oidc-device-code"] = "oidc-device-code"


class OAuth2Config(base.APIBase):
    client_id: str
    authorization_endpoint: str
    callback_url: str
    type: typing.Literal["oauth2-github"] = "oauth2-github"


AuthConfig = OidcConfig | OidcDeviceCodeConfig | OAuth2Config | HttpSigConfig


class OidcCreateConfig(OidcConfig):
    pass


class OidcDeviceCodeCreateConfig(OidcDeviceCodeConfig):
    pass


class HttpSigCreateConfig(HttpSigConfig):
    pass


class OAuth2CreateConfig(base.APIBase):
    type: typing.Literal["oauth2-github"] = "oauth2-github"
    client_id: str
    client_secret: str


class Auth(base.APIBase):
    id: int
    name: str
    client_type: str
    description: str
    tags: list[tag.TagNameValue]
    created_at: int
    is_enabled: bool
    config: AuthConfig


class AuthListResponse(base.APIBase):
    auths: list[Auth]


class AuthCreateRequest(base.APIBase):
    name: str
    client_type: str
    description: str = ""
    tags: list[tag.TagNameValue] = pydantic.Field(default_factory=list[tag.TagNameValue])
    config: OidcCreateConfig | OidcDeviceCodeCreateConfig | OAuth2CreateConfig | HttpSigCreateConfig


class AuthUpdateRequest(base.APIBase):
    name: str | None = None
    description: str | None = None
    tags: list[tag.TagNameValue] | None = None
    is_enabled: bool | None = None


class AuthPublic(base.APIBase):
    name: str
    description: str
    config: AuthConfig


class OidcLoginRequest(base.APIBase):
    auth_name: str
    id_token: str
    session_public_key: jwk.PublicJWK


class OAuth2StartRequest(base.APIBase):
    auth_name: str
    session_public_key: jwk.PublicJWK
    client_redirect_uri: str


class OAuth2StartResponse(base.APIBase):
    auth_url: str


class OidcED25519PublicJwk(jwk.ED25519PublicJWK):
    kid: str
    alg: typing.Literal["EdDSA"] = "EdDSA"
    use: typing.Literal["sig"] = "sig"


class OidcJwksResponse(base.APIBase):
    keys: list[OidcED25519PublicJwk]


class AuthPublicSummary(base.APIBase):
    name: str
    client_type: str
    type: typing.Literal["http_sig", "oidc", "oidc-device-code", "oauth2-github"]


class AuthPublicListResponse(base.APIBase):
    auths: list[AuthPublicSummary]
