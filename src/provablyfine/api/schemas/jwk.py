from __future__ import annotations

import typing

import pydantic

from . import base


class RSAPublicJWK(base.APIBase):
    kty: typing.Literal["RSA"] = "RSA"
    e: str
    n: str


class ECDSAPublicJWK(base.APIBase):
    crv: typing.Literal["P-256"] = "P-256"
    kty: typing.Literal["EC"] = "EC"
    x: str
    y: str


class ED25519PublicJWK(base.APIBase):
    crv: typing.Literal["Ed25519"] = "Ed25519"
    kty: typing.Literal["OKP"] = "OKP"
    x: str


PublicJWK = typing.Annotated[RSAPublicJWK | ECDSAPublicJWK | ED25519PublicJWK, pydantic.Field(discriminator="kty")]


class SymmetricJWK(base.APIBase):
    kty: typing.Literal["oct"]
    k: str  # base64url encoded
