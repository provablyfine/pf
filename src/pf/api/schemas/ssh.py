from __future__ import annotations

import typing

import pydantic

from . import base, bastion, jwk


class SSHHostCertificateRequest(base.APIBase):
    public_keys: list[jwk.PublicJWK]


class SSHCertificateResponse(base.APIBase):
    certificates: list[str]


class SSHHostCertificateResponse(SSHCertificateResponse):
    pass


class SSHUserCertificateRequest(base.APIBase):
    hostname: str
    username: str
    public_key: jwk.PublicJWK
    action: typing.Literal["shell", "port-forwarding", "command"]
    command: str | None = None


class SSHUserCertificateResponse(SSHCertificateResponse):
    bastion_list: list[bastion.Bastion] = pydantic.Field(default_factory=list[bastion.Bastion])
    ip_address_list: list[str] = pydantic.Field(default_factory=list[str])


class SSHHostEntry(base.APIBase):
    hostname: str
    type: typing.Literal["shell", "port", "command"]
    username_list: list[str] | None
    command_list: list[str] | None = None


class SSHHostsResponse(base.APIBase):
    hosts: list[SSHHostEntry]
