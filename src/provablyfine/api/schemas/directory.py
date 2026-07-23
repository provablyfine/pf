from __future__ import annotations

from . import base, jwk


class DirectoryReadResponse(base.APIBase):
    initialize: str
    accept_invitation: str
    login: str
    login_oidc: str
    auth: str
    public_auth: str
    boundary: str
    tag: str
    role: str
    identity: str
    ssh: str
    bastion: str
    tenant: str
    audit_log: str
    ping: str
    session: str


class InitializeResponse(base.APIBase):
    key: jwk.SymmetricJWK


class AcceptInvitationRequest(base.APIBase):
    account_public_key: jwk.PublicJWK


class LoginRequest(base.APIBase):
    session_public_key: jwk.PublicJWK


class LoginRoleInfo(base.APIBase):
    id: int
    name: str


class LoginResponse(base.APIBase):
    roles: list[LoginRoleInfo]
    expires_at: int
