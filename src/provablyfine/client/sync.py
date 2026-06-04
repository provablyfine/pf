from __future__ import annotations

import typing

import provablyfine_client as pfc
import requests

from .. import base64url, jwk
from . import configuration, http_client


class Client:
    def __init__(self, config: configuration.Config, timeout: float = 1.0) -> None:
        self._config = config
        self._http = pfc.HttpSession(requests.Session(), timeout)
        self._directory = pfc.Directory(config.directory_url, timeout)

    def _session(self) -> pfc.SessionClient:
        signer = http_client.private_key_signer("session", self._config.session_key)
        return pfc.SessionClient(self._http, self._directory, signer)

    def _public(self) -> pfc.PublicClient:
        return pfc.PublicClient(self._http, self._directory)

    # SSH

    def list_ssh_hosts(self) -> pfc.schemas.SshHostsResponse:
        return self._session().list_ssh_hosts()

    def get_host_trusted_keys(self) -> str:
        return self._session().get_host_trusted_keys()

    def get_user_certificate(
        self,
        hostname: str,
        username: str,
        action: str,
        public_key: dict[str, typing.Any],
        command: str | None = None,
    ) -> pfc.schemas.SshUserCertificateResponse:
        return self._session().get_user_certificate(hostname, username, action, public_key, command)

    def get_user_trusted_keys_public(self) -> str:
        return self._public().get_user_trusted_keys_public()

    def sign_host_certificates(
        self, public_keys: list[dict[str, typing.Any]]
    ) -> pfc.schemas.SshHostCertificateResponse:
        return self._session().sign_host_certificates(public_keys)

    # Identity / self

    def list_self_bastions(self) -> pfc.schemas.IdentitySelfBastionListResponse:
        return self._session().list_self_bastions()

    def get_self_token(self, service: str) -> pfc.schemas.IdentitySelfTokenResponse:
        return self._session().get_self_token(service)

    # Tags

    def list_tags(
        self,
        id: int | None = None,
        name: str | None = None,
        value: str | None = None,
    ) -> pfc.schemas.TagsResponse:
        return self._session().list_tags(id, name, value)

    def create_tag(self, name: str, value: str) -> pfc.schemas.Tag:
        return self._session().create_tag(name, value)

    def delete_tag(self, id: int) -> None:
        return self._session().delete_tag(id)

    # Tenants

    def list_tenants(self, id: int | None = None) -> pfc.schemas.TenantsResponse:
        return self._session().list_tenants(id)

    def get_tenant(self, id: int) -> pfc.schemas.Tenant:
        return self._session().get_tenant(id)

    def create_tenant(self, name: str, display_name: str) -> pfc.schemas.Tenant:
        return self._session().create_tenant(name, display_name)

    def update_tenant(
        self,
        id: int,
        display_name: str | None = None,
        is_enabled: bool | None = None,
    ) -> None:
        return self._session().update_tenant(id, display_name, is_enabled)

    def delete_tenant(self, id: int) -> None:
        return self._session().delete_tenant(id)

    # Auth configs

    def list_auths(self) -> pfc.schemas.AuthListResponse:
        return self._session().list_auths()

    def get_auth(self, id: int) -> pfc.schemas.Auth:
        return self._session().get_auth(id)

    def create_auth_http_sig(self, name: str, description: str, tags: list[dict[str, str]]) -> pfc.schemas.Auth:
        return self._session().create_auth_http_sig(name, description, tags)

    def create_auth_oidc(
        self,
        name: str,
        description: str,
        tags: list[dict[str, str]],
        issuer: str,
        client_id: str,
        client_secret: str | None,
    ) -> pfc.schemas.Auth:
        return self._session().create_auth_oidc(name, description, tags, issuer, client_id, client_secret)

    def create_auth_oauth2_github(
        self,
        name: str,
        description: str,
        tags: list[dict[str, str]],
        client_id: str,
        client_secret: str,
    ) -> pfc.schemas.Auth:
        return self._session().create_auth_oauth2_github(name, description, tags, client_id, client_secret)

    def update_auth(
        self,
        id: int,
        name: str | None = None,
        description: str | None = None,
        is_enabled: bool | None = None,
        tags: list[pfc.schemas.TagNameValue] | None = None,
    ) -> None:
        return self._session().update_auth(id, name, description, is_enabled, tags)

    def delete_auth(self, id: int) -> None:
        return self._session().delete_auth(id)

    # Bastions

    def list_bastions(self, id: int | None = None) -> pfc.schemas.BastionListResponse:
        return self._session().list_bastions(id)

    def get_bastion(self, id: int) -> pfc.schemas.Bastion:
        return self._session().get_bastion(id)

    def create_bastion(
        self,
        url: str,
        ssh_proxy_jump: str | None,
        tag_id_list: list[int],
        tag_name_value_list: list[dict[str, str]],
    ) -> pfc.schemas.Bastion:
        return self._session().create_bastion(url, ssh_proxy_jump, tag_id_list, tag_name_value_list)

    def update_bastion(
        self,
        id: int,
        url: str | None = None,
        ssh_proxy_jump: str | None = None,
        tag_id_list: list[int] | None = None,
        tag_name_value_list: list[pfc.schemas.TagNameValue] | None = None,
    ) -> None:
        return self._session().update_bastion(id, url, ssh_proxy_jump, tag_id_list, tag_name_value_list)

    def delete_bastion(self, id: int) -> None:
        return self._session().delete_bastion(id)

    # Roles

    def list_roles(self, id: int | None = None, name: str | None = None) -> pfc.schemas.RolesResponse:
        return self._session().list_roles(id, name)

    def get_role(self, id: int) -> pfc.schemas.Role:
        return self._session().get_role(id)

    def create_role(self, name: str, description: str) -> pfc.schemas.Role:
        return self._session().create_role(name, description)

    def update_role(
        self,
        id: int,
        name: str | None = None,
        description: str | None = None,
        grant_list: list[pfc.schemas.Grant] | None = None,
        member_list: list[pfc.schemas.RoleMemberRef] | None = None,
    ) -> None:
        return self._session().update_role(id, name, description, grant_list, member_list)

    def delete_role(self, id: int) -> None:
        return self._session().delete_role(id)

    # Boundaries

    def list_boundaries(self, id: int | None = None, name: str | None = None) -> pfc.schemas.BoundariesResponse:
        return self._session().list_boundaries(id, name)

    def get_boundary(self, id: int) -> pfc.schemas.Boundary:
        return self._session().get_boundary(id)

    def create_boundary(self, name: str, description: str) -> pfc.schemas.Boundary:
        return self._session().create_boundary(name, description)

    def update_boundary(
        self,
        id: int,
        name: str | None = None,
        description: str | None = None,
        ceiling_list: list[pfc.schemas.Grant] | None = None,
        denied_list: list[pfc.schemas.Grant] | None = None,
    ) -> None:
        return self._session().update_boundary(id, name, description, ceiling_list, denied_list)

    def delete_boundary(self, id: int) -> None:
        return self._session().delete_boundary(id)

    # Identities

    def list_identities(
        self,
        id: int | None = None,
        name: str | None = None,
        tag_id: list[str] | None = None,
        tag_name: list[str] | None = None,
        boundary_id: list[str] | None = None,
        boundary_name: list[str] | None = None,
    ) -> pfc.schemas.IdentitiesResponse:
        return self._session().list_identities(id, name, tag_id, tag_name, boundary_id, boundary_name)

    def get_identity(self, id: int) -> pfc.schemas.Identity:
        return self._session().get_identity(id)

    def create_identity(
        self,
        name: str | None,
        boundary_id_list: list[int],
        boundary_name_list: list[str],
        tag_id_list: list[int],
        tag_name_value_list: list[dict[str, str]],
    ) -> pfc.schemas.Identity:
        return self._session().create_identity(
            name, boundary_id_list, boundary_name_list, tag_id_list, tag_name_value_list
        )

    def invite_identity(self, id: int, delivery: str) -> str | None:
        return self._session().invite_identity(id, delivery)

    def delete_identity(self, id: int) -> None:
        return self._session().delete_identity(id)

    def update_identity(
        self,
        id: int,
        name: str | None = None,
        tags: list[pfc.schemas.IdentityTagOp] | None = None,
    ) -> None:
        return self._session().update_identity(id, name, tags)

    # Auth flow

    def initialize(self, key: str) -> None:
        signer = http_client.private_key_signer("account", key)
        self._public().initialize(signer, signer.public_key().to_dict())

    def connect(self, invitation: str, key: str) -> None:
        account_signer = http_client.private_key_signer("account", key)
        inv_signer = pfc.HmacSigner("invitation", base64url.decode(invitation))
        pfc.InvitationClient(self._http, self._directory, inv_signer, account_signer).connect(
            account_signer.public_key().to_dict()
        )

    def get_public_auth(self, auth_name: str) -> pfc.schemas.AuthPublic:
        return self._public().get_public_auth(auth_name)

    def list_public_auths(self) -> list[pfc.schemas.AuthPublicSummary]:
        return self._public().list_public_auths()

    def login_http_sig(self, session_public_key: dict[str, typing.Any], session_fingerprint: str) -> None:
        account_signer = http_client.private_key_signer("account", self._config.account_key)
        session_signer = http_client.private_key_signer("session", session_fingerprint)
        pfc.AccountClient(self._http, self._directory, account_signer, session_signer).login_http_sig(
            session_public_key
        )

    def login_http_sig_with_keys(self, account: jwk.Private, session: jwk.Private) -> None:
        account_signer = http_client.FileSigner("account", account)
        session_signer = http_client.FileSigner("session", session)
        pfc.AccountClient(self._http, self._directory, account_signer, session_signer).login_http_sig(
            session.public().to_dict()
        )

    def login_oidc(
        self, auth_name: str, id_token: str, session_public_key: dict[str, typing.Any], session_fingerprint: str
    ) -> None:
        signer = http_client.private_key_signer("session", session_fingerprint)
        pfc.SessionClient(self._http, self._directory, signer).login_oidc(auth_name, id_token, session_public_key)

    def login_oauth2_start(
        self,
        auth_name: str,
        session_public_key: dict[str, typing.Any],
        session_fingerprint: str,
        client_redirect_uri: str,
    ) -> str:
        signer = http_client.private_key_signer("session", session_fingerprint)
        return pfc.SessionClient(self._http, self._directory, signer).login_oauth2_start(
            auth_name, session_public_key, client_redirect_uri
        )

    def list_audit_log(
        self,
        level: int | None = None,
        object_type: str | None = None,
        by_identity_id: str | None = None,
        start_time: int | None = None,
        end_time: int | None = None,
    ) -> pfc.schemas.AuditLogListResponse:
        return self._session().list_audit_log(level, object_type, by_identity_id, start_time, end_time)
