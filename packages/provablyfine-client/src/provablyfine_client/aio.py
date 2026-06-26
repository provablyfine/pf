from __future__ import annotations

import asyncio
import typing

from . import account_client, invitation_client, public_client, schemas, session_client


class AsyncPublicClient:
    def __init__(self, inner: public_client.PublicClient) -> None:
        self._inner = inner
        self._lock = asyncio.Lock()

    async def _run(self, fn: typing.Callable[[], typing.Any]) -> typing.Any:
        async with self._lock:
            return await asyncio.to_thread(fn)

    async def get_user_trusted_keys_public(self) -> str:
        return await self._run(self._inner.get_user_trusted_keys_public)

    async def get_public_auth(self, auth_name: str, client_type: str) -> schemas.AuthPublic:
        return await self._run(lambda: self._inner.get_public_auth(auth_name, client_type))

    async def list_public_auths(self, client_type: str) -> list[schemas.AuthPublicSummary]:
        return await self._run(lambda: self._inner.list_public_auths(client_type))

    async def initialize(self) -> str:
        return await self._run(self._inner.initialize)


class AsyncSessionClient:
    def __init__(self, inner: session_client.SessionClient) -> None:
        self._inner = inner
        self._lock = asyncio.Lock()

    async def _run(self, fn: typing.Callable[[], typing.Any]) -> typing.Any:
        async with self._lock:
            return await asyncio.to_thread(fn)

    async def list_ssh_hosts(self) -> schemas.SshHostsResponse:
        return await self._run(self._inner.list_ssh_hosts)

    async def get_host_trusted_keys(self) -> str:
        return await self._run(self._inner.get_host_trusted_keys)

    async def get_user_certificate(
        self,
        hostname: str,
        username: str,
        action: str,
        public_key: dict[str, typing.Any],
        command: str | None = None,
    ) -> schemas.SshUserCertificateResponse:
        return await self._run(
            lambda: self._inner.get_user_certificate(hostname, username, action, public_key, command)
        )

    async def sign_host_certificates(
        self, public_keys: list[dict[str, typing.Any]]
    ) -> schemas.SshHostCertificateResponse:
        return await self._run(lambda: self._inner.sign_host_certificates(public_keys))

    async def list_self_bastions(self) -> schemas.IdentitySelfBastionListResponse:
        return await self._run(self._inner.list_self_bastions)

    async def get_self_token(self, service: str) -> schemas.IdentitySelfTokenResponse:
        return await self._run(lambda: self._inner.get_self_token(service))

    async def list_tags(
        self,
        id: int | None = None,
        name: str | None = None,
        value: str | None = None,
    ) -> schemas.TagsResponse:
        return await self._run(lambda: self._inner.list_tags(id, name, value))

    async def create_tag(self, name: str, value: str) -> schemas.Tag:
        return await self._run(lambda: self._inner.create_tag(name, value))

    async def delete_tag(self, id: int) -> None:
        return await self._run(lambda: self._inner.delete_tag(id))

    async def list_tenants(self, id: int | None = None) -> schemas.TenantsResponse:
        return await self._run(lambda: self._inner.list_tenants(id))

    async def get_tenant(self, id: int) -> schemas.Tenant:
        return await self._run(lambda: self._inner.get_tenant(id))

    async def create_tenant(self, name: str, display_name: str) -> schemas.Tenant:
        return await self._run(lambda: self._inner.create_tenant(name, display_name))

    async def update_tenant(
        self,
        id: int,
        display_name: str | None = None,
        is_enabled: bool | None = None,
    ) -> None:
        return await self._run(lambda: self._inner.update_tenant(id, display_name, is_enabled))

    async def delete_tenant(self, id: int) -> None:
        return await self._run(lambda: self._inner.delete_tenant(id))

    async def list_auths(self) -> schemas.AuthListResponse:
        return await self._run(self._inner.list_auths)

    async def get_auth(self, id: int) -> schemas.Auth:
        return await self._run(lambda: self._inner.get_auth(id))

    async def create_auth_http_sig(
        self, name: str, client_type: str, description: str, tags: list[dict[str, str]]
    ) -> schemas.Auth:
        return await self._run(lambda: self._inner.create_auth_http_sig(name, client_type, description, tags))

    async def create_auth_oidc(
        self,
        name: str,
        client_type: str,
        description: str,
        tags: list[dict[str, str]],
        issuer: str,
        client_id: str,
        client_secret: str | None,
    ) -> schemas.Auth:
        return await self._run(
            lambda: self._inner.create_auth_oidc(name, client_type, description, tags, issuer, client_id, client_secret)
        )

    async def update_auth(
        self,
        id: int,
        name: str | None = None,
        description: str | None = None,
        is_enabled: bool | None = None,
        tags: list[schemas.TagNameValue] | None = None,
    ) -> None:
        return await self._run(lambda: self._inner.update_auth(id, name, description, is_enabled, tags))

    async def delete_auth(self, id: int) -> None:
        return await self._run(lambda: self._inner.delete_auth(id))

    async def list_bastions(self, id: int | None = None) -> schemas.BastionListResponse:
        return await self._run(lambda: self._inner.list_bastions(id))

    async def get_bastion(self, id: int) -> schemas.Bastion:
        return await self._run(lambda: self._inner.get_bastion(id))

    async def create_bastion(
        self,
        url: str,
        ssh_proxy_jump: str | None,
        tag_id_list: list[int],
        tag_name_value_list: list[dict[str, str]],
    ) -> schemas.Bastion:
        return await self._run(
            lambda: self._inner.create_bastion(url, ssh_proxy_jump, tag_id_list, tag_name_value_list)
        )

    async def update_bastion(
        self,
        id: int,
        url: str | None = None,
        ssh_proxy_jump: str | None = None,
        tag_id_list: list[int] | None = None,
        tag_name_value_list: list[schemas.TagNameValue] | None = None,
    ) -> None:
        return await self._run(
            lambda: self._inner.update_bastion(id, url, ssh_proxy_jump, tag_id_list, tag_name_value_list)
        )

    async def delete_bastion(self, id: int) -> None:
        return await self._run(lambda: self._inner.delete_bastion(id))

    async def list_roles(self, id: int | None = None, name: str | None = None) -> schemas.RolesResponse:
        return await self._run(lambda: self._inner.list_roles(id, name))

    async def get_role(self, id: int) -> schemas.Role:
        return await self._run(lambda: self._inner.get_role(id))

    async def create_role(self, name: str, description: str) -> schemas.Role:
        return await self._run(lambda: self._inner.create_role(name, description))

    async def update_role(
        self,
        id: int,
        name: str | None = None,
        description: str | None = None,
        grant_list: list[schemas.Grant] | None = None,
        member_list: list[schemas.RoleMemberUpdateRequest] | None = None,
    ) -> None:
        return await self._run(lambda: self._inner.update_role(id, name, description, grant_list, member_list))

    async def delete_role(self, id: int) -> None:
        return await self._run(lambda: self._inner.delete_role(id))

    async def list_boundaries(self, id: int | None = None, name: str | None = None) -> schemas.BoundariesResponse:
        return await self._run(lambda: self._inner.list_boundaries(id, name))

    async def get_boundary(self, id: int) -> schemas.Boundary:
        return await self._run(lambda: self._inner.get_boundary(id))

    async def create_boundary(self, name: str, description: str) -> schemas.Boundary:
        return await self._run(lambda: self._inner.create_boundary(name, description))

    async def update_boundary(
        self,
        id: int,
        name: str | None = None,
        description: str | None = None,
        ceiling_list: list[schemas.Grant] | None = None,
        denied_list: list[schemas.Grant] | None = None,
    ) -> None:
        return await self._run(lambda: self._inner.update_boundary(id, name, description, ceiling_list, denied_list))

    async def delete_boundary(self, id: int) -> None:
        return await self._run(lambda: self._inner.delete_boundary(id))

    async def list_identities(
        self,
        id: int | None = None,
        name: str | None = None,
        tag_id: list[str] | None = None,
        tag_name: list[str] | None = None,
        boundary_id: list[str] | None = None,
        boundary_name: list[str] | None = None,
    ) -> schemas.IdentitiesResponse:
        return await self._run(
            lambda: self._inner.list_identities(id, name, tag_id, tag_name, boundary_id, boundary_name)
        )

    async def get_identity(self, id: int) -> schemas.Identity:
        return await self._run(lambda: self._inner.get_identity(id))

    async def create_identity(
        self,
        name: str | None,
        boundary_id_list: list[int],
        boundary_name_list: list[str],
        tag_id_list: list[int],
        tag_name_value_list: list[dict[str, str]],
    ) -> schemas.Identity:
        return await self._run(
            lambda: self._inner.create_identity(
                name, boundary_id_list, boundary_name_list, tag_id_list, tag_name_value_list
            )
        )

    async def invite_identity(self, id: int, delivery: str) -> str | None:
        return await self._run(lambda: self._inner.invite_identity(id, delivery))

    async def delete_identity(self, id: int) -> None:
        return await self._run(lambda: self._inner.delete_identity(id))

    async def update_identity(
        self,
        id: int,
        name: str | None = None,
        tags: list[schemas.IdentityTagOp] | None = None,
    ) -> None:
        return await self._run(lambda: self._inner.update_identity(id, name, tags))

    async def login_oidc(
        self,
        auth_name: str,
        client_type: str,
        id_token: str,
        session_public_key: dict[str, typing.Any],
    ) -> None:
        return await self._run(lambda: self._inner.login_oidc(auth_name, client_type, id_token, session_public_key))

    async def list_audit_log(
        self,
        level: int | None = None,
        object_type: str | None = None,
        by_identity_id: str | None = None,
        start_time: int | None = None,
        end_time: int | None = None,
    ) -> schemas.AuditLogListResponse:
        return await self._run(
            lambda: self._inner.list_audit_log(level, object_type, by_identity_id, start_time, end_time)
        )


class AsyncAccountClient:
    def __init__(self, inner: account_client.AccountClient) -> None:
        self._inner = inner
        self._lock = asyncio.Lock()

    async def _run(self, fn: typing.Callable[[], typing.Any]) -> typing.Any:
        async with self._lock:
            return await asyncio.to_thread(fn)

    async def login_http_sig(self, session_public_key: dict[str, typing.Any]) -> None:
        return await self._run(lambda: self._inner.login_http_sig(session_public_key))


class AsyncInvitationClient:
    def __init__(self, inner: invitation_client.InvitationClient) -> None:
        self._inner = inner
        self._lock = asyncio.Lock()

    async def _run(self, fn: typing.Callable[[], typing.Any]) -> typing.Any:
        async with self._lock:
            return await asyncio.to_thread(fn)

    async def accept_invitation(self) -> None:
        return await self._run(self._inner.accept_invitation)
