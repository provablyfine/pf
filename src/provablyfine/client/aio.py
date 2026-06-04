import asyncio
import typing

import provablyfine_client as pfc

from . import configuration, sync


class Client:
    """Async wrapper around sync.Client using asyncio.Lock and asyncio.to_thread."""

    def __init__(self, config: configuration.Config, timeout: float = 1.0) -> None:
        self._sync = sync.Client(config, timeout=timeout)
        self._lock = asyncio.Lock()

    async def _run(self, fn: typing.Callable[[], typing.Any]) -> typing.Any:
        """Run a blocking sync function in a thread under the lock."""
        async with self._lock:
            return await asyncio.to_thread(fn)

    # SSH
    async def list_ssh_hosts(self) -> pfc.schemas.SshHostsResponse:
        return await self._run(self._sync.list_ssh_hosts)

    async def get_host_trusted_keys(self) -> str:
        return await self._run(self._sync.get_host_trusted_keys)

    async def get_user_certificate(
        self,
        hostname: str,
        username: str,
        action: str,
        public_key: dict[str, typing.Any],
        command: str | None = None,
    ) -> pfc.schemas.SshUserCertificateResponse:
        return await self._run(lambda: self._sync.get_user_certificate(hostname, username, action, public_key, command))

    async def get_user_trusted_keys_public(self) -> str:
        return await self._run(self._sync.get_user_trusted_keys_public)

    async def sign_host_certificates(
        self, public_keys: list[dict[str, typing.Any]]
    ) -> pfc.schemas.SshHostCertificateResponse:
        return await self._run(lambda: self._sync.sign_host_certificates(public_keys))

    # Identity/Self
    async def list_self_bastions(self) -> pfc.schemas.IdentitySelfBastionListResponse:
        return await self._run(self._sync.list_self_bastions)

    async def get_self_token(self, service: str) -> pfc.schemas.IdentitySelfTokenResponse:
        return await self._run(lambda: self._sync.get_self_token(service))

    # Tags
    async def list_tags(
        self,
        id: int | None = None,
        name: str | None = None,
        value: str | None = None,
    ) -> pfc.schemas.TagsResponse:
        return await self._run(lambda: self._sync.list_tags(id, name, value))

    async def create_tag(self, name: str, value: str) -> pfc.schemas.Tag:
        return await self._run(lambda: self._sync.create_tag(name, value))

    async def delete_tag(self, id: int) -> None:
        return await self._run(lambda: self._sync.delete_tag(id))

    # Tenants
    async def list_tenants(self, id: int | None = None) -> pfc.schemas.TenantsResponse:
        return await self._run(lambda: self._sync.list_tenants(id))

    async def get_tenant(self, id: int) -> pfc.schemas.Tenant:
        return await self._run(lambda: self._sync.get_tenant(id))

    async def create_tenant(self, name: str, display_name: str) -> pfc.schemas.Tenant:
        return await self._run(lambda: self._sync.create_tenant(name, display_name))

    async def update_tenant(
        self,
        id: int,
        display_name: str | None = None,
        is_enabled: bool | None = None,
    ) -> None:
        return await self._run(lambda: self._sync.update_tenant(id, display_name, is_enabled))

    async def delete_tenant(self, id: int) -> None:
        return await self._run(lambda: self._sync.delete_tenant(id))

    # Auth configs
    async def list_auths(self) -> pfc.schemas.AuthListResponse:
        return await self._run(self._sync.list_auths)

    async def get_auth(self, id: int) -> pfc.schemas.Auth:
        return await self._run(lambda: self._sync.get_auth(id))

    async def create_auth_http_sig(self, name: str, description: str, tags: list[dict[str, str]]) -> pfc.schemas.Auth:
        return await self._run(lambda: self._sync.create_auth_http_sig(name, description, tags))

    async def create_auth_oidc(
        self,
        name: str,
        description: str,
        tags: list[dict[str, str]],
        issuer: str,
        client_id: str,
        client_secret: str | None,
    ) -> pfc.schemas.Auth:
        return await self._run(
            lambda: self._sync.create_auth_oidc(name, description, tags, issuer, client_id, client_secret)
        )

    async def create_auth_oauth2_github(
        self,
        name: str,
        description: str,
        tags: list[dict[str, str]],
        client_id: str,
        client_secret: str,
    ) -> pfc.schemas.Auth:
        return await self._run(
            lambda: self._sync.create_auth_oauth2_github(name, description, tags, client_id, client_secret)
        )

    async def update_auth(
        self,
        id: int,
        name: str | None = None,
        description: str | None = None,
        is_enabled: bool | None = None,
        tags: list[pfc.schemas.TagNameValue] | None = None,
    ) -> None:
        return await self._run(lambda: self._sync.update_auth(id, name, description, is_enabled, tags))

    async def delete_auth(self, id: int) -> None:
        return await self._run(lambda: self._sync.delete_auth(id))

    # Bastions
    async def list_bastions(self, id: int | None = None) -> pfc.schemas.BastionListResponse:
        return await self._run(lambda: self._sync.list_bastions(id))

    async def get_bastion(self, id: int) -> pfc.schemas.Bastion:
        return await self._run(lambda: self._sync.get_bastion(id))

    async def create_bastion(
        self,
        url: str,
        ssh_proxy_jump: str | None,
        tag_id_list: list[int],
        tag_name_value_list: list[dict[str, str]],
    ) -> pfc.schemas.Bastion:
        return await self._run(lambda: self._sync.create_bastion(url, ssh_proxy_jump, tag_id_list, tag_name_value_list))

    async def update_bastion(
        self,
        id: int,
        url: str | None = None,
        ssh_proxy_jump: str | None = None,
        tag_id_list: list[int] | None = None,
        tag_name_value_list: list[pfc.schemas.TagNameValue] | None = None,
    ) -> None:
        return await self._run(
            lambda: self._sync.update_bastion(id, url, ssh_proxy_jump, tag_id_list, tag_name_value_list)
        )

    async def delete_bastion(self, id: int) -> None:
        return await self._run(lambda: self._sync.delete_bastion(id))

    # Roles
    async def list_roles(self, id: int | None = None, name: str | None = None) -> pfc.schemas.RolesResponse:
        return await self._run(lambda: self._sync.list_roles(id, name))

    async def get_role(self, id: int) -> pfc.schemas.Role:
        return await self._run(lambda: self._sync.get_role(id))

    async def create_role(self, name: str, description: str) -> pfc.schemas.Role:
        return await self._run(lambda: self._sync.create_role(name, description))

    async def update_role(
        self,
        id: int,
        name: str | None = None,
        description: str | None = None,
        grant_list: list[pfc.schemas.Grant] | None = None,
        member_list: list[pfc.schemas.RoleMemberRef] | None = None,
    ) -> None:
        return await self._run(lambda: self._sync.update_role(id, name, description, grant_list, member_list))

    async def delete_role(self, id: int) -> None:
        return await self._run(lambda: self._sync.delete_role(id))

    # Boundaries
    async def list_boundaries(self, id: int | None = None, name: str | None = None) -> pfc.schemas.BoundariesResponse:
        return await self._run(lambda: self._sync.list_boundaries(id, name))

    async def get_boundary(self, id: int) -> pfc.schemas.Boundary:
        return await self._run(lambda: self._sync.get_boundary(id))

    async def create_boundary(self, name: str, description: str) -> pfc.schemas.Boundary:
        return await self._run(lambda: self._sync.create_boundary(name, description))

    async def update_boundary(
        self,
        id: int,
        name: str | None = None,
        description: str | None = None,
        ceiling_list: list[pfc.schemas.Grant] | None = None,
        denied_list: list[pfc.schemas.Grant] | None = None,
    ) -> None:
        return await self._run(lambda: self._sync.update_boundary(id, name, description, ceiling_list, denied_list))

    async def delete_boundary(self, id: int) -> None:
        return await self._run(lambda: self._sync.delete_boundary(id))

    # Identities
    async def list_identities(
        self,
        id: int | None = None,
        name: str | None = None,
        tag_id: list[str] | None = None,
        tag_name: list[str] | None = None,
        boundary_id: list[str] | None = None,
        boundary_name: list[str] | None = None,
    ) -> pfc.schemas.IdentitiesResponse:
        return await self._run(
            lambda: self._sync.list_identities(id, name, tag_id, tag_name, boundary_id, boundary_name)
        )

    async def get_identity(self, id: int) -> pfc.schemas.Identity:
        return await self._run(lambda: self._sync.get_identity(id))

    async def create_identity(
        self,
        name: str | None,
        boundary_id_list: list[int],
        boundary_name_list: list[str],
        tag_id_list: list[int],
        tag_name_value_list: list[dict[str, str]],
    ) -> pfc.schemas.Identity:
        return await self._run(
            lambda: self._sync.create_identity(
                name, boundary_id_list, boundary_name_list, tag_id_list, tag_name_value_list
            )
        )

    async def invite_identity(self, id: int, delivery: str) -> str | None:
        return await self._run(lambda: self._sync.invite_identity(id, delivery))

    async def delete_identity(self, id: int) -> None:
        return await self._run(lambda: self._sync.delete_identity(id))

    async def update_identity(
        self,
        id: int,
        name: str | None = None,
        tags: list[pfc.schemas.IdentityTagOp] | None = None,
    ) -> None:
        return await self._run(lambda: self._sync.update_identity(id, name, tags))

    # Session / Auth flow
    async def initialize(self, key: str) -> None:
        return await self._run(lambda: self._sync.initialize(key))

    async def connect(self, invitation: str, key: str) -> None:
        return await self._run(lambda: self._sync.connect(invitation, key))

    async def get_public_auth(self, auth_name: str) -> pfc.schemas.AuthPublic:
        return await self._run(lambda: self._sync.get_public_auth(auth_name))

    async def list_public_auths(self) -> list[pfc.schemas.AuthPublicSummary]:
        return await self._run(lambda: self._sync.list_public_auths())

    async def login_http_sig(
        self,
        session_public_key: dict[str, typing.Any],
        session_fingerprint: str,
    ) -> None:
        return await self._run(lambda: self._sync.login_http_sig(session_public_key, session_fingerprint))

    async def login_oidc(
        self,
        auth_name: str,
        id_token: str,
        session_public_key: dict[str, typing.Any],
        session_fingerprint: str,
    ) -> None:
        return await self._run(
            lambda: self._sync.login_oidc(auth_name, id_token, session_public_key, session_fingerprint)
        )

    async def login_oauth2_start(
        self,
        auth_name: str,
        session_public_key: dict[str, typing.Any],
        session_fingerprint: str,
        client_redirect_uri: str,
    ) -> str:
        return await self._run(
            lambda: self._sync.login_oauth2_start(
                auth_name, session_public_key, session_fingerprint, client_redirect_uri
            )
        )

    async def list_audit_log(
        self,
        level: int | None = None,
        object_type: str | None = None,
        by_identity_id: str | None = None,
        start_time: int | None = None,
        end_time: int | None = None,
    ) -> pfc.schemas.AuditLogListResponse:
        return await self._run(
            lambda: self._sync.list_audit_log(level, object_type, by_identity_id, start_time, end_time)
        )
