import asyncio
import typing

from . import configuration, schemas, sync


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
    async def list_ssh_hosts(self) -> schemas.SshHostsResponse:
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
    ) -> schemas.SshUserCertificateResponse:
        return await self._run(lambda: self._sync.get_user_certificate(hostname, username, action, public_key, command))

    async def get_user_trusted_keys_public(self) -> str:
        return await self._run(self._sync.get_user_trusted_keys_public)

    async def sign_host_certificates(
        self, public_keys: list[dict[str, typing.Any]]
    ) -> schemas.SshHostCertificateResponse:
        return await self._run(lambda: self._sync.sign_host_certificates(public_keys))

    # Identity/Self
    async def get_self_bastions(self) -> schemas.IdentitySelfBastionListResponse:
        return await self._run(self._sync.get_self_bastions)

    async def get_self_token(self, service: str) -> schemas.IdentitySelfTokenResponse:
        return await self._run(lambda: self._sync.get_self_token(service))

    # Tags
    async def list_tags(
        self,
        id: int | None = None,
        name: str | None = None,
        value: str | None = None,
    ) -> schemas.TagsResponse:
        return await self._run(lambda: self._sync.list_tags(id, name, value))

    async def create_tag(self, name: str, value: str) -> schemas.Tag:
        return await self._run(lambda: self._sync.create_tag(name, value))

    async def delete_tag(self, id: int) -> None:
        return await self._run(lambda: self._sync.delete_tag(id))

    # Tenants
    async def list_tenants(self, id: int | None = None) -> schemas.TenantsResponse:
        return await self._run(lambda: self._sync.list_tenants(id))

    async def get_tenant(self, id: int) -> schemas.Tenant:
        return await self._run(lambda: self._sync.get_tenant(id))

    async def create_tenant(self, name: str, display_name: str) -> schemas.Tenant:
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
    async def list_auths(self) -> schemas.AuthListResponse:
        return await self._run(self._sync.list_auths)

    async def get_auth(self, id: int) -> schemas.Auth:
        return await self._run(lambda: self._sync.get_auth(id))

    async def create_auth_http_sig(self, name: str, description: str, tags: list[dict[str, str]]) -> schemas.Auth:
        return await self._run(lambda: self._sync.create_auth_http_sig(name, description, tags))

    async def create_auth_oidc(
        self,
        name: str,
        description: str,
        tags: list[dict[str, str]],
        issuer: str,
        client_id: str,
        client_secret: str | None,
    ) -> schemas.Auth:
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
    ) -> schemas.Auth:
        return await self._run(
            lambda: self._sync.create_auth_oauth2_github(name, description, tags, client_id, client_secret)
        )

    async def update_auth(
        self,
        id: int,
        name: str | None = None,
        description: str | None = None,
        is_enabled: bool | None = None,
        tags: list[schemas.TagNameValue] | None = None,
    ) -> None:
        return await self._run(lambda: self._sync.update_auth(id, name, description, is_enabled, tags))

    async def delete_auth(self, id: int) -> None:
        return await self._run(lambda: self._sync.delete_auth(id))

    # Bastions
    async def list_bastions(self, id: int | None = None) -> schemas.BastionListResponse:
        return await self._run(lambda: self._sync.list_bastions(id))

    async def get_bastion(self, id: int) -> schemas.Bastion:
        return await self._run(lambda: self._sync.get_bastion(id))

    async def create_bastion(
        self,
        register_url: str,
        connect_url: str | None,
        ssh_proxy_jump: str | None,
        tag_id_list: list[int],
        tag_name_value_list: list[dict[str, str]],
    ) -> schemas.Bastion:
        return await self._run(
            lambda: self._sync.create_bastion(
                register_url, connect_url, ssh_proxy_jump, tag_id_list, tag_name_value_list
            )
        )

    async def update_bastion(
        self,
        id: int,
        register_url: str | None = None,
        connect_url: str | None = None,
        ssh_proxy_jump: str | None = None,
        tag_id_list: list[int] | None = None,
        tag_name_value_list: list[schemas.TagNameValue] | None = None,
    ) -> None:
        return await self._run(
            lambda: self._sync.update_bastion(
                id, register_url, connect_url, ssh_proxy_jump, tag_id_list, tag_name_value_list
            )
        )

    async def delete_bastion(self, id: int) -> None:
        return await self._run(lambda: self._sync.delete_bastion(id))

    # Roles
    async def list_roles(self, id: int | None = None, name: str | None = None) -> schemas.RolesResponse:
        return await self._run(lambda: self._sync.list_roles(id, name))

    async def get_role(self, id: int) -> schemas.Role:
        return await self._run(lambda: self._sync.get_role(id))

    async def create_role(self, name: str, description: str) -> schemas.Role:
        return await self._run(lambda: self._sync.create_role(name, description))

    async def update_role(
        self,
        id: int,
        name: str | None = None,
        description: str | None = None,
        grant_list: list[schemas.Grant] | None = None,
        member_list: list[schemas.RoleMemberRef] | None = None,
    ) -> None:
        return await self._run(lambda: self._sync.update_role(id, name, description, grant_list, member_list))

    async def delete_role(self, id: int) -> None:
        return await self._run(lambda: self._sync.delete_role(id))

    # Boundaries
    async def list_boundaries(self, id: int | None = None, name: str | None = None) -> schemas.BoundariesResponse:
        return await self._run(lambda: self._sync.list_boundaries(id, name))

    async def get_boundary(self, id: int) -> schemas.Boundary:
        return await self._run(lambda: self._sync.get_boundary(id))

    async def create_boundary(self, name: str, description: str) -> schemas.Boundary:
        return await self._run(lambda: self._sync.create_boundary(name, description))

    async def update_boundary(
        self,
        id: int,
        name: str | None = None,
        description: str | None = None,
        ceiling_list: list[schemas.Grant] | None = None,
        denied_list: list[schemas.Grant] | None = None,
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
    ) -> schemas.IdentitiesResponse:
        return await self._run(
            lambda: self._sync.list_identities(id, name, tag_id, tag_name, boundary_id, boundary_name)
        )

    async def get_identity(self, id: int) -> schemas.Identity:
        return await self._run(lambda: self._sync.get_identity(id))

    async def create_identity(
        self,
        name: str | None,
        boundary_id_list: list[int],
        boundary_name_list: list[str],
        tag_id_list: list[int],
        tag_name_value_list: list[dict[str, str]],
    ) -> schemas.Identity:
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
        tags: list[schemas.IdentityTagOp] | None = None,
    ) -> None:
        return await self._run(lambda: self._sync.update_identity(id, name, tags))

    # Session / Auth flow
    async def initialize(self, key: str) -> None:
        return await self._run(lambda: self._sync.initialize(key))

    async def connect(self, invitation: str, key: str) -> None:
        return await self._run(lambda: self._sync.connect(invitation, key))

    async def get_public_auth(self, auth_name: str) -> schemas.AuthPublic:
        return await self._run(lambda: self._sync.get_public_auth(auth_name))

    async def http_sig_login(
        self,
        session_public_key: dict[str, typing.Any],
        session_fingerprint: str,
    ) -> None:
        return await self._run(lambda: self._sync.http_sig_login(session_public_key, session_fingerprint))

    async def oidc_login(
        self,
        auth_name: str,
        id_token: str,
        session_public_key: dict[str, typing.Any],
        session_fingerprint: str,
    ) -> None:
        return await self._run(
            lambda: self._sync.oidc_login(auth_name, id_token, session_public_key, session_fingerprint)
        )

    async def oauth2_login_start(
        self,
        auth_name: str,
        session_public_key: dict[str, typing.Any],
        session_fingerprint: str,
        client_redirect_uri: str,
    ) -> str:
        return await self._run(
            lambda: self._sync.oauth2_login_start(
                auth_name, session_public_key, session_fingerprint, client_redirect_uri
            )
        )
