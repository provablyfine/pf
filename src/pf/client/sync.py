import typing

import requests

from . import configuration, exceptions, http_client, schemas


def _problem_title(response: requests.Response, default: str) -> str:
    """Extract title from a RFC 7807 Problem Details response, or return default."""
    try:
        title = response.json().get("title")
        if title:
            return str(title)
    except Exception:
        pass
    return default


class Client:
    def __init__(self, config: configuration.Config, timeout: float = 1.0) -> None:
        self._client = http_client.Client(config, timeout)

    def list_ssh_hosts(self) -> schemas.SshHostsResponse:
        http = self._client.session_auth(self._client.config.session_key)
        response = http.get(f"{http.directory.ssh}/hosts")
        if response.status_code != 200:
            raise exceptions.UI(_problem_title(response, "Failed to list SSH hosts"))
        return schemas.SshHostsResponse.model_validate(response.json())

    def get_host_trusted_keys(self) -> str:
        http = self._client.session_auth(self._client.config.session_key)
        response = http.get(f"{http.directory.ssh}/host/trusted-keys")
        if response.status_code != 200:
            raise exceptions.UI(_problem_title(response, "Failed to get host trusted keys"))
        return response.content.decode("utf-8")

    def get_user_certificate(
        self,
        hostname: str,
        username: str,
        action: str,
        public_key: dict[str, typing.Any],
        command: str | None = None,
    ) -> schemas.SshUserCertificateResponse:
        http = self._client.session_auth(self._client.config.session_key)
        body: dict[str, typing.Any] = {
            "public_key": public_key,
            "hostname": hostname,
            "username": username,
            "action": action,
        }
        if command is not None:
            body["command"] = command
        response = http.post(f"{http.directory.ssh}/user/certificate", json=body)
        if response.status_code == 403:
            raise exceptions.Forbidden("User is not authorized to connect to host")
        elif response.status_code != 200:
            raise exceptions.UI(_problem_title(response, "Failed to get user certificate"))
        return schemas.SshUserCertificateResponse.model_validate(response.json())

    def get_user_trusted_keys_public(self) -> str:
        """Get user trusted keys without authentication."""
        http = self._client.no_auth
        response = http.get(f"{http.directory.ssh}/user/trusted-keys")
        if response.status_code != 200:
            raise exceptions.UI(_problem_title(response, "Failed to get user trusted keys"))
        return response.text

    def sign_host_certificates(self, public_keys: list[dict[str, typing.Any]]) -> schemas.SshHostCertificateResponse:
        """Sign host certificates."""
        http = self._client.session_auth(self._client.config.session_key)
        response = http.post(f"{http.directory.ssh}/host/certificate", json={"public_keys": public_keys})
        if response.status_code != 200:
            raise exceptions.UI(_problem_title(response, "Failed to sign host certificates"))
        return schemas.SshHostCertificateResponse.model_validate(response.json())

    def get_self_bastions(self) -> schemas.IdentitySelfBastionListResponse:
        http = self._client.session_auth(self._client.config.session_key)
        response = http.get(f"{http.directory.identity}/self/bastions")
        if response.status_code != 200:
            raise exceptions.UI(_problem_title(response, "Failed to get bastions"))
        return schemas.IdentitySelfBastionListResponse.model_validate(response.json())

    def get_self_token(self, service: str) -> schemas.IdentitySelfTokenResponse:
        http = self._client.session_auth(self._client.config.session_key)
        response = http.get(f"{http.directory.identity}/self/token", params={"service": service})
        if response.status_code != 200:
            raise exceptions.UI(_problem_title(response, "Failed to get token"))
        return schemas.IdentitySelfTokenResponse.model_validate(response.json())

    def list_tags(
        self,
        id: int | None = None,
        name: str | None = None,
        value: str | None = None,
    ) -> schemas.TagsResponse:
        params: dict[str, int | str] = {}
        if id is not None:
            params["id"] = id
        if name is not None:
            params["name"] = name
        if value is not None:
            params["value"] = value

        http = self._client.session_auth(self._client.config.session_key)
        response = http.get(http.directory.tag, params=params)
        if response.status_code != 200:
            params_str = ",".join("=".join(str(v) for v in kv) for kv in params.items())
            raise exceptions.UI(f"Unable to find tags {params_str}")
        return schemas.TagsResponse.model_validate(response.json())

    def create_tag(self, name: str, value: str) -> schemas.Tag:
        http = self._client.session_auth(self._client.config.session_key)
        response = http.post(
            http.directory.tag,
            json={"name": name, "value": value},
        )
        if response.status_code != 201:
            raise exceptions.UI(_problem_title(response, "Unable to create tag"))
        return schemas.Tag.model_validate(response.json())

    def delete_tag(self, id: int) -> None:
        http = self._client.session_auth(self._client.config.session_key)
        response = http.delete(f"{http.directory.tag}/{id}")
        if response.status_code != 204:
            raise exceptions.UI(_problem_title(response, "Unable to delete tag"))

    def list_tenants(self, id: int | None = None) -> schemas.TenantsResponse:
        params: dict[str, int] = {}
        if id is not None:
            params["id"] = id
        http = self._client.session_auth(self._client.config.session_key)
        response = http.get(http.directory.tenant, params=params)
        if response.status_code != 200:
            raise exceptions.UI(_problem_title(response, "Unable to list tenants"))
        return schemas.TenantsResponse.model_validate(response.json())

    def get_tenant(self, id: int) -> schemas.Tenant:
        http = self._client.session_auth(self._client.config.session_key)
        response = http.get(f"{http.directory.tenant}/{id}")
        if response.status_code == 404:
            raise exceptions.UI(f"Tenant {id} not found")
        if response.status_code != 200:
            raise exceptions.UI(_problem_title(response, "Unable to get tenant"))
        return schemas.Tenant.model_validate(response.json())

    def create_tenant(self, name: str, display_name: str) -> schemas.Tenant:
        http = self._client.session_auth(self._client.config.session_key)
        response = http.post(http.directory.tenant, json={"name": name, "display_name": display_name})
        if response.status_code != 200:
            raise exceptions.UI(_problem_title(response, "Unable to create tenant"))
        return schemas.Tenant.model_validate(response.json())

    def update_tenant(
        self,
        id: int,
        display_name: str | None = None,
        is_enabled: bool | None = None,
    ) -> None:
        data: dict[str, str | bool] = {}
        if display_name is not None:
            data["display_name"] = display_name
        if is_enabled is not None:
            data["is_enabled"] = is_enabled
        if not data:
            raise exceptions.UI("Nothing to update")
        http = self._client.session_auth(self._client.config.session_key)
        response = http.patch(f"{http.directory.tenant}/{id}", json=data)
        if response.status_code == 404:
            raise exceptions.UI(f"Tenant {id} not found")
        if response.status_code != 204:
            raise exceptions.UI(_problem_title(response, "Unable to update tenant"))

    def delete_tenant(self, id: int) -> None:
        http = self._client.session_auth(self._client.config.session_key)
        response = http.delete(f"{http.directory.tenant}/{id}")
        if response.status_code == 404:
            raise exceptions.UI(f"Tenant {id} not found")
        if response.status_code != 204:
            raise exceptions.UI(_problem_title(response, "Unable to delete tenant"))

    def list_auths(self) -> schemas.AuthListResponse:
        http = self._client.session_auth(self._client.config.session_key)
        response = http.get(http.directory.auth)
        if response.status_code != 200:
            raise exceptions.UI(_problem_title(response, "Unable to list auth configs"))
        return schemas.AuthListResponse.model_validate(response.json())

    def get_auth(self, id: int) -> schemas.Auth:
        http = self._client.session_auth(self._client.config.session_key)
        response = http.get(f"{http.directory.auth}/{id}")
        if response.status_code == 404:
            raise exceptions.UI("Auth config not found")
        if response.status_code != 200:
            raise exceptions.UI(_problem_title(response, "Unable to read auth config"))
        return schemas.Auth.model_validate(response.json())

    def create_auth_http_sig(self, name: str, description: str, tags: list[dict[str, str]]) -> schemas.Auth:
        http = self._client.session_auth(self._client.config.session_key)
        body = {
            "name": name,
            "description": description,
            "config": {"type": "http_sig"},
            "tags": tags,
        }
        response = http.post(http.directory.auth, json=body)
        if response.status_code != 201:
            raise exceptions.UI(_problem_title(response, "Unable to create auth config"))
        return schemas.Auth.model_validate(response.json())

    def create_auth_oidc(
        self,
        name: str,
        description: str,
        tags: list[dict[str, str]],
        issuer: str,
        client_id: str,
        client_secret: str | None,
    ) -> schemas.Auth:
        http = self._client.session_auth(self._client.config.session_key)
        config: dict[str, str] = {
            "type": "oidc",
            "issuer": issuer,
            "client_id": client_id,
        }
        if client_secret is not None:
            config["client_secret"] = client_secret
        body = {"name": name, "description": description, "config": config, "tags": tags}
        response = http.post(http.directory.auth, json=body)
        if response.status_code != 201:
            raise exceptions.UI(_problem_title(response, "Unable to create auth config"))
        return schemas.Auth.model_validate(response.json())

    def create_auth_oauth2_github(
        self,
        name: str,
        description: str,
        tags: list[dict[str, str]],
        client_id: str,
        client_secret: str,
    ) -> schemas.Auth:
        http = self._client.session_auth(self._client.config.session_key)
        config = {
            "type": "oauth2-github",
            "client_id": client_id,
            "client_secret": client_secret,
        }
        body = {"name": name, "description": description, "config": config, "tags": tags}
        response = http.post(http.directory.auth, json=body)
        if response.status_code != 201:
            raise exceptions.UI(_problem_title(response, "Unable to create auth config"))
        return schemas.Auth.model_validate(response.json())

    def update_auth(
        self,
        id: int,
        name: str | None = None,
        description: str | None = None,
        is_enabled: bool | None = None,
        tags: list[schemas.TagNameValue] | None = None,
    ) -> None:
        body: dict[str, typing.Any] = {}
        if name is not None:
            body["name"] = name
        if description is not None:
            body["description"] = description
        if is_enabled is not None:
            body["is_enabled"] = is_enabled
        if tags is not None:
            body["tags"] = [{"name": t.name, "value": t.value} for t in tags]
        if not body:
            raise exceptions.UI("Nothing to update")
        http = self._client.session_auth(self._client.config.session_key)
        response = http.patch(f"{http.directory.auth}/{id}", json=body)
        if response.status_code == 404:
            raise exceptions.UI("Auth config not found")
        if response.status_code != 200:
            raise exceptions.UI(_problem_title(response, "Unable to update auth config"))

    def delete_auth(self, id: int) -> None:
        http = self._client.session_auth(self._client.config.session_key)
        response = http.delete(f"{http.directory.auth}/{id}")
        if response.status_code == 404:
            raise exceptions.UI("Auth config not found")
        if response.status_code != 204:
            raise exceptions.UI(_problem_title(response, "Unable to delete auth config"))

    def list_bastions(self, id: int | None = None) -> schemas.BastionListResponse:
        params: dict[str, int] = {}
        if id is not None:
            params["id"] = id
        http = self._client.session_auth(self._client.config.session_key)
        response = http.get(http.directory.bastion, params=params)
        if response.status_code != 200:
            params_str = ",".join(f"{k}={v}" for k, v in params.items())
            raise exceptions.UI(f"Unable to find bastion {params_str}")
        return schemas.BastionListResponse.model_validate(response.json())

    def get_bastion(self, id: int) -> schemas.Bastion:
        result = self.list_bastions(id=id)
        if len(result.bastions) == 0:
            raise exceptions.UI("No bastion found")
        assert len(result.bastions) == 1
        return result.bastions[0]

    def create_bastion(
        self,
        register_url: str,
        connect_url: str | None,
        ssh_proxy_jump: str | None,
        tag_id_list: list[int],
        tag_name_value_list: list[dict[str, str]],
    ) -> schemas.Bastion:
        http = self._client.session_auth(self._client.config.session_key)
        response = http.post(
            http.directory.bastion,
            json={
                "register_url": register_url,
                "connect_url": connect_url,
                "ssh_proxy_jump": ssh_proxy_jump,
                "tag_id_list": tag_id_list,
                "tag_name_value_list": tag_name_value_list,
            },
        )
        if response.status_code != 201:
            raise exceptions.UI(_problem_title(response, "Unable to create bastion"))
        return schemas.Bastion.model_validate(response.json())

    def update_bastion(
        self,
        id: int,
        register_url: str | None = None,
        connect_url: str | None = None,
        ssh_proxy_jump: str | None = None,
        tag_id_list: list[int] | None = None,
        tag_name_value_list: list[schemas.TagNameValue] | None = None,
    ) -> None:
        query: dict[str, typing.Any] = {}
        if register_url is not None:
            query["register_url"] = register_url
        if connect_url is not None:
            query["connect_url"] = connect_url
        if ssh_proxy_jump is not None:
            query["ssh_proxy_jump"] = ssh_proxy_jump
        if tag_id_list is not None:
            query["tag_id_list"] = tag_id_list
        if tag_name_value_list is not None:
            query["tag_name_value_list"] = [{"name": t.name, "value": t.value} for t in tag_name_value_list]
        if not query:
            raise exceptions.UI("No fields to update")
        http = self._client.session_auth(self._client.config.session_key)
        response = http.patch(f"{http.directory.bastion}/{id}", json=query)
        if response.status_code != 200:
            raise exceptions.UI(_problem_title(response, "Unable to update bastion"))

    def delete_bastion(self, id: int) -> None:
        http = self._client.session_auth(self._client.config.session_key)
        response = http.delete(f"{http.directory.bastion}/{id}")
        if response.status_code != 204:
            raise exceptions.UI(_problem_title(response, "Unable to delete bastion"))

    def list_roles(self, id: int | None = None, name: str | None = None) -> schemas.RolesResponse:
        params: dict[str, int | str] = {}
        if id is not None:
            params["id"] = id
        if name is not None:
            params["name"] = name
        http = self._client.session_auth(self._client.config.session_key)
        response = http.get(http.directory.role, params=params)
        if response.status_code != 200:
            params_str = ",".join(f"{k}={v}" for k, v in params.items())
            raise exceptions.UI(f"Unable to find role {params_str}")
        return schemas.RolesResponse.model_validate(response.json())

    def get_role(self, id: int) -> schemas.Role:
        result = self.list_roles(id=id)
        if len(result.roles) == 0:
            raise exceptions.UI("No role found")
        assert len(result.roles) == 1
        return result.roles[0]

    def create_role(self, name: str, description: str) -> schemas.Role:
        http = self._client.session_auth(self._client.config.session_key)
        response = http.post(http.directory.role, json={"name": name, "description": description})
        if response.status_code != 201:
            raise exceptions.UI(_problem_title(response, "Unable to create role"))
        return schemas.Role.model_validate(response.json())

    def update_role(
        self,
        id: int,
        name: str | None = None,
        description: str | None = None,
        grant_list: list[schemas.Grant] | None = None,
        member_list: list[schemas.RoleMemberRef] | None = None,
    ) -> None:
        body: dict[str, typing.Any] = {}
        if name is not None:
            body["name"] = name
        if description is not None:
            body["description"] = description
        if grant_list is not None:
            body["grant_list"] = [g.model_dump() for g in grant_list]
        if member_list is not None:
            body["member_list"] = [m.model_dump(exclude_none=True) for m in member_list]
        if not body:
            raise exceptions.UI("Nothing to update")
        http = self._client.session_auth(self._client.config.session_key)
        response = http.patch(f"{http.directory.role}/{id}", json=body)
        if response.status_code != 200:
            raise exceptions.UI(_problem_title(response, "Unable to update role"))

    def delete_role(self, id: int) -> None:
        http = self._client.session_auth(self._client.config.session_key)
        response = http.delete(f"{http.directory.role}/{id}")
        if response.status_code != 204:
            raise exceptions.UI(_problem_title(response, "Unable to delete role"))

    def list_boundaries(self, id: int | None = None, name: str | None = None) -> schemas.BoundariesResponse:
        params: dict[str, int | str] = {}
        if id is not None:
            params["id"] = id
        if name is not None:
            params["name"] = name
        http = self._client.session_auth(self._client.config.session_key)
        response = http.get(http.directory.boundary, params=params)
        if response.status_code != 200:
            params_str = ",".join(f"{k}={v}" for k, v in params.items())
            raise exceptions.UI(f"Unable to find boundary {params_str}")
        return schemas.BoundariesResponse.model_validate(response.json())

    def get_boundary(self, id: int) -> schemas.Boundary:
        result = self.list_boundaries(id=id)
        if len(result.boundaries) == 0:
            raise exceptions.UI("No boundary found")
        assert len(result.boundaries) == 1
        return result.boundaries[0]

    def create_boundary(self, name: str, description: str) -> schemas.Boundary:
        http = self._client.session_auth(self._client.config.session_key)
        response = http.post(http.directory.boundary, json={"name": name, "description": description})
        if response.status_code != 201:
            raise exceptions.UI(_problem_title(response, "Unable to create boundary"))
        return schemas.Boundary.model_validate(response.json()["boundary"])

    def update_boundary(
        self,
        id: int,
        name: str | None = None,
        description: str | None = None,
        ceiling_list: list[schemas.Grant] | None = None,
        denied_list: list[schemas.Grant] | None = None,
    ) -> None:
        body: dict[str, typing.Any] = {}
        if name is not None:
            body["name"] = name
        if description is not None:
            body["description"] = description
        if ceiling_list is not None:
            body["ceiling_list"] = [g.model_dump() for g in ceiling_list]
        if denied_list is not None:
            body["denied_list"] = [g.model_dump() for g in denied_list]
        if not body:
            raise exceptions.UI("Nothing to update")
        http = self._client.session_auth(self._client.config.session_key)
        response = http.patch(f"{http.directory.boundary}/{id}", json=body)
        if response.status_code != 200:
            raise exceptions.UI(_problem_title(response, "Unable to update boundary"))

    def delete_boundary(self, id: int) -> None:
        http = self._client.session_auth(self._client.config.session_key)
        response = http.delete(f"{http.directory.boundary}/{id}")
        if response.status_code != 204:
            raise exceptions.UI(_problem_title(response, "Unable to delete boundary"))

    def list_identities(
        self,
        id: int | None = None,
        name: str | None = None,
        tag_id: list[str] | None = None,
        tag_name: list[str] | None = None,
        boundary_id: list[str] | None = None,
        boundary_name: list[str] | None = None,
    ) -> schemas.IdentitiesResponse:
        params: dict[str, typing.Any] = {}
        if id is not None:
            params["id"] = id
        if name is not None:
            params["name"] = name
        if tag_id is not None:
            params["tag_id"] = tag_id
        if tag_name is not None:
            params["tag_name"] = tag_name
        if boundary_id is not None:
            params["boundary_id"] = boundary_id
        if boundary_name is not None:
            params["boundary_name"] = boundary_name
        http = self._client.session_auth(self._client.config.session_key)
        response = http.get(http.directory.identity, params=params)
        if response.status_code != 200:
            params_str = ",".join(f"{k}={v}" for k, v in params.items())
            raise exceptions.UI(f"Unable to find identity {params_str}")
        return schemas.IdentitiesResponse.model_validate(response.json())

    def get_identity(self, id: int) -> schemas.Identity:
        result = self.list_identities(id=id)
        if len(result.identities) == 0:
            raise exceptions.UI("No identity found")
        assert len(result.identities) == 1
        return result.identities[0]

    def create_identity(
        self,
        name: str | None,
        boundary_id_list: list[int],
        boundary_name_list: list[str],
        tag_id_list: list[int],
        tag_name_value_list: list[dict[str, str]],
    ) -> schemas.Identity:
        http = self._client.session_auth(self._client.config.session_key)
        response = http.post(
            http.directory.identity,
            json={
                "name": name,
                "boundary_id_list": boundary_id_list,
                "boundary_name_list": boundary_name_list,
                "tag_id_list": tag_id_list,
                "tag_name_value_list": tag_name_value_list,
            },
        )
        if response.status_code != 201:
            raise exceptions.UI(_problem_title(response, "Unable to create identity"))
        return schemas.Identity.model_validate(response.json())

    def invite_identity(self, id: int, delivery: str) -> str | None:
        http = self._client.session_auth(self._client.config.session_key)
        response = http.post(f"{http.directory.identity}/{id}/invite", json={"delivery": delivery})
        if response.status_code == 204:
            return None
        if response.status_code == 200:
            return response.json()["key"]["k"]
        raise exceptions.UI(_problem_title(response, "Unable to invite identity"))

    def delete_identity(self, id: int) -> None:
        http = self._client.session_auth(self._client.config.session_key)
        response = http.delete(f"{http.directory.identity}/{id}")
        if response.status_code != 204:
            raise exceptions.UI(_problem_title(response, "Unable to delete identity"))

    def update_identity(
        self,
        id: int,
        name: str | None = None,
        tags: list[schemas.IdentityTagOp] | None = None,
    ) -> None:
        body: dict[str, typing.Any] = {}
        if name is not None:
            body["name"] = name
        if tags is not None:
            body["tags"] = [op.model_dump(exclude_none=True) for op in tags]
        if not body:
            raise exceptions.UI("Nothing to update")
        http = self._client.session_auth(self._client.config.session_key)
        response = http.patch(f"{http.directory.identity}/{id}", json=body)
        if response.status_code != 200:
            raise exceptions.UI(_problem_title(response, "Unable to update identity"))

    def initialize(self, key: str) -> None:
        """POST to initialize endpoint, then accept the returned invitation."""
        response = self._client.no_auth.post(self._client.directory.initialize)
        if response.status_code == 204:
            raise exceptions.UI("Unable to initialize app: it is already initialized.")
        if response.status_code != 200:
            raise exceptions.UI(f"Unable to initialize app. Unexpected error: {response.status_code}.")
        invitation_key = response.json()["key"]["k"]
        auth = self._client.invitation_auth(account=key, invitation=invitation_key)
        response = auth.post(
            url=auth.directory.accept_invitation,
            json={"account_public_key": auth.account_public_key.to_dict()},
        )
        if response.status_code != 204:
            raise exceptions.UI(f"Unable to accept invitation: {response.text}")

    def connect(self, invitation: str, key: str) -> None:
        """Accept an existing invitation."""
        auth = self._client.invitation_auth(account=key, invitation=invitation)
        response = auth.post(
            url=auth.directory.accept_invitation,
            json={"account_public_key": auth.account_public_key.to_dict()},
        )
        if response.status_code != 204:
            raise exceptions.UI(f"Unable to accept invitation: {response.text}")

    def get_public_auth(self, auth_name: str) -> schemas.AuthPublic:
        """Fetch public auth configuration."""
        http = self._client.no_auth
        response = http.get(f"{http.directory.public_auth}/{auth_name}")
        if response.status_code == 404:
            raise exceptions.UI(f"Auth config '{auth_name}' not found")
        if response.status_code != 200:
            raise exceptions.UI(f"Unable to read auth config: {response.text}")
        return schemas.AuthPublic.model_validate(response.json())

    def list_public_auths(self) -> list[schemas.AuthPublicSummary]:
        """Fetch list of public auth methods."""
        http = self._client.no_auth
        response = http.get(http.directory.public_auth)
        if response.status_code != 200:
            raise exceptions.UI("Unable to list auth methods")
        return [schemas.AuthPublicSummary.model_validate(a) for a in response.json().get("auths", [])]

    def http_sig_login(self, session_public_key: dict[str, typing.Any], session_fingerprint: str) -> None:
        """POST to /login endpoint. Caller manages session key and config updates."""
        auth = self._client.login_auth(account=self._client.config.account_key, session=session_fingerprint)
        response = auth.post(url=auth.directory.login, json={"session_public_key": session_public_key})
        if response.status_code != 204:
            raise exceptions.UI(f"Unable to login successfully: {response.text}")

    def oidc_login(
        self, auth_name: str, id_token: str, session_public_key: dict[str, typing.Any], session_fingerprint: str
    ) -> None:
        """POST to /auth/oidc/login endpoint. Caller manages OIDC flow, session key, and config updates."""
        auth = self._client.session_auth(session=session_fingerprint)
        response = auth.post(
            url=auth.directory.login_oidc,
            json={
                "auth_name": auth_name,
                "id_token": id_token,
                "session_public_key": session_public_key,
            },
        )
        if response.status_code != 204:
            raise exceptions.UI(f"Unable to login via OIDC: {response.text}")

    def oauth2_login_start(
        self,
        auth_name: str,
        session_public_key: dict[str, typing.Any],
        session_fingerprint: str,
        client_redirect_uri: str,
    ) -> str:
        """POST to /auth/oauth2/start and return auth_url.

        Caller manages session key, browser, callback server, and config updates.
        """
        auth = self._client.session_auth(session=session_fingerprint)
        response = auth.post(
            url=auth.directory.login_oauth2_start,
            json={
                "auth_name": auth_name,
                "session_public_key": session_public_key,
                "client_redirect_uri": client_redirect_uri,
            },
        )
        if response.status_code != 200:
            raise exceptions.UI(f"Unable to start OAuth2 login: {response.text}")
        return response.json()["auth_url"]
