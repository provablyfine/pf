from __future__ import annotations

import typing

from . import directory, exceptions, http_session, http_signatures, schemas, signer


def _problem_title(response: typing.Any, default: str) -> str:
    try:
        title = response.json().get("title")
        if title:
            return str(title)
    except Exception:
        pass
    return default


class SessionClient:
    """API methods that require session authentication."""

    def __init__(
        self, session: http_session.HttpSession, _directory: directory.Directory, session_signer: signer.Signer
    ) -> None:
        self._session = session
        self._directory = _directory
        self._session_signer = session_signer

    def _auth(self) -> http_signatures.Auth:
        return http_signatures.Auth([self._session_signer])

    # SSH

    def list_ssh_hosts(self) -> schemas.SshHostsResponse:
        response = self._session.get(f"{self._directory.ssh}/hosts", auth=self._auth())
        if response.status_code != 200:
            raise exceptions.UI(_problem_title(response, "Failed to list SSH hosts"))
        return schemas.SshHostsResponse.model_validate(response.json())

    def get_host_trusted_keys(self) -> str:
        response = self._session.get(f"{self._directory.ssh}/host/trusted-keys", auth=self._auth())
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
        body: dict[str, typing.Any] = {
            "public_key": public_key,
            "hostname": hostname,
            "username": username,
            "action": action,
        }
        if command is not None:
            body["command"] = command
        response = self._session.post(f"{self._directory.ssh}/user/certificate", auth=self._auth(), json=body)
        if response.status_code == 403:
            raise exceptions.Forbidden("User is not authorized to connect to host")
        if response.status_code != 200:
            raise exceptions.UI(_problem_title(response, "Failed to get user certificate"))
        return schemas.SshUserCertificateResponse.model_validate(response.json())

    def sign_host_certificates(self, public_keys: list[dict[str, typing.Any]]) -> schemas.SshHostCertificateResponse:
        response = self._session.post(
            f"{self._directory.ssh}/host/certificate",
            auth=self._auth(),
            json={"public_keys": public_keys},
        )
        if response.status_code != 200:
            raise exceptions.UI(_problem_title(response, "Failed to sign host certificates"))
        return schemas.SshHostCertificateResponse.model_validate(response.json())

    # Identity / self

    def list_self_bastions(self) -> schemas.IdentitySelfBastionListResponse:
        response = self._session.get(f"{self._directory.identity}/self/bastions", auth=self._auth())
        if response.status_code != 200:
            raise exceptions.UI(_problem_title(response, "Failed to get bastions"))
        return schemas.IdentitySelfBastionListResponse.model_validate(response.json())

    def get_self_token(self, service: str) -> schemas.IdentitySelfTokenResponse:
        response = self._session.get(
            f"{self._directory.identity}/self/token",
            auth=self._auth(),
            params={"service": service},
        )
        if response.status_code != 200:
            raise exceptions.UI(_problem_title(response, "Failed to get token"))
        return schemas.IdentitySelfTokenResponse.model_validate(response.json())

    # Tags

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
        response = self._session.get(self._directory.tag, auth=self._auth(), params=params)
        if response.status_code != 200:
            params_str = ",".join("=".join(str(v) for v in kv) for kv in params.items())
            raise exceptions.UI(f"Unable to find tags {params_str}")
        return schemas.TagsResponse.model_validate(response.json())

    def create_tag(self, name: str, value: str) -> schemas.Tag:
        response = self._session.post(
            self._directory.tag,
            auth=self._auth(),
            json={"name": name, "value": value},
        )
        if response.status_code != 201:
            raise exceptions.UI(_problem_title(response, "Unable to create tag"))
        return schemas.Tag.model_validate(response.json())

    def delete_tag(self, id: int) -> None:
        response = self._session.delete(f"{self._directory.tag}/{id}", auth=self._auth())
        if response.status_code != 204:
            raise exceptions.UI(_problem_title(response, "Unable to delete tag"))

    # Tenants

    def list_tenants(self, id: int | None = None) -> schemas.TenantsResponse:
        params: dict[str, int] = {}
        if id is not None:
            params["id"] = id
        response = self._session.get(self._directory.tenant, auth=self._auth(), params=params)
        if response.status_code != 200:
            raise exceptions.UI(_problem_title(response, "Unable to list tenants"))
        return schemas.TenantsResponse.model_validate(response.json())

    def get_tenant(self, id: int) -> schemas.Tenant:
        response = self._session.get(f"{self._directory.tenant}/{id}", auth=self._auth())
        if response.status_code == 404:
            raise exceptions.UI(f"Tenant {id} not found")
        if response.status_code != 200:
            raise exceptions.UI(_problem_title(response, "Unable to get tenant"))
        return schemas.Tenant.model_validate(response.json())

    def create_tenant(self, name: str, display_name: str) -> schemas.Tenant:
        response = self._session.post(
            self._directory.tenant,
            auth=self._auth(),
            json={"name": name, "display_name": display_name},
        )
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
        response = self._session.patch(f"{self._directory.tenant}/{id}", auth=self._auth(), json=data)
        if response.status_code == 404:
            raise exceptions.UI(f"Tenant {id} not found")
        if response.status_code != 204:
            raise exceptions.UI(_problem_title(response, "Unable to update tenant"))

    def delete_tenant(self, id: int) -> None:
        response = self._session.delete(f"{self._directory.tenant}/{id}", auth=self._auth())
        if response.status_code == 404:
            raise exceptions.UI(f"Tenant {id} not found")
        if response.status_code != 204:
            raise exceptions.UI(_problem_title(response, "Unable to delete tenant"))

    # Auth configs

    def list_auths(self) -> schemas.AuthListResponse:
        response = self._session.get(self._directory.auth, auth=self._auth())
        if response.status_code != 200:
            raise exceptions.UI(_problem_title(response, "Unable to list auth configs"))
        return schemas.AuthListResponse.model_validate(response.json())

    def get_auth(self, id: int) -> schemas.Auth:
        response = self._session.get(f"{self._directory.auth}/{id}", auth=self._auth())
        if response.status_code == 404:
            raise exceptions.UI("Auth config not found")
        if response.status_code != 200:
            raise exceptions.UI(_problem_title(response, "Unable to read auth config"))
        return schemas.Auth.model_validate(response.json())

    def create_auth_http_sig(
        self, name: str, client_type: str, description: str, tags: list[dict[str, str]]
    ) -> schemas.Auth:
        body = {
            "name": name,
            "client_type": client_type,
            "description": description,
            "config": {"type": "http_sig"},
            "tags": tags,
        }
        response = self._session.post(self._directory.auth, auth=self._auth(), json=body)
        if response.status_code != 201:
            raise exceptions.UI(_problem_title(response, "Unable to create auth config"))
        return schemas.Auth.model_validate(response.json())

    def create_auth_oidc(
        self,
        name: str,
        client_type: str,
        description: str,
        tags: list[dict[str, str]],
        issuer: str,
        client_id: str,
        client_secret: str | None,
    ) -> schemas.Auth:
        config: dict[str, str] = {"type": "oidc", "issuer": issuer, "client_id": client_id}
        if client_secret is not None:
            config["client_secret"] = client_secret
        body = {"name": name, "client_type": client_type, "description": description, "config": config, "tags": tags}
        response = self._session.post(self._directory.auth, auth=self._auth(), json=body)
        if response.status_code != 201:
            raise exceptions.UI(_problem_title(response, "Unable to create auth config"))
        return schemas.Auth.model_validate(response.json())

    def create_auth_oidc_device_code(
        self,
        name: str,
        client_type: str,
        description: str,
        tags: list[dict[str, str]],
        issuer: str,
        client_id: str,
        client_secret: str | None,
    ) -> schemas.Auth:
        config: dict[str, str] = {"type": "oidc-device-code", "issuer": issuer, "client_id": client_id}
        if client_secret is not None:
            config["client_secret"] = client_secret
        body = {"name": name, "client_type": client_type, "description": description, "config": config, "tags": tags}
        response = self._session.post(self._directory.auth, auth=self._auth(), json=body)
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
        response = self._session.patch(f"{self._directory.auth}/{id}", auth=self._auth(), json=body)
        if response.status_code == 404:
            raise exceptions.UI("Auth config not found")
        if response.status_code != 200:
            raise exceptions.UI(_problem_title(response, "Unable to update auth config"))

    def delete_auth(self, id: int) -> None:
        response = self._session.delete(f"{self._directory.auth}/{id}", auth=self._auth())
        if response.status_code == 404:
            raise exceptions.UI("Auth config not found")
        if response.status_code != 204:
            raise exceptions.UI(_problem_title(response, "Unable to delete auth config"))

    # Bastions

    def list_bastions(self, id: int | None = None) -> schemas.BastionListResponse:
        params: dict[str, int] = {}
        if id is not None:
            params["id"] = id
        response = self._session.get(self._directory.bastion, auth=self._auth(), params=params)
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
        url: str,
        ssh_proxy_jump: str | None,
        tag_id_list: list[int],
        tag_name_value_list: list[dict[str, str]],
    ) -> schemas.Bastion:
        response = self._session.post(
            self._directory.bastion,
            auth=self._auth(),
            json={
                "url": url,
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
        url: str | None = None,
        ssh_proxy_jump: str | None = None,
        tag_id_list: list[int] | None = None,
        tag_name_value_list: list[schemas.TagNameValue] | None = None,
    ) -> None:
        query: dict[str, typing.Any] = {}
        if url is not None:
            query["url"] = url
        if ssh_proxy_jump is not None:
            query["ssh_proxy_jump"] = ssh_proxy_jump
        if tag_id_list is not None:
            query["tag_id_list"] = tag_id_list
        if tag_name_value_list is not None:
            query["tag_name_value_list"] = [{"name": t.name, "value": t.value} for t in tag_name_value_list]
        if not query:
            raise exceptions.UI("No fields to update")
        response = self._session.patch(f"{self._directory.bastion}/{id}", auth=self._auth(), json=query)
        if response.status_code != 200:
            raise exceptions.UI(_problem_title(response, "Unable to update bastion"))

    def delete_bastion(self, id: int) -> None:
        response = self._session.delete(f"{self._directory.bastion}/{id}", auth=self._auth())
        if response.status_code != 204:
            raise exceptions.UI(_problem_title(response, "Unable to delete bastion"))

    # Roles

    def list_roles(self, id: int | None = None, name: str | None = None) -> schemas.RolesResponse:
        params: dict[str, int | str] = {}
        if id is not None:
            params["id"] = id
        if name is not None:
            params["name"] = name
        response = self._session.get(self._directory.role, auth=self._auth(), params=params)
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
        response = self._session.post(
            self._directory.role,
            auth=self._auth(),
            json={"name": name, "description": description},
        )
        if response.status_code != 201:
            raise exceptions.UI(_problem_title(response, "Unable to create role"))
        return schemas.Role.model_validate(response.json())

    def update_role(
        self,
        id: int,
        name: str | None = None,
        description: str | None = None,
        grant_list: list[schemas.Grant] | None = None,
        member_list: list[schemas.RoleMemberUpdateRequest] | None = None,
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
        response = self._session.patch(f"{self._directory.role}/{id}", auth=self._auth(), json=body)
        if response.status_code != 200:
            raise exceptions.UI(_problem_title(response, "Unable to update role"))

    def delete_role(self, id: int) -> None:
        response = self._session.delete(f"{self._directory.role}/{id}", auth=self._auth())
        if response.status_code != 204:
            raise exceptions.UI(_problem_title(response, "Unable to delete role"))

    # Boundaries

    def list_boundaries(self, id: int | None = None, name: str | None = None) -> schemas.BoundariesResponse:
        params: dict[str, int | str] = {}
        if id is not None:
            params["id"] = id
        if name is not None:
            params["name"] = name
        response = self._session.get(self._directory.boundary, auth=self._auth(), params=params)
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
        response = self._session.post(
            self._directory.boundary,
            auth=self._auth(),
            json={"name": name, "description": description},
        )
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
        response = self._session.patch(f"{self._directory.boundary}/{id}", auth=self._auth(), json=body)
        if response.status_code != 200:
            raise exceptions.UI(_problem_title(response, "Unable to update boundary"))

    def delete_boundary(self, id: int) -> None:
        response = self._session.delete(f"{self._directory.boundary}/{id}", auth=self._auth())
        if response.status_code != 204:
            raise exceptions.UI(_problem_title(response, "Unable to delete boundary"))

    # Identities

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
        response = self._session.get(self._directory.identity, auth=self._auth(), params=params)
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
        response = self._session.post(
            self._directory.identity,
            auth=self._auth(),
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
        response = self._session.post(
            f"{self._directory.identity}/{id}/invite",
            auth=self._auth(),
            json={"delivery": delivery},
        )
        if response.status_code == 204:
            return None
        if response.status_code == 200:
            return response.json()["key"]["k"]
        raise exceptions.UI(_problem_title(response, "Unable to invite identity"))

    def delete_identity(self, id: int) -> None:
        response = self._session.delete(f"{self._directory.identity}/{id}", auth=self._auth())
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
        response = self._session.patch(f"{self._directory.identity}/{id}", auth=self._auth(), json=body)
        if response.status_code != 200:
            raise exceptions.UI(_problem_title(response, "Unable to update identity"))

    # Auth flow

    def login_oidc(
        self,
        auth_name: str,
        client_type: str,
        id_token: str,
        session_public_key: dict[str, typing.Any],
    ) -> None:
        response = self._session.post(
            self._directory.login_oidc,
            auth=self._auth(),
            json={
                "auth_name": auth_name,
                "client_type": client_type,
                "id_token": id_token,
                "session_public_key": session_public_key,
            },
        )
        if response.status_code != 204:
            raise exceptions.UI(f"Unable to login via OIDC: {response.text}")

    # Audit log

    def list_audit_log(
        self,
        level: int | None = None,
        object_type: str | None = None,
        by_identity_id: str | None = None,
        start_time: int | None = None,
        end_time: int | None = None,
    ) -> schemas.AuditLogListResponse:
        params: dict[str, int | str] = {}
        if level is not None:
            params["level"] = level
        if object_type is not None:
            params["object_type"] = object_type
        if by_identity_id is not None:
            params["by_identity_id"] = by_identity_id
        if start_time is not None:
            params["start_time"] = start_time
        if end_time is not None:
            params["end_time"] = end_time
        response = self._session.get(self._directory.audit_log, auth=self._auth(), params=params)
        if response.status_code != 200:
            raise exceptions.UI(_problem_title(response, "Unable to list audit log"))
        return schemas.AuditLogListResponse.model_validate(response.json())
