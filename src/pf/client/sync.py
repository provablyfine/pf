import requests

from . import configuration, exceptions, schemas
from .http_client import Client as HttpClient


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
        self._client = HttpClient(config, timeout)

    def list_ssh_hosts(self) -> schemas.SshHostsResponse:
        http = self._client.session_auth(self._client.config.session_key)
        response = http.get(f"{http.directory.ssh}/hosts")
        if response.status_code != 200:
            raise exceptions.UI(_problem_title(response, "Failed to list SSH hosts"))
        return schemas.SshHostsResponse.model_validate(response.json())

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

    def create_tag(self, name: str, value: str) -> None:
        http = self._client.session_auth(self._client.config.session_key)
        response = http.post(
            http.directory.tag,
            json={"name": name, "value": value},
        )
        if response.status_code != 201:
            raise exceptions.UI(_problem_title(response, "Unable to create tag"))

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
