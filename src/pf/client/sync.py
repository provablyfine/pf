from . import configuration, exceptions, schemas
from .http_client import Client as HttpClient


class Client:
    def __init__(self, config: configuration.Config, timeout: float = 1.0) -> None:
        self._client = HttpClient(config, timeout)

    def list_ssh_hosts(self) -> schemas.SshHostsResponse:
        http = self._client.session_auth(self._client.config.session_key)
        response = http.get(f"{http.directory.ssh}/hosts")
        if response.status_code != 200:
            raise exceptions.UI(response.json().get("title", "Failed to list SSH hosts"))
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
            title = response.json().get("title", "Unable to create tag")
            raise exceptions.UI(f"Unable to create tag. {title}")

    def delete_tag(self, id: int) -> None:
        http = self._client.session_auth(self._client.config.session_key)
        response = http.delete(f"{http.directory.tag}/{id}")
        if response.status_code != 204:
            title = response.json().get("title", "Unable to delete tag")
            raise exceptions.UI(f"Unable to delete tag. {title}")
