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
