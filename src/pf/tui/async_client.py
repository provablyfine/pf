import asyncio

import requests

from .. import client


class AsyncClient:
    """Async wrapper around HttpClient for use in Textual widgets."""

    def __init__(self, http_client: client.HttpClient):
        self._client = http_client

    @property
    def directory(self):
        return self._client.directory

    async def get(self, *args, **kwargs) -> requests.Response:
        return await asyncio.to_thread(self._client.get, *args, **kwargs)

    async def post(self, *args, **kwargs) -> requests.Response:
        return await asyncio.to_thread(self._client.post, *args, **kwargs)

    async def patch(self, *args, **kwargs) -> requests.Response:
        return await asyncio.to_thread(self._client.patch, *args, **kwargs)

    async def put(self, *args, **kwargs) -> requests.Response:
        return await asyncio.to_thread(self._client.put, *args, **kwargs)

    async def delete(self, *args, **kwargs) -> requests.Response:
        return await asyncio.to_thread(self._client.delete, *args, **kwargs)

    async def get_list(self, url: str, key: str, error_msg: str) -> list:
        response = await self.get(url)
        if response.status_code != 200:
            raise client.exceptions.UI(response.json().get("title", error_msg))
        return response.json()[key]

    async def list_roles(self) -> list:
        return await self.get_list(self.directory.role, "roles", "Failed to read list of roles")

    async def list_identities(self) -> list:
        return await self.get_list(self.directory.identity, "identities", "Failed to read list of identities")

    async def list_tags(self) -> list:
        return await self.get_list(self.directory.tag, "tags", "Failed to read list of tags")

    async def list_boundaries(self) -> list:
        return await self.get_list(self.directory.boundary, "boundaries", "Failed to read list of boundaries")
