import asyncio
import typing

import provablyfine_client as pfc
import requests

from .. import client


class AsyncClient:
    """Async wrapper around HttpClient for use in Textual widgets."""

    def __init__(self, http_client: client.HttpClient):
        self._client = http_client
        self._lock = asyncio.Lock()

    @property
    def directory(self) -> pfc.Directory:
        return self._client.directory

    async def get(self, url: str, *, params: dict[str, typing.Any] | None = None) -> requests.Response:
        async with self._lock:
            return await asyncio.to_thread(self._client.get, url, params=params)

    async def post(self, url: str, *, json: typing.Any = None) -> requests.Response:
        async with self._lock:
            return await asyncio.to_thread(self._client.post, url, json=json)

    async def patch(self, url: str, *, json: typing.Any = None) -> requests.Response:
        async with self._lock:
            return await asyncio.to_thread(self._client.patch, url, json=json)

    async def put(self, url: str, *, json: typing.Any = None) -> requests.Response:
        async with self._lock:
            return await asyncio.to_thread(self._client.put, url, json=json)

    async def delete(self, url: str) -> requests.Response:
        async with self._lock:
            return await asyncio.to_thread(self._client.delete, url)

    async def get_list(self, url: str, key: str, error_msg: str) -> list[dict[str, typing.Any]]:
        response = await self.get(url)
        if response.status_code != 200:
            raise pfc.exceptions.UI(response.json().get("title", error_msg))
        return response.json()[key]

    async def list_roles(self) -> list[dict[str, typing.Any]]:
        return await self.get_list(self.directory.role, "roles", "Failed to read list of roles")

    async def list_identities(self) -> list[dict[str, typing.Any]]:
        return await self.get_list(self.directory.identity, "identities", "Failed to read list of identities")

    async def list_tags(self) -> list[dict[str, typing.Any]]:
        return await self.get_list(self.directory.tag, "tags", "Failed to read list of tags")

    async def list_boundaries(self) -> list[dict[str, typing.Any]]:
        return await self.get_list(self.directory.boundary, "boundaries", "Failed to read list of boundaries")

    async def list_tenants(self) -> list[dict[str, typing.Any]]:
        return await self.get_list(self.directory.tenant, "tenants", "Failed to read list of tenant")

    async def list_auths(self) -> list[dict[str, typing.Any]]:
        return await self.get_list(self.directory.auth, "auths", "Failed to read list of auths")

    async def list_bastions(self) -> list[dict[str, typing.Any]]:
        return await self.get_list(self.directory.bastion, "bastions", "Failed to read list of bastion")
