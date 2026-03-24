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
