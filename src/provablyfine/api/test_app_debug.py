import asyncio
import contextlib
import json
import os
import pathlib

import fastapi
import pytest

from . import app, config


def _create(tmp_path: pathlib.Path, *, debug: bool) -> fastapi.FastAPI:
    kek_file = tmp_path / "kek.key"
    kek_file.write_bytes(os.urandom(32))
    conf = config.Config(
        debug=debug,
        tenant_registry_url=f"sqlite:///{tmp_path / 'tenants.db'}",
        tenants_dir=str(tmp_path / "tenants"),
        kek_filename=str(kek_file),
    )
    api = app.create(conf)

    @api.get("/boom")
    def boom() -> None:
        raise RuntimeError("boom")

    return api


async def _get(api: fastapi.FastAPI, path: str) -> tuple[int, bytes]:
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": [(b"host", b"testserver")],
        "client": ("127.0.0.1", 1),
        "server": ("testserver", 80),
    }
    status = 0
    body = b""

    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, object]) -> None:
        nonlocal status, body
        if message["type"] == "http.response.start":
            assert isinstance(message["status"], int)
            status = message["status"]
        elif message["type"] == "http.response.body":
            assert isinstance(message["body"], bytes)
            body += message["body"]

    # Starlette re-raises after sending the 500 response, and uvicorn logs it.
    with contextlib.suppress(RuntimeError):
        await api(scope, receive, send)
    assert status != 0
    return status, body


async def _run(api: fastapi.FastAPI, *paths: str) -> list[tuple[int, bytes]]:
    async with api.router.lifespan_context(api):
        return [await _get(api, path) for path in paths]


def test_debug_enabled_serves_traceback(tmp_path: pathlib.Path) -> None:
    api = _create(tmp_path, debug=True)

    async def scenario() -> None:
        async with api.router.lifespan_context(api):
            status, body = await _get(api, "/boom")
            assert status == 500
            instance = json.loads(body)["instance"]
            status, body = await _get(api, instance.removeprefix(api.state.config.base_url))
            assert status == 200
            assert "RuntimeError: boom" in json.loads(body)["backtrace"]
            status, _ = await _get(api, "/debug/trigger-error")
            assert status == 500

    asyncio.run(scenario())


@pytest.mark.parametrize("path", ["/debug/trigger-error", "/debug/anything"])
def test_debug_disabled_hides_debug_routes(tmp_path: pathlib.Path, path: str) -> None:
    [(status, _)] = asyncio.run(_run(_create(tmp_path, debug=False), path))
    assert status == 404


def test_debug_disabled_omits_traceback_url(tmp_path: pathlib.Path) -> None:
    [(status, body)] = asyncio.run(_run(_create(tmp_path, debug=False), "/boom"))
    assert status == 500
    assert "instance" not in json.loads(body)
    assert b"RuntimeError" not in body
