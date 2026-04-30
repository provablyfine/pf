"""HTTP parsing tests for anet."""

from __future__ import annotations

import asyncio

import pytest

import pf.anet.exceptions as exceptions
import pf.anet.http as http
import pf.anet.socket as anet_socket


@pytest.mark.anyio
async def test_http_message_deserialize_simple(anet_socketpair: tuple[anet_socket.Socket, anet_socket.Socket]) -> None:
    """Deserialize HTTP message with headers and no body."""
    client, server = anet_socketpair

    async def server_send() -> None:
        await server.send(b"HTTP/1.1 200 OK\r\n")
        await server.send(b"Content-Type: text/plain\r\n")
        await server.send(b"Content-Length: 0\r\n")
        await server.send(b"\r\n")

    async def client_read() -> None:
        msg = await http.Message.deserialize(client)
        assert msg.start_line == "HTTP/1.1 200 OK"
        assert msg.headers["content-type"] == "text/plain"
        assert msg.headers["content-length"] == "0"
        assert msg.body == b""

    await asyncio.gather(client_read(), server_send())


@pytest.mark.anyio
async def test_http_message_deserialize_with_body(anet_socketpair: tuple[anet_socket.Socket, anet_socket.Socket]) -> None:
    """Deserialize HTTP message with body."""
    client, server = anet_socketpair
    body_data = b"Hello, World!"

    async def server_send() -> None:
        await server.send(b"HTTP/1.1 200 OK\r\n")
        await server.send(b"Content-Length: 13\r\n")
        await server.send(b"\r\n")
        await server.send(body_data)

    async def client_read() -> None:
        msg = await http.Message.deserialize(client)
        assert msg.start_line == "HTTP/1.1 200 OK"
        assert msg.headers["content-length"] == "13"
        assert msg.body == body_data

    await asyncio.gather(client_read(), server_send())


@pytest.mark.anyio
async def test_http_message_multiple_headers(anet_socketpair: tuple[anet_socket.Socket, anet_socket.Socket]) -> None:
    """Deserialize message with multiple headers."""
    client, server = anet_socketpair

    async def server_send() -> None:
        await server.send(b"GET / HTTP/1.1\r\n")
        await server.send(b"Host: example.com\r\n")
        await server.send(b"User-Agent: test\r\n")
        await server.send(b"Accept: */*\r\n")
        await server.send(b"Content-Length: 0\r\n")
        await server.send(b"\r\n")

    async def client_read() -> None:
        msg = await http.Message.deserialize(client)
        assert msg.start_line == "GET / HTTP/1.1"
        assert msg.headers["host"] == "example.com"
        assert msg.headers["user-agent"] == "test"
        assert msg.headers["accept"] == "*/*"

    await asyncio.gather(client_read(), server_send())


@pytest.mark.anyio
async def test_http_request_deserialize(anet_socketpair: tuple[anet_socket.Socket, anet_socket.Socket]) -> None:
    """Deserialize HTTP request."""
    client, server = anet_socketpair

    async def server_send() -> None:
        await server.send(b"POST /api/test HTTP/1.1\r\n")
        await server.send(b"Host: api.example.com\r\n")
        await server.send(b"Content-Length: 0\r\n")
        await server.send(b"\r\n")

    async def client_read() -> None:
        req = await http.Request.deserialize(client)
        assert req.method == "POST"
        assert req.resource_target == "/api/test"
        assert req.version == "HTTP/1.1"
        assert req.headers["host"] == "api.example.com"
        assert req.body == b""

    await asyncio.gather(client_read(), server_send())


@pytest.mark.anyio
async def test_http_request_with_body(anet_socketpair: tuple[anet_socket.Socket, anet_socket.Socket]) -> None:
    """Deserialize HTTP request with body."""
    client, server = anet_socketpair
    body = b'{"key": "value"}'

    async def server_send() -> None:
        await server.send(b"POST /api/test HTTP/1.1\r\n")
        await server.send(f"Content-Length: {len(body)}\r\n".encode())
        await server.send(b"\r\n")
        await server.send(body)

    async def client_read() -> None:
        req = await http.Request.deserialize(client)
        assert req.method == "POST"
        assert req.resource_target == "/api/test"
        assert req.version == "HTTP/1.1"
        assert req.body == body

    await asyncio.gather(client_read(), server_send())


@pytest.mark.anyio
async def test_http_response_deserialize(anet_socketpair: tuple[anet_socket.Socket, anet_socket.Socket]) -> None:
    """Deserialize HTTP response."""
    client, server = anet_socketpair

    async def server_send() -> None:
        await server.send(b"HTTP/1.1 404 Not Found\r\n")
        await server.send(b"Content-Type: text/html\r\n")
        await server.send(b"Content-Length: 0\r\n")
        await server.send(b"\r\n")

    async def client_read() -> None:
        resp = await http.Response.deserialize(client)
        assert resp.version == "HTTP/1.1"
        assert resp.status_code == 404
        assert resp.reason == "Not Found"
        assert resp.headers["content-type"] == "text/html"
        assert resp.body == b""

    await asyncio.gather(client_read(), server_send())


@pytest.mark.anyio
async def test_http_response_with_body(anet_socketpair: tuple[anet_socket.Socket, anet_socket.Socket]) -> None:
    """Deserialize HTTP response with body."""
    client, server = anet_socketpair
    body = b"<html><body>Page not found</body></html>"

    async def server_send() -> None:
        await server.send(b"HTTP/1.0 404 Not Found\r\n")
        await server.send(f"Content-Length: {len(body)}\r\n".encode())
        await server.send(b"\r\n")
        await server.send(body)

    async def client_read() -> None:
        resp = await http.Response.deserialize(client)
        assert resp.version == "HTTP/1.0"
        assert resp.status_code == 404
        assert resp.reason == "Not Found"
        assert resp.body == body

    await asyncio.gather(client_read(), server_send())


@pytest.mark.anyio
async def test_http_message_invalid_header(anet_socketpair: tuple[anet_socket.Socket, anet_socket.Socket]) -> None:
    """Reject malformed header (no colon)."""
    client, server = anet_socketpair

    async def server_send() -> None:
        await server.send(b"HTTP/1.1 200 OK\r\n")
        await server.send(b"BadHeaderNoColon\r\n")

    async def client_read() -> None:
        with pytest.raises(exceptions.Error, match="Invalid header"):
            await http.Message.deserialize(client)

    await asyncio.gather(client_read(), server_send())


@pytest.mark.anyio
async def test_http_message_invalid_content_length(anet_socketpair: tuple[anet_socket.Socket, anet_socket.Socket]) -> None:
    """Reject non-numeric Content-Length."""
    client, server = anet_socketpair

    async def server_send() -> None:
        await server.send(b"HTTP/1.1 200 OK\r\n")
        await server.send(b"Content-Length: notanumber\r\n")
        await server.send(b"\r\n")

    async def client_read() -> None:
        with pytest.raises(exceptions.Error, match="Invalid Content-Length"):
            await http.Message.deserialize(client)

    await asyncio.gather(client_read(), server_send())


@pytest.mark.anyio
async def test_http_request_invalid_start_line(anet_socketpair: tuple[anet_socket.Socket, anet_socket.Socket]) -> None:
    """Reject invalid request start line."""
    client, server = anet_socketpair

    async def server_send() -> None:
        await server.send(b"INVALID\r\n")
        await server.send(b"Content-Length: 0\r\n")
        await server.send(b"\r\n")

    async def client_read() -> None:
        with pytest.raises(exceptions.Error, match="Invalid request start line"):
            await http.Request.deserialize(client)

    await asyncio.gather(client_read(), server_send())


@pytest.mark.anyio
async def test_http_response_invalid_status_code(anet_socketpair: tuple[anet_socket.Socket, anet_socket.Socket]) -> None:
    """Reject non-numeric status code."""
    client, server = anet_socketpair

    async def server_send() -> None:
        await server.send(b"HTTP/1.1 BADCODE OK\r\n")
        await server.send(b"Content-Length: 0\r\n")
        await server.send(b"\r\n")

    async def client_read() -> None:
        with pytest.raises(exceptions.Error, match="Invalid status_code"):
            await http.Response.deserialize(client)

    await asyncio.gather(client_read(), server_send())
