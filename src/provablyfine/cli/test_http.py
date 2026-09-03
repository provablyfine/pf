"""HTTP parsing tests."""

from __future__ import annotations

import asyncio
import collections.abc
import socket

import pytest

from . import http

StreamPair = tuple[tuple[asyncio.StreamReader, asyncio.StreamWriter], tuple[asyncio.StreamReader, asyncio.StreamWriter]]


@pytest.fixture
async def stream_pair() -> collections.abc.AsyncGenerator[StreamPair, None]:
    a, b = socket.socketpair()
    reader_a, writer_a = await asyncio.open_connection(sock=a)
    reader_b, writer_b = await asyncio.open_connection(sock=b)
    yield (reader_a, writer_a), (reader_b, writer_b)
    writer_a.close()
    writer_b.close()
    await asyncio.gather(writer_a.wait_closed(), writer_b.wait_closed())


@pytest.mark.anyio
async def test_http_message_deserialize_simple(stream_pair: StreamPair) -> None:
    """Deserialize HTTP message with headers and no body."""
    (reader, _), (_, writer) = stream_pair

    async def server_send() -> None:
        writer.write(b"HTTP/1.1 200 OK\r\n")
        writer.write(b"Content-Type: text/plain\r\n")
        writer.write(b"Content-Length: 0\r\n")
        writer.write(b"\r\n")
        await writer.drain()

    async def client_read() -> None:
        msg = await http.Message.deserialize(reader)
        assert msg.start_line == "HTTP/1.1 200 OK"
        assert msg.headers["content-type"] == "text/plain"
        assert msg.headers["content-length"] == "0"
        assert msg.body == b""

    await asyncio.gather(client_read(), server_send())


@pytest.mark.anyio
async def test_http_message_deserialize_with_body(stream_pair: StreamPair) -> None:
    """Deserialize HTTP message with body."""
    (reader, _), (_, writer) = stream_pair
    body_data = b"Hello, World!"

    async def server_send() -> None:
        writer.write(b"HTTP/1.1 200 OK\r\n")
        writer.write(b"Content-Length: 13\r\n")
        writer.write(b"\r\n")
        writer.write(body_data)
        await writer.drain()

    async def client_read() -> None:
        msg = await http.Message.deserialize(reader)
        assert msg.start_line == "HTTP/1.1 200 OK"
        assert msg.headers["content-length"] == "13"
        assert msg.body == body_data

    await asyncio.gather(client_read(), server_send())


@pytest.mark.anyio
async def test_http_message_multiple_headers(stream_pair: StreamPair) -> None:
    """Deserialize message with multiple headers."""
    (reader, _), (_, writer) = stream_pair

    async def server_send() -> None:
        writer.write(b"GET / HTTP/1.1\r\n")
        writer.write(b"Host: example.com\r\n")
        writer.write(b"User-Agent: test\r\n")
        writer.write(b"Accept: */*\r\n")
        writer.write(b"Content-Length: 0\r\n")
        writer.write(b"\r\n")
        await writer.drain()

    async def client_read() -> None:
        msg = await http.Message.deserialize(reader)
        assert msg.start_line == "GET / HTTP/1.1"
        assert msg.headers["host"] == "example.com"
        assert msg.headers["user-agent"] == "test"
        assert msg.headers["accept"] == "*/*"

    await asyncio.gather(client_read(), server_send())


@pytest.mark.anyio
async def test_http_request_deserialize(stream_pair: StreamPair) -> None:
    """Deserialize HTTP request."""
    (reader, _), (_, writer) = stream_pair

    async def server_send() -> None:
        writer.write(b"POST /api/test HTTP/1.1\r\n")
        writer.write(b"Host: api.example.com\r\n")
        writer.write(b"Content-Length: 0\r\n")
        writer.write(b"\r\n")
        await writer.drain()

    async def client_read() -> None:
        req = await http.Request.deserialize(reader)
        assert req.method == "POST"
        assert req.resource_target == "/api/test"
        assert req.version == "HTTP/1.1"
        assert req.headers["host"] == "api.example.com"
        assert req.body == b""

    await asyncio.gather(client_read(), server_send())


@pytest.mark.anyio
async def test_http_request_with_body(stream_pair: StreamPair) -> None:
    """Deserialize HTTP request with body."""
    (reader, _), (_, writer) = stream_pair
    body = b'{"key": "value"}'

    async def server_send() -> None:
        writer.write(b"POST /api/test HTTP/1.1\r\n")
        writer.write(f"Content-Length: {len(body)}\r\n".encode())
        writer.write(b"\r\n")
        writer.write(body)
        await writer.drain()

    async def client_read() -> None:
        req = await http.Request.deserialize(reader)
        assert req.method == "POST"
        assert req.resource_target == "/api/test"
        assert req.version == "HTTP/1.1"
        assert req.body == body

    await asyncio.gather(client_read(), server_send())


@pytest.mark.anyio
async def test_http_response_deserialize(stream_pair: StreamPair) -> None:
    """Deserialize HTTP response."""
    (reader, _), (_, writer) = stream_pair

    async def server_send() -> None:
        writer.write(b"HTTP/1.1 404 Not Found\r\n")
        writer.write(b"Content-Type: text/html\r\n")
        writer.write(b"Content-Length: 0\r\n")
        writer.write(b"\r\n")
        await writer.drain()

    async def client_read() -> None:
        resp = await http.Response.deserialize(reader)
        assert resp.version == "HTTP/1.1"
        assert resp.status_code == 404
        assert resp.reason == "Not Found"
        assert resp.headers["content-type"] == "text/html"
        assert resp.body == b""

    await asyncio.gather(client_read(), server_send())


@pytest.mark.anyio
async def test_http_response_with_body(stream_pair: StreamPair) -> None:
    """Deserialize HTTP response with body."""
    (reader, _), (_, writer) = stream_pair
    body = b"<html><body>Page not found</body></html>"

    async def server_send() -> None:
        writer.write(b"HTTP/1.0 404 Not Found\r\n")
        writer.write(f"Content-Length: {len(body)}\r\n".encode())
        writer.write(b"\r\n")
        writer.write(body)
        await writer.drain()

    async def client_read() -> None:
        resp = await http.Response.deserialize(reader)
        assert resp.version == "HTTP/1.0"
        assert resp.status_code == 404
        assert resp.reason == "Not Found"
        assert resp.body == body

    await asyncio.gather(client_read(), server_send())


@pytest.mark.anyio
async def test_http_message_invalid_header(stream_pair: StreamPair) -> None:
    """Reject malformed header (no colon)."""
    (reader, _), (_, writer) = stream_pair

    async def server_send() -> None:
        writer.write(b"HTTP/1.1 200 OK\r\n")
        writer.write(b"BadHeaderNoColon\r\n")
        await writer.drain()

    async def client_read() -> None:
        with pytest.raises(http.ParseError, match="Invalid header"):
            await http.Message.deserialize(reader)

    await asyncio.gather(client_read(), server_send())


@pytest.mark.anyio
async def test_http_message_invalid_content_length(stream_pair: StreamPair) -> None:
    """Reject non-numeric Content-Length."""
    (reader, _), (_, writer) = stream_pair

    async def server_send() -> None:
        writer.write(b"HTTP/1.1 200 OK\r\n")
        writer.write(b"Content-Length: notanumber\r\n")
        writer.write(b"\r\n")
        await writer.drain()

    async def client_read() -> None:
        with pytest.raises(http.ParseError, match="Invalid Content-Length"):
            await http.Message.deserialize(reader)

    await asyncio.gather(client_read(), server_send())


@pytest.mark.anyio
async def test_http_request_invalid_start_line(stream_pair: StreamPair) -> None:
    """Reject invalid request start line."""
    (reader, _), (_, writer) = stream_pair

    async def server_send() -> None:
        writer.write(b"INVALID\r\n")
        writer.write(b"Content-Length: 0\r\n")
        writer.write(b"\r\n")
        await writer.drain()

    async def client_read() -> None:
        with pytest.raises(http.ParseError, match="Invalid request start line"):
            await http.Request.deserialize(reader)

    await asyncio.gather(client_read(), server_send())


@pytest.mark.anyio
async def test_http_response_invalid_status_code(stream_pair: StreamPair) -> None:
    """Reject non-numeric status code."""
    (reader, _), (_, writer) = stream_pair

    async def server_send() -> None:
        writer.write(b"HTTP/1.1 BADCODE OK\r\n")
        writer.write(b"Content-Length: 0\r\n")
        writer.write(b"\r\n")
        await writer.drain()

    async def client_read() -> None:
        with pytest.raises(http.ParseError, match="Invalid status_code"):
            await http.Response.deserialize(reader)

    await asyncio.gather(client_read(), server_send())
