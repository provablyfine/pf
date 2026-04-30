from __future__ import annotations
import dataclasses
import logging

from . import base, exceptions, stream


logger = logging.getLogger(__name__)


@dataclasses.dataclass
class Message:
    start_line: str
    headers: dict[str, str]
    body: bytes

    @classmethod
    async def deserialize(cls, sock: base.Socket) -> Message:
        reader = stream.Reader(sock)
        start_line = (await reader.read_until(b"\r\n"))[:-2].decode("ascii")
        headers: dict[str, str] = {}
        while True:
            line = (await reader.read_until(b"\r\n"))[:-2].decode("ascii")
            if line == "":
                break
            colon = line.find(":")
            if colon == -1:
                logger.warning(f"Invalid header: {line}")
                raise exceptions.Error("Invalid header")
            key = line[:colon].lower()
            value = line[colon + 1 :].lstrip()
            headers[key] = value
        if "content-length" in headers:
            length = headers["content-length"].strip()
            if not length.isdigit():
                logger.warning(f"Invalid Content-Length: {length}")
                raise exceptions.Error("Invalid Content-Length")
            body = await reader.read(int(length))
        else:
            # We do not support chunk encoding
            body = b""
        return Message(start_line=start_line, headers=headers, body=body)


@dataclasses.dataclass
class Request:
    method: str
    resource_target: str
    version: str
    headers: dict[str, str]
    body: bytes

    @classmethod
    async def deserialize(cls, sock: base.Socket) -> Request:
        message = await Message.deserialize(sock)
        start_line = message.start_line
        space = start_line.find(" ")
        if space == -1:
            raise exceptions.Error(f"Invalid request start line: {message.start_line}")
        method = start_line[:space]
        start_line = start_line[space+1:]
        space = start_line.find(" ")
        if space == -1:
            raise exceptions.Error(f"Invalid request start line: {message.start_line}")
        resource_target = start_line[:space]
        version = start_line[space+1:]
        return Request(method=method, resource_target=resource_target, version=version, headers=message.headers, body=message.body)


@dataclasses.dataclass
class Response:
    version: str
    status_code: int
    reason: str
    headers: dict[str, str]
    body: bytes

    @classmethod
    async def deserialize(cls, sock: base.Socket) -> Response:
        message = await Message.deserialize(sock)
        status_line = message.start_line
        space1 = status_line.find(" ")
        if space1 == -1:
            raise exceptions.Error(f"Invalid status_line={status_line}")
        version = status_line[:space1]
        remainder = status_line[space1 + 1 :]
        space2 = remainder.find(" ")
        if space2 == -1:
            raise exceptions.Error(f"Invalid status_line={status_line}")
        status_code = remainder[:space2]
        reason = remainder[space2 + 1 :]
        if not status_code.isdigit():
            raise exceptions.Error(f"Invalid status_code={status_code}")
        return Response(
            version=version, status_code=int(status_code), reason=reason, headers=message.headers, body=message.body
        )
