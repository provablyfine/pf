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
        try:
            start_line = (await reader.read_until(b"\r\n"))[:-2].decode("ascii")
        except EOFError:
            raise exceptions.Error("Unable to read start line before connection was closed")
        headers: dict[str, str] = {}
        while True:
            try:
                line = (await reader.read_until(b"\r\n"))[:-2].decode("ascii")
            except EOFError:
                raise exceptions.Error("Unable to last line before connection was closed")
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

    async def serialize(self, sock: base.Socket) -> None:
        lines = [self.start_line]
        for name, value in self.headers.items():
            lines.append(f"{name}: {value}")
        lines.extend(["", ""])
        data = b"\r\n".join(line.encode("ascii") for line in lines) + self.body
        await sock.send(data)


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
        start_line = start_line[space + 1 :]
        space = start_line.find(" ")
        if space == -1:
            raise exceptions.Error(f"Invalid request start line: {message.start_line}")
        resource_target = start_line[:space]
        version = start_line[space + 1 :]
        return Request(
            method=method,
            resource_target=resource_target,
            version=version,
            headers=message.headers,
            body=message.body,
        )

    async def serialize(self, sock: base.Socket) -> None:
        start = f"{self.method} {self.resource_target} {self.version}"
        message = Message(start_line=start, headers=self.headers, body=self.body)
        await message.serialize(sock)


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
            version=version,
            status_code=int(status_code),
            reason=reason,
            headers=message.headers,
            body=message.body,
        )

    async def serialize(self, sock: base.Socket) -> None:
        start = f"{self.version} {self.status_code} {self.reason}"
        message = Message(start_line=start, headers=self.headers, body=self.body)
        await message.serialize(sock)
