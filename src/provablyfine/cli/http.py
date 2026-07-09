from __future__ import annotations

import asyncio
import dataclasses
import logging

logger = logging.getLogger(__name__)


class ParseError(Exception):
    pass


@dataclasses.dataclass
class Message:
    start_line: str
    headers: dict[str, str]
    body: bytes

    @classmethod
    async def deserialize(cls, reader: asyncio.StreamReader) -> Message:
        try:
            start_line = (await reader.readuntil(b"\r\n"))[:-2].decode("ascii")
        except asyncio.IncompleteReadError as e:
            raise ParseError("Unable to read start line before connection was closed") from e
        headers: dict[str, str] = {}
        while True:
            try:
                raw_line = await reader.readuntil(b"\r\n")
            except asyncio.IncompleteReadError as e:
                raise ParseError("Unable to read last line before connection was closed") from e
            line = raw_line[:-2].decode("ascii")
            if line == "":
                break
            colon = line.find(":")
            if colon == -1:
                logger.warning(f"Invalid header: {line}")
                raise ParseError("Invalid header")
            key = line[:colon].lower()
            value = line[colon + 1 :].lstrip()
            headers[key] = value
        body = b""
        if "content-length" in headers:
            length = headers["content-length"].strip()
            if not length.isdigit():
                logger.warning(f"Invalid Content-Length: {length}")
                raise ParseError("Invalid Content-Length")
            try:
                body = await reader.readexactly(int(length))
            except asyncio.IncompleteReadError as e:
                raise ParseError("Connection closed before body was complete") from e
        return Message(start_line=start_line, headers=headers, body=body)

    async def serialize(self, writer: asyncio.StreamWriter) -> None:
        lines = [self.start_line]
        for name, value in self.headers.items():
            lines.append(f"{name}: {value}")
        lines.extend(["", ""])
        data = b"\r\n".join(line.encode("ascii") for line in lines) + self.body
        writer.write(data)
        await writer.drain()


@dataclasses.dataclass
class Request:
    method: str
    resource_target: str
    version: str
    headers: dict[str, str]
    body: bytes

    @classmethod
    async def deserialize(cls, reader: asyncio.StreamReader) -> Request:
        message = await Message.deserialize(reader)
        start_line = message.start_line
        space = start_line.find(" ")
        if space == -1:
            raise ParseError(f"Invalid request start line: {message.start_line}")
        method = start_line[:space]
        start_line = start_line[space + 1 :]
        space = start_line.find(" ")
        if space == -1:
            raise ParseError(f"Invalid request start line: {message.start_line}")
        resource_target = start_line[:space]
        version = start_line[space + 1 :]
        return Request(
            method=method,
            resource_target=resource_target,
            version=version,
            headers=message.headers,
            body=message.body,
        )

    async def serialize(self, writer: asyncio.StreamWriter) -> None:
        start = f"{self.method} {self.resource_target} {self.version}"
        message = Message(start_line=start, headers=self.headers, body=self.body)
        await message.serialize(writer)


@dataclasses.dataclass
class Response:
    version: str
    status_code: int
    reason: str
    headers: dict[str, str]
    body: bytes

    @classmethod
    async def deserialize(cls, reader: asyncio.StreamReader) -> Response:
        message = await Message.deserialize(reader)
        status_line = message.start_line
        space1 = status_line.find(" ")
        if space1 == -1:
            raise ParseError(f"Invalid status_line={status_line}")
        version = status_line[:space1]
        remainder = status_line[space1 + 1 :]
        space2 = remainder.find(" ")
        if space2 == -1:
            raise ParseError(f"Invalid status_line={status_line}")
        status_code = remainder[:space2]
        reason = remainder[space2 + 1 :]
        if not status_code.isdigit():
            raise ParseError(f"Invalid status_code={status_code}")
        return Response(
            version=version,
            status_code=int(status_code),
            reason=reason,
            headers=message.headers,
            body=message.body,
        )

    async def serialize(self, writer: asyncio.StreamWriter) -> None:
        start = f"{self.version} {self.status_code} {self.reason}"
        message = Message(start_line=start, headers=self.headers, body=self.body)
        await message.serialize(writer)
