from __future__ import annotations

import collections.abc
import dataclasses
import getpass
import os
import socket

from .. import jwk
from . import buffer, cert, exceptions, serde


@dataclasses.dataclass
class Identity:
    public_key: jwk.Public
    comment: str
    raw: bytes


@dataclasses.dataclass
class Message:
    type: int
    contents: bytes


class Client:
    # https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent
    SSH_AGENTC_REQUEST_IDENTITIES = 11
    SSH_AGENT_IDENTITIES_ANSWER = 12
    SSH_AGENTC_SIGN_REQUEST = 13
    SSH_AGENTC_ADD_IDENTITY = 17
    SSH_AGENTC_REMOVE_IDENTITY = 18
    SSH_AGENTC_REMOVE_ALL_IDENTITIES = 19
    SSH_AGENTC_ADD_ID_CONSTRAINED = 25
    SSH_AGENT_CONSTRAIN_LIFETIME = 1
    SSH_AGENT_CONSTRAIN_CONFIRM = 2
    SSH_AGENT_FAILURE = 5

    def __init__(self):
        path = os.environ["SSH_AUTH_SOCK"]
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(path.encode("ascii"))
        self._sock = sock

    def _send_request(self, type: int, data: bytes):
        request = buffer.Writer()
        request.write_uint32(len(data) + 1)
        request.write_byte(type)
        request.write_bytes(data)
        written = self._sock.send(request.to_bytes())
        assert written == len(request)

    def _recv_bytes(self, n: int) -> bytes:
        remaining = n
        data: list[bytes] = []
        while remaining > 0:
            partial = self._sock.recv(remaining)
            if len(partial) == 0:
                raise Exception("Unable to read SSH Agent response")
            remaining -= len(partial)
            data.append(partial)
        return b"".join(data)

    def _recv_message(self):
        length = self._recv_bytes(4)
        length = int.from_bytes(length, byteorder="big")
        payload = self._recv_bytes(length)
        return Message(type=payload[0], contents=payload[1:])

    def list_identities(self) -> collections.abc.Generator[Identity]:
        self._send_request(Client.SSH_AGENTC_REQUEST_IDENTITIES, b"")
        rx = self._recv_message()
        assert rx.type == Client.SSH_AGENT_IDENTITIES_ANSWER
        assert len(rx.contents) >= 4
        response = buffer.Reader(rx.contents)
        nkeys = response.read_uint32()
        for _ in range(nkeys):
            raw_key = response.read_string()
            key = serde.deserialize_public(raw_key)
            comment = response.read_string()
            yield Identity(public_key=key, comment=comment.decode("utf-8"), raw=raw_key)

    def sign(self, identity: Identity, data: bytes, flags: int) -> bytes:
        request = buffer.Writer()
        request.write_string(identity.raw)
        request.write_string(data)
        request.write_uint32(flags)
        self._send_request(Client.SSH_AGENTC_SIGN_REQUEST, request.to_bytes())
        message = self._recv_message()
        if message.type == Client.SSH_AGENT_FAILURE:
            raise exceptions.Error(f"Unable to obtain signature from agent: {message.contents}")
        response = buffer.Reader(message.contents)
        _length = response.read_uint32()
        _key_type = response.read_string()
        signature = response.read_string()
        return signature

    def add(
        self,
        private_key: jwk.Private,
        cert: cert.Cert | None = None,
        comment: str | None = None,
        lifetime: int | None = None,
        require_confirmation: bool = False,
    ):
        if cert is None:
            key = serde.serialize_private(private_key)
        else:
            key = serde.serialize_private_certificate(private_key, cert)
        if comment is None:
            comment = f"{getpass.getuser()}@{socket.gethostname()}"
        self._add(key, comment, lifetime, require_confirmation)

    def _add(self, key: bytes, comment: str, lifetime: int | None = None, require_confirmation: bool = False):
        request = buffer.Writer()
        request.write_bytes(key)
        request.write_string(comment.encode("utf-8"))
        request_id = Client.SSH_AGENTC_ADD_IDENTITY
        if lifetime is not None:
            request_id = Client.SSH_AGENTC_ADD_ID_CONSTRAINED
            request.write_byte(Client.SSH_AGENT_CONSTRAIN_LIFETIME)
            request.write_uint32(lifetime)
        if require_confirmation:
            request_id = Client.SSH_AGENTC_ADD_ID_CONSTRAINED
            request.write_byte(Client.SSH_AGENT_CONSTRAIN_CONFIRM)
        self._send_request(request_id, request.to_bytes())
        message = self._recv_message()
        if message.type == Client.SSH_AGENT_FAILURE:
            raise exceptions.Error(f"Unable to add key to agent: {message.contents}")

    def remove_all(self):
        self._send_request(Client.SSH_AGENTC_REMOVE_ALL_IDENTITIES, b"")
        message = self._recv_message()
        if message.type == Client.SSH_AGENT_FAILURE:
            raise exceptions.Error(f"Unable to remove keys from agent: {message.contents}")

    def remove(self, identity: Identity):
        request = buffer.Writer()
        request.write_string(identity.raw)
        self._send_request(Client.SSH_AGENTC_REMOVE_IDENTITY, request.to_bytes())
        message = self._recv_message()
        if message.type == Client.SSH_AGENT_FAILURE:
            raise exceptions.Error(f"Unable to remove key from agent: {message.contents}")
