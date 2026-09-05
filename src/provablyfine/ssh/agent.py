from __future__ import annotations

import collections.abc
import dataclasses
import getpass
import os
import socket

from .. import jwk
from . import buffer, cert, exceptions, serde, wire


@dataclasses.dataclass
class Identity:
    public_key: jwk.Public
    comment: str
    raw: bytes


class Client(wire.WireSocket):
    def __init__(self, path: str | None = None):
        if path is None:
            path = os.environ.get("SSH_AUTH_SOCK")
            if path is None:
                raise OSError("SSH_AUTH_SOCK is not set")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(path.encode("ascii"))
        super().__init__(sock)

    def list_identities(self) -> collections.abc.Generator[Identity]:
        self.send_message(wire.SSH_AGENTC_REQUEST_IDENTITIES, b"")
        rx = self.recv_message()
        assert rx.type == wire.SSH_AGENT_IDENTITIES_ANSWER
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
        self.send_message(wire.SSH_AGENTC_SIGN_REQUEST, request.to_bytes())
        message = self.recv_message()
        if message.type == wire.SSH_AGENT_FAILURE:
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
        request_id = wire.SSH_AGENTC_ADD_IDENTITY
        if lifetime is not None:
            request_id = wire.SSH_AGENTC_ADD_ID_CONSTRAINED
            request.write_byte(wire.SSH_AGENT_CONSTRAIN_LIFETIME)
            request.write_uint32(lifetime)
        if require_confirmation:
            request_id = wire.SSH_AGENTC_ADD_ID_CONSTRAINED
            request.write_byte(wire.SSH_AGENT_CONSTRAIN_CONFIRM)
        self.send_message(request_id, request.to_bytes())
        message = self.recv_message()
        if message.type == wire.SSH_AGENT_FAILURE:
            raise exceptions.Error(f"Unable to add key to agent: {message.contents}")

    def remove_all(self):
        self.send_message(wire.SSH_AGENTC_REMOVE_ALL_IDENTITIES, b"")
        message = self.recv_message()
        if message.type == wire.SSH_AGENT_FAILURE:
            raise exceptions.Error(f"Unable to remove keys from agent: {message.contents}")

    def remove(self, identity: Identity):
        request = buffer.Writer()
        request.write_string(identity.raw)
        self.send_message(wire.SSH_AGENTC_REMOVE_IDENTITY, request.to_bytes())
        message = self.recv_message()
        if message.type == wire.SSH_AGENT_FAILURE:
            raise exceptions.Error(f"Unable to remove key from agent: {message.contents}")
