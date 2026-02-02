import collections
import os
import socket
import enum


from . import exceptions
from . import buffer

Method = collections.namedtuple('Method', ['encrypt', 'decrypt'])

@enum.unique
class RSA(enum.IntEnum):
    SHA2_256 = 0x02
    SHA2_512 = 0x04


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
    Message = collections.namedtuple('Message', ['type', 'contents'])
    Identity = collections.namedtuple('Identity', ['public_key', 'comment'])

    def __init__(self):
        path = os.getenv('SSH_AUTH_SOCK')
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(path)
        self._sock = sock

    def _send_request(self, type, buffer):
        request = buffer.Writer()
        request.write_uint32(len(buffer)+1)
        request.write_byte(type)
        request.write_bytes(buffer)
        written = self._sock.send(request.to_bytes())
        assert written == len(request)

    def _recv_bytes(self, n):
        remaining = n
        data = []
        while remaining > 0:
            buffer = self._sock.recv(remaining)
            if len(buffer) == 0:
                raise Exception('fuck')
            remaining -= len(buffer)
            data.append(buffer)
        return b''.join(data)

    def _recv_message(self):
        length = self._recv_bytes(4)
        length = int.from_bytes(length, byteorder='big')
        payload = self._recv_bytes(length)
        return Client.Message(type=payload[0], contents=payload[1:])

    def list_identities(self):
        self._send_request(Client.SSH_AGENTC_REQUEST_IDENTITIES, b'')
        rx = self._recv_message()
        assert rx.type == Client.SSH_AGENT_IDENTITIES_ANSWER
        assert len(rx.contents) >= 4
        buffer = buffer.Reader(rx.contents)
        nkeys = buffer.read_uint32()
        for _ in range(nkeys):
            key = buffer.read_string()
            comment = buffer.read_string()
            yield Client.Identity(public_key=key, comment=comment)

    def sign(self, public_key: bytes, data: bytes, flags: int) -> bytes:
        request = buffer.Writer()
        request.write_string(public_key)
        request.write_string(data)
        request.write_uint32(flags)
        self._send_request(Client.SSH_AGENTC_SIGN_REQUEST, request)
        message = self._recv_message()
        if message.type == Client.SSH_AGENT_FAILURE:
            raise exceptions.Error(f'Unable to obtain signature from agent: {message.contents}')
        response = buffer.Reader(message.contents)
        length = response.read_uint32()
        key_type = response.read_string()
        signature = response.read_string()
        return signature

    def add(self, key: bytes, comment: str, lifetime: int=None, require_confirmation: bool=False):
        request = buffer.Writer()
        request.write_bytes(key)
        request.write_string(comment.encode('utf-8'))
        request_id = Client.SSH_AGENTC_ADD_IDENTITY
        if lifetime is not None:
            request_id = Client.SSH_AGENTC_ADD_ID_CONSTRAINED
            request.write_byte(Client.SSH_AGENT_CONSTRAIN_LIFETIME)
            request.write_uint32(lifetime)
        if require_confirmation:
            request_id = Client.SSH_AGENTC_ADD_ID_CONSTRAINED
            request.write_byte(Client.SSH_AGENT_CONSTRAIN_CONFIRM)
        self._send_request(request_id, request)
        message = self._recv_message()
        if message.type == Client.SSH_AGENT_FAILURE:
            raise exceptions.Error(f'Unable to add key to agent: {message.contents}')

    def remove_all(self):
        self._send_request(Client.SSH_AGENTC_REMOVE_ALL_IDENTITIES, b'')
        message = self._recv_message()
        if message.type == Client.SSH_AGENT_FAILURE:
            raise exceptions.Error(f'Unable to remove keys from agent: {message.contents}')

    def remove(self, key: bytes):
        request = buffer.Writer()
        request.write_string(key)
        self._send_request(Client.SSH_AGENTC_REMOVE_IDENTITY, request)
        message = self._recv_message()
        if message.type == Client.SSH_AGENT_FAILURE:
            raise exceptions.Error(f'Unable to remove key from agent: {message.contents}')
