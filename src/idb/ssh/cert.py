import base64
import dataclasses
import enum
import time

import cryptography.exceptions

from . import exceptions
from . import buffer
from . import key


@enum.unique
class Role(enum.IntEnum):
    USER = 1
    HOST = 2


@dataclasses.dataclass(frozen=True)
class CriticalOptions:
    force_command: str
    source_address: list[str]
    verify_required: bool


@dataclasses.dataclass(frozen=True)
class Extensions:
    no_touch_required: bool
    permit_agent_forwarding: bool
    permit_pty: bool
    permit_user_rc: bool
    permit_x11_forwarding: bool


@dataclasses.dataclass(frozen=True)
class Cert:
    key_type: bytes
    public_key: key.Public
    serial_number: int
    role: Role
    identifier: str
    principals: tuple[str]
    valid_after: int
    valid_before: int
    critical_options: CriticalOptions
    extensions: Extensions
    signature_public_key: key.Public
    is_signature_valid: bool


    def is_valid(self) -> bool:
        now = int(time.time())
        if now < self.valid_after or now > self.valid_before:
            return False
        return True

    @classmethod
    def from_base64(klass, data):
        items = data.split(b" ")
        if len(items) != 3:
            raise exceptions.Error('Certificate format invalid. Expected 3 fields separated by whitespace.')
        return klass.from_bytes(base64.b64decode(items[1]))

    @classmethod
    def from_bytes(klass, data: bytes):
        # Based on https://www.ietf.org/archive/id/draft-miller-ssh-cert-01.html#section-2.1.1
        reader = buffer.Reader(data)
        key_type = reader.read_string()
        _ = reader.read_string() # nonce
        match key_type:
            case b'ssh-ed25519-cert-v01@openssh.com' | b'ssh-ed25519-cert':
                public_key = key.Public.from_ed25519_reader(reader)
        serial_number = reader.read_uint64()
        role = reader.read_uint32()
        identifier = reader.read_string()
        principal_reader = buffer.Reader(reader.read_string())
        principals = []
        while principal_reader.has_left:
            principal = principal_reader.read_string().decode('utf-8')
            principals.append(principal)
        valid_after = reader.read_uint64()
        valid_before = reader.read_uint64()

        critical_options_reader = buffer.Reader(reader.read_string())
        if len(critical_options_reader) > 0 and role == Role.HOST:
            raise exceptions.Error('Host certificates are not allowed to contain critical options')
        force_command = None
        source_address = None
        verify_required = None
        while critical_options_reader.has_left:
            name = critical_options_reader.read_string()
            value = critical_options_reader.read_string()
            match name:
                case b'force-command':
                    force_command = buffer.Reader(value).read_string().decode('utf-8')
                case b'source-address':
                    source_address = buffer.Reader(value).read_string().decode('utf-8').split(',')
                case b'verify-required':
                    verify_required = True
                case _:
                    raise exceptions.Error(f'Unknown critical option: "{name.decode("utf-8")}"')
        critical_options = CriticalOptions(
            force_command=force_command,
            source_address=source_address,
            verify_required=verify_required
        )

        extensions_reader = buffer.Reader(reader.read_string())
        if len(extensions_reader) > 0 and role == Role.HOST:
            raise exceptions.Error('Host certificates are not allowed to contain extensions')
        no_touch_required = None
        permit_agent_forwarding = None
        permit_pty = None
        permit_user_rc = None
        permit_x11_forwarding = None
        while extensions_reader.has_left:
            name = extensions_reader.read_string().decode('utf-8')
            value = extensions_reader.read_string()
            match name:
                case b'no-touch-required':
                    no_touch_required = True
                case b'permit-agent-forwarding':
                    permit_agent_forwarding = True
                case b'permit-pty':
                    permit_pty = True
                case b'permit-user-rc':
                    permit_user_rc = True
                case b'permit-X11-forwarding':
                    permit_x11_forwarding = True
        extensions = Extensions(
            no_touch_required=no_touch_required,
            permit_agent_forwarding=permit_agent_forwarding,
            permit_pty=permit_pty,
            permit_user_rc=permit_user_rc,
            permit_x11_forwarding=permit_x11_forwarding,
        )
        reserved = reader.read_string()
        signature_key = reader.read_string()
        signature_public_key = key.Public.from_bytes(signature_key)

        # The signature is calculated over everything except the signature itself
        signed_data_end = reader.offset

        signature_reader = buffer.Reader(reader.read_string())
        signature_type = signature_reader.read_string()
        signature = signature_reader.read_string()
        try:
            signature_public_key.to_crypto().verify(signature, data[:signed_data_end])
            is_signature_valid = True
        except cryptography.exceptions.InvalidSignature:
            is_signature_valid = False

        return Cert(
            key_type=key_type.decode('ascii'),
            public_key=public_key,
            serial_number=serial_number,
            role=role,
            identifier=identifier.decode('utf-8'),
            principals=principals,
            valid_after=valid_after,
            valid_before=valid_before,
            critical_options=critical_options,
            extensions=extensions,
            signature_public_key=signature_public_key,
            is_signature_valid=is_signature_valid,
        )
