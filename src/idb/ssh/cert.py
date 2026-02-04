from __future__ import annotations
import base64
import dataclasses
import datetime
import enum
import time
import secrets
import getpass
import socket

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
    force_command: str = None
    source_address: list[str] = None
    verify_required: bool = None


@dataclasses.dataclass(frozen=True)
class Extensions:
    no_touch_required: bool = None
    permit_agent_forwarding: bool = None
    permit_port_forwarding: bool = None
    permit_pty: bool = None
    permit_user_rc: bool = None
    permit_x11_forwarding: bool = None


@dataclasses.dataclass(frozen=True)
class Cert:
    public_key: key.Public
    serial_number: int
    role: Role
    identifier: str
    principals: tuple[str]
    valid_after: int
    valid_before: int
    critical_options: CriticalOptions
    extensions: Extensions
    signer_public_key: key.Public


    def is_valid(self) -> bool:
        now = int(time.time())
        if now < self.valid_after or now > self.valid_before:
            return False
        return True

    def to_bytes(self, signer: key.Private, flags: int) -> bytes:
        if signer.public().fingerprint() != self.signer_public_key.fingerprint():
            raise exceptions.Error('Unable to sign with a private key that does not match the signer public key')
        writer = buffer.Writer()
        serialized_public_key = self.public_key.to_serialized()
        writer.write_string(serialized_public_key.key_type + b'-cert')
        writer.write_string(secrets.token_bytes(32))
        writer.write_bytes(serialized_public_key.key)
        writer.write_uint64(self.serial_number)
        writer.write_uint32(self.role)
        writer.write_string(self.identifier)

        principals_writer = buffer.Writer()
        for principal in self.principals:
            principals_writer.write_string(principal.encode('utf-8'))
        writer.write_string(principals_writer.to_bytes())

        writer.write_uint64(self.valid_after)
        writer.write_uint64(self.valid_before)

        critical_options_writer = buffer.Writer()
        if self.critical_options.force_command is not None:
            critical_options_writer.write_string(b'force-command')
            critical_options_writer.write_nested_string(self.critical_options.force_command.encode('utf-8'))
        if self.critical_options.source_address is not None:
            critical_options_writer.write_string(b'source-address')
            critical_options_writer.write_nested_string((','.join(self.critical_options.source_address)).encode('utf-8'))
        if self.critical_options.verify_required is not None:
            critical_options_writer.write_string(b'verify-required')
            critical_options_writer.write_string(b'')
        writer.write_string(critical_options_writer.to_bytes())

        extensions_writer = buffer.Writer()
        if self.extensions.no_touch_required is not None:
            extensions_writer.write_string(b'no-touch-required')
            extensions_writer.write_string(b'')
        if self.extensions.permit_agent_forwarding is not None:
            extensions_writer.write_string(b'permit-agent-forwarding')
            extensions_writer.write_string(b'')
        if self.extensions.permit_port_forwarding is not None:
            extensions_writer.write_string(b'permit-port-forwarding')
            extensions_writer.write_string(b'')
        if self.extensions.permit_pty is not None:
            extensions_writer.write_string(b'permit-pty')
            extensions_writer.write_string(b'')
        if self.extensions.permit_user_rc is not None:
            extensions_writer.write_string(b'permit-user-rc')
            extensions_writer.write_string(b'')
        if self.extensions.permit_x11_forwarding is not None:
            extensions_writer.write_string(b'permit-X11-forwarding')
            extensions_writer.write_string(b'')
        writer.write_string(extensions_writer.to_bytes())
        writer.write_string(b'') # reserved

        writer.write_string(signer.public().to_bytes())

        signature = signer.sign(writer.to_bytes(), flags)

        writer.write_string(signature)

        return writer.to_bytes()



    @classmethod
    def create_host(klass, public_key: key.Public, serial_number: int, identifier: str, principals: list[str], valid_after: int, valid_before: int, signer_public_key: key.Public) -> Cert:
        return Cert(
            public_key=public_key,
            serial_number=serial_number,
            role=Role.HOST,
            identifier=identifier,
            principals=tuple(principals),
            valid_after=valid_after,
            valid_before=valid_before,
            critical_options=CriticalOptions(),
            extensions=Extensions(),
            signer_public_key=signer_public_key,
        )

    def to_base64(self, signer: key.Private, flags: int) -> bytes:
        data = self.to_bytes(signer, flags)
        serialized_public_key = self.public_key.to_serialized()
        username = getpass.getuser()
        hostname = socket.gethostname()
        items = [
            (serialized_public_key.key_type + b'-cert').decode('ascii'),
            base64.b64encode(data).decode('ascii'),
            f'{username}@{hostname}',
        ]
        return ' '.join(items).encode('utf-8')

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
        nonce = reader.read_string()
        if len(nonce) < 16:
            raise exceptions.Error('Nonce must be bigger than 16 bytes')
        match key_type:
            case b'ssh-dss-cert-v01@openssh.com' | b'ssh-dss-cert':
                public_key = key.Public.from_dss_reader(reader)
            case b'ssh-ed25519-cert-v01@openssh.com' | b'ssh-ed25519-cert':
                public_key = key.Public.from_ed25519_reader(reader)
            case b'ssh-ed448-cert-v01@openssh.com' | b'ssh-ed448-cert':
                public_key = key.Public.from_ed448_reader(reader)
            case b'ssh-rsa-cert-v01@openssh.com' | b'ssh-rsa-cert':
                public_key = key.Public.from_rsa_reader(reader)
            case b'ecdsa-sha2-nistp256-cert-v01@openssh.com' | b'ecdsa-sha2-nistp256-cert':
                return key.Public.from_ecdsa_reader(reader)
            case b'ecdsa-sha2-nistp384-cert-v01@openssh.com' | b'ecdsa-sha2-nistp384-cert':
                return key.Public.from_ecdsa_reader(reader)
            case b'ecdsa-sha2-nistp521-cert-v01@openssh.com' | b'ecdsa-sha2-nistp521-cert':
                return key.Public.from_ecdsa_reader(reader)
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
        permit_port_forwarding = None
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
                case b'permit-port-forwarding':
                    permit_port_forwarding = True
                case b'permit-pty':
                    permit_pty = True
                case b'permit-user-rc':
                    permit_user_rc = True
                case b'permit-X11-forwarding':
                    permit_x11_forwarding = True
        extensions = Extensions(
            no_touch_required=no_touch_required,
            permit_agent_forwarding=permit_agent_forwarding,
            permit_port_forwarding=permit_port_forwarding,
            permit_pty=permit_pty,
            permit_user_rc=permit_user_rc,
            permit_x11_forwarding=permit_x11_forwarding,
        )

        reserved = reader.read_string()
        signature_key = reader.read_string()
        signature_public_key = key.Public.from_bytes(signature_key)

        # The signature is calculated over everything except the signature itself
        signed_data_end = reader.offset

        signature = reader.read_string()
        try:
            signature_public_key.verify(signature, data[:signed_data_end])
        except cryptography.exceptions.InvalidSignature:
            raise exceptions.Error('Certificate signature invalid')

        return Cert(
            public_key=public_key,
            serial_number=serial_number,
            role=role,
            identifier=identifier.decode('utf-8'),
            principals=principals,
            valid_after=valid_after,
            valid_before=valid_before,
            critical_options=critical_options,
            extensions=extensions,
            signer_public_key=signature_public_key,
        )
