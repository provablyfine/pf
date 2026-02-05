from __future__ import annotations
import dataclasses
import enum
import time

import cryptography.exceptions

from . import exceptions
from .. import jwk


@enum.unique
class Role(enum.IntEnum):
    USER = 1
    HOST = 2


@dataclasses.dataclass(frozen=True)
class CriticalOptions:
    # https://www.ietf.org/archive/id/draft-miller-ssh-cert-01.html#name-critical-options
    force_command: str = None
    source_address: list[str] = None
    verify_required: bool = None


@dataclasses.dataclass(frozen=True)
class Extensions:
    # https://www.ietf.org/archive/id/draft-miller-ssh-cert-01.html#name-certificate-extensions
    no_touch_required: bool = None
    permit_agent_forwarding: bool = None
    permit_port_forwarding: bool = None
    permit_pty: bool = None
    permit_user_rc: bool = None
    permit_x11_forwarding: bool = None


@dataclasses.dataclass(frozen=True)
class Cert:
    public_key: jwk.Public
    serial_number: int
    role: Role
    identifier: str
    principals: tuple[str]
    valid_after: int
    valid_before: int
    critical_options: CriticalOptions
    extensions: Extensions
    signer_public_key: jwk.Public


    def is_valid(self) -> bool:
        now = int(time.time())
        if now < self.valid_after or now > self.valid_before:
            return False
        return True

    @classmethod
    def create_host(klass, public_key: jwk.Public, serial_number: int, identifier: str, principals: list[str], valid_after: int, valid_before: int, signer_public_key: jwk.Public) -> Cert:
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

    @classmethod
    def create_user(klass, public_key: jwk.Public, serial_number: int, identifier: str, principals: list[str], valid_after: int, valid_before: int, critical_options: CriticalOptions, extensions: Extensions, signer_public_key: jwk.Public) -> Cert:
        return Cert(
            public_key=public_key,
            serial_number=serial_number,
            role=Role.USER,
            identifier=identifier,
            principals=tuple(principals),
            valid_after=valid_after,
            valid_before=valid_before,
            critical_options=critical_options,
            extensions=extensions,
            signer_public_key=signer_public_key,
        )

    def to_openssh(self, signer: jwk.Private) -> bytes:
        match self.role:
            case Role.HOST:
                type = cryptography.hazmat.primitives.serialization.SSHCertificateType.HOST
            case Role.USER:
                type = cryptography.hazmat.primitives.serialization.SSHCertificateType.USER

        builder = (
            cryptography.hazmat.primitives.serialization.SSHCertificateBuilder()
            .public_key(self.public_key.to_crypto())
            .type(type)
            .valid_before(self.valid_before)
            .valid_after(self.valid_after)
            .key_id(self.identifier)
            .valid_principals([p.encode('utf-8') for p in self.principals])
        )
        if self.critical_options.force_command is not None:
            builder = builder.add_critical_option(b'force-command', self.critical_options.force_command.encode('utf-8'))
        if self.critical_options.source_address is not None:
            builder = builder.add_critical_option(b'source-address', ','.join(self.critical_options.source_address).encode('utf-8'))
        if self.critical_options.verify_required:
            builder = builder.add_critical_option(b'verify-required', b'')
        if self.extensions.no_touch_required:
            builder = builder.add_extension(b'no-touch-required', b'')
        if self.extensions.permit_agent_forwarding:
            builder = builder.add_extension(b'permit-agent-forwarding', b'')
        if self.extensions.permit_port_forwarding:
            builder = builder.add_extension(b'permit-port-forwarding', b'')
        if self.extensions.permit_pty:
            builder = builder.add_extension(b'permit-pty', b'')
        if self.extensions.permit_user_rc:
            builder = builder.add_extension(b'permit-user-rc', b'')
        if self.extensions.permit_x11_forwarding:
            builder = builder.add_extension(b'permit-X11-forwarding', b'')
        data = builder.sign(signer.to_crypto()).public_bytes()
        return data

    @classmethod
    def from_openssh(klass, data: bytes) -> Cert:
        try:
            cert = cryptography.hazmat.primitives.serialization.load_ssh_public_identity(data)
        except ValueError:
            raise exceptions.Error('Failed to load certificate. Most likely invalid.')
        except cryptography.exceptions.UnsupportedAlgorithm:
            raise exceptions.Error('Failed to load certificate. Unsupported algorithm.')
        if len(cert.nonce) < 16:
            raise exceptions.Error('Nonce must be bigger than 16 bytes')
        public_key = jwk.Public(cert.public_key())

        if b'force-command' in cert.critical_options:
            force_command = cert.critical_options[b'force-command'].decode('utf-8')
        else:
            force_command = None
        if b'source-address' in cert.critical_options:
            source_address = cert.critical_options[b'source-address'].decode('utf-8').split(',')
        else:
            source_address = None
        verify_required = cert.critical_options.get(b'verify-required', False)
        critical_options = CriticalOptions(
            force_command=force_command,
            source_address=source_address,
            verify_required=verify_required
        )

        no_touch_required = cert.extensions.get(b'no-touch-required', False)
        permit_agent_forwarding = cert.extensions.get(b'permit-agent-forwarding', False)
        permit_port_forwarding = cert.extensions.get(b'permit-port-forwarding', False)
        permit_pty = cert.extensions.get(b'permit-pty', False)
        permit_user_rc = cert.extensions.get(b'permit-user-rc', False)
        permit_x11_forwarding = cert.extensions.get(b'permit-X11-forwarding', False)

        extensions = Extensions(
            no_touch_required=no_touch_required,
            permit_agent_forwarding=permit_agent_forwarding,
            permit_port_forwarding=permit_port_forwarding,
            permit_pty=permit_pty,
            permit_user_rc=permit_user_rc,
            permit_x11_forwarding=permit_x11_forwarding,
        )

        signature_public_key = jwk.Public(cert.signature_key())
        match cert.type:
            case cryptography.hazmat.primitives.serialization.SSHCertificateType.HOST:
                role = Role.HOST
            case cryptography.hazmat.primitives.serialization.SSHCertificateType.USER:
                role = Role.USER

        return Cert(
            public_key=public_key,
            serial_number=cert.serial,
            role=role,
            identifier=cert.key_id.decode('utf-8'),
            principals=[p.decode('utf-8') for p in cert.valid_principals],
            valid_after=cert.valid_after,
            valid_before=cert.valid_before,
            critical_options=critical_options,
            extensions=extensions,
            signer_public_key=signature_public_key,
        )
