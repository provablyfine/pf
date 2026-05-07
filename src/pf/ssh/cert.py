from __future__ import annotations

import dataclasses
import enum
import time

import cryptography.exceptions
import cryptography.hazmat.primitives.serialization

from .. import jwk
from . import exceptions


@enum.unique
class Role(enum.IntEnum):
    USER = 1
    HOST = 2


@dataclasses.dataclass(frozen=True)
class CriticalOptions:
    # https://www.ietf.org/archive/id/draft-miller-ssh-cert-01.html#name-critical-options
    force_command: str | None = None
    source_address: list[str] | None = None
    verify_required: bool | None = None

    def to_dict(self):
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class Extensions:
    # https://www.ietf.org/archive/id/draft-miller-ssh-cert-01.html#name-certificate-extensions
    no_touch_required: bool | None = None
    permit_agent_forwarding: bool | None = None
    permit_port_forwarding: bool | None = None
    permit_pty: bool | None = None
    permit_user_rc: bool | None = None
    permit_x11_forwarding: bool | None = None

    def to_dict(self):
        return dataclasses.asdict(self)


class Cert:
    def __init__(self, cert: cryptography.hazmat.primitives.serialization.SSHCertificate):
        self._cert = cert

    @property
    def public_key(self) -> jwk.Public:
        public_key = jwk.Public(self._cert.public_key())
        return public_key

    @property
    def serial_number(self) -> int:
        return self._cert.serial

    @property
    def role(self) -> Role:
        match self._cert.type:
            case cryptography.hazmat.primitives.serialization.SSHCertificateType.HOST:
                role = Role.HOST
            case cryptography.hazmat.primitives.serialization.SSHCertificateType.USER:
                role = Role.USER
            case _:
                assert False
        return role

    @property
    def identifier(self) -> str:
        return self._cert.key_id.decode("utf-8")

    @property
    def principals(self) -> tuple[str, ...]:
        return tuple([p.decode("utf-8") for p in self._cert.valid_principals])

    @property
    def valid_after(self) -> int:
        return self._cert.valid_after

    @property
    def valid_before(self) -> int:
        return self._cert.valid_before

    @property
    def critical_options(self) -> CriticalOptions:
        if b"force-command" in self._cert.critical_options:
            force_command = self._cert.critical_options[b"force-command"].decode("utf-8")
        else:
            force_command = None
        if b"source-address" in self._cert.critical_options:
            source_address = self._cert.critical_options[b"source-address"].decode("utf-8").split(",")
        else:
            source_address = None
        verify_required = self._cert.critical_options.get(b"verify-required") == b""
        return CriticalOptions(
            force_command=force_command, source_address=source_address, verify_required=verify_required
        )

    @property
    def extensions(self) -> Extensions:
        no_touch_required = self._cert.extensions.get(b"no-touch-required") == b""
        permit_agent_forwarding = self._cert.extensions.get(b"permit-agent-forwarding") == b""
        permit_port_forwarding = self._cert.extensions.get(b"permit-port-forwarding") == b""
        permit_pty = self._cert.extensions.get(b"permit-pty") == b""
        permit_user_rc = self._cert.extensions.get(b"permit-user-rc") == b""
        permit_x11_forwarding = self._cert.extensions.get(b"permit-X11-forwarding") == b""

        return Extensions(
            no_touch_required=no_touch_required,
            permit_agent_forwarding=permit_agent_forwarding,
            permit_port_forwarding=permit_port_forwarding,
            permit_pty=permit_pty,
            permit_user_rc=permit_user_rc,
            permit_x11_forwarding=permit_x11_forwarding,
        )

    @property
    def signer_public_key(self) -> jwk.Public:
        return jwk.Public(self._cert.signature_key())

    def is_valid(self) -> bool:
        now = int(time.time())
        if now < self.valid_after or now > self.valid_before:
            return False
        return True

    @classmethod
    def create_host(
        cls,
        public_key: jwk.Public,
        serial_number: int,
        identifier: str,
        principals: list[str],
        valid_after: int,
        valid_before: int,
        signer: jwk.Private,
    ) -> Cert:
        builder = (
            cryptography.hazmat.primitives.serialization.SSHCertificateBuilder()
            .public_key(public_key.to_crypto())
            .type(cryptography.hazmat.primitives.serialization.SSHCertificateType.HOST)
            .valid_before(valid_before)
            .valid_after(valid_after)
            .key_id(identifier.encode("utf-8"))
            .valid_principals([p.encode("utf-8") for p in principals])
            .serial(serial_number)
        )
        cert = builder.sign(signer.to_crypto())
        return Cert(cert)

    @classmethod
    def create_user(
        cls,
        public_key: jwk.Public,
        serial_number: int,
        identifier: str,
        principals: list[str],
        valid_after: int,
        valid_before: int,
        critical_options: CriticalOptions,
        extensions: Extensions,
        signer: jwk.Private,
    ) -> Cert:
        builder = (
            cryptography.hazmat.primitives.serialization.SSHCertificateBuilder()
            .public_key(public_key.to_crypto())
            .type(cryptography.hazmat.primitives.serialization.SSHCertificateType.USER)
            .valid_before(valid_before)
            .valid_after(valid_after)
            .key_id(identifier.encode("utf-8"))
            .valid_principals([p.encode("utf-8") for p in principals])
            .serial(serial_number)
        )
        if critical_options.force_command is not None:
            builder = builder.add_critical_option(b"force-command", critical_options.force_command.encode("utf-8"))
        if critical_options.source_address is not None:
            builder = builder.add_critical_option(
                b"source-address", ",".join(critical_options.source_address).encode("utf-8")
            )
        if critical_options.verify_required:
            builder = builder.add_critical_option(b"verify-required", b"")
        if extensions.no_touch_required:
            builder = builder.add_extension(b"no-touch-required", b"")
        if extensions.permit_agent_forwarding:
            builder = builder.add_extension(b"permit-agent-forwarding", b"")
        if extensions.permit_port_forwarding:
            builder = builder.add_extension(b"permit-port-forwarding", b"")
        if extensions.permit_pty:
            builder = builder.add_extension(b"permit-pty", b"")
        if extensions.permit_user_rc:
            builder = builder.add_extension(b"permit-user-rc", b"")
        if extensions.permit_x11_forwarding:
            builder = builder.add_extension(b"permit-X11-forwarding", b"")
        cert = builder.sign(signer.to_crypto())
        return Cert(cert)

    def to_openssh(self) -> bytes:
        return self._cert.public_bytes()

    @classmethod
    def from_openssh(cls, data: bytes) -> Cert:
        try:
            cert = cryptography.hazmat.primitives.serialization.load_ssh_public_identity(data)
        except ValueError:
            raise exceptions.Error("Failed to load certificate. Most likely invalid.")
        except cryptography.exceptions.UnsupportedAlgorithm:
            raise exceptions.Error("Failed to load certificate. Unsupported algorithm.")
        if not isinstance(cert, cryptography.hazmat.primitives.serialization.SSHCertificate):
            raise exceptions.Error("Failed to load certificate. This is a public key.")
        if len(cert.nonce) < 16:
            raise exceptions.Error("Nonce must be bigger than 16 bytes")
        return Cert(cert)
