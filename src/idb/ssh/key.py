from __future__ import annotations
import enum
import hashlib
import base64
import dataclasses

from . import buffer
from . import constants
from . import exceptions

import cryptography.hazmat.primitives.asymmetric.ed25519
import cryptography.hazmat.primitives.asymmetric.ec
import cryptography.hazmat.primitives.serialization


@enum.unique
class FingerprintFormat(enum.Enum):
    MD5 = 1
    SHA1 = 2
    SHA256 = 3


@dataclasses.dataclass(frozen=True)
class SerializedPublicKey:
    key_type: bytes
    key: bytes


class Public:
    def __init__(self, key):
        self._key = key

    def verify(self, signature: bytes, data: bytes):
        try:
            self._verify(signature, data)
        except cryptography.exceptions.InvalidSignature:
            raise exceptions.InvalidSignature()

    def _verify(self, signature: bytes, data: bytes):
        # We read the signature from the SSH signature format
        reader = buffer.Reader(signature)
        signature_type = reader.read_string()
        signature = reader.read_string()

        match self._key:
            case cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey():
                if signature_type != b'ssh-dss':
                    raise exceptions.InvalidSignature('Invalid signature type')
                self._key.verify(signature, data, cryptography.hazmat.primitives.hashes.SHA1())
            case cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey():
                if signature_type != b'ssh-ed25519':
                    raise exceptions.InvalidSignature('Invalid signature type')
                self._key.verify(signature, data)
            case cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey():
                if signature_type != b'ssh-ed448':
                    raise exceptions.InvalidSignature('Invalid signature type')
                self._key.verify(signature, data)
            case cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey():
                match signature_type:
                    case b'ssh-rsa':
                        h = cryptography.hazmat.primitives.hashes.SHA1()
                    case b'rsa-sha2-256':
                        h = cryptography.hazmat.primitives.hashes.SHA256()
                    case b'rsa-sha2-512':
                        h = cryptography.hazmat.primitives.hashes.SHA512()
                    case _:
                        raise exceptions.InvalidSignature('Invalid signature type')
                self._key.verify(data, cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15(), h)
            case cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey():
                # RFC 5656
                match signature_type:
                    case b'ecdsa-sha2-nistp256':
                        h = cryptography.hazmat.primitives.hashes.SHA256()
                    case b'ecdsa-sha2-nistp384':
                        h = cryptography.hazmat.primitives.hashes.SHA384()
                    case b'ecdsa-sha2-nistp512':
                        h = cryptography.hazmat.primitives.hashes.SHA512()
                    case _:
                        raise exceptions.InvalidSignature('Invalid signature type')
                return self._key.verify(signature, data, cryptography.hazmat.primitives.asymmetric.ec.ECDSA(h))


    def match_ssh_fingerprint(self, expected_fingerprint):
        colon = expected_fingerprint.find(':')
        prefix = expected_fingerprint[:colon]
        match prefix:
            case 'MD5':
                format = FingerprintFormat.MD5
            case 'SHA1':
                format = FingerprintFormat.SHA1
            case 'SHA256':
                format = FingerprintFormat.SHA256
        got_fingerprint = self.fingerprint(format=format)
        return expected_fingerprint == got_fingerprint

    def fingerprint(self, format: FingerprintFormat = FingerprintFormat.SHA256) -> str:
        match format:
            case FingerprintFormat.SHA256:
                # Spec from OpenSSH source code
                h = hashlib.sha256(self.to_bytes())
                fingerprint = base64.b64encode(h.digest()).rstrip(b'=').decode('ascii')
                return f'SHA256:{fingerprint}'
            case FingerprintFormat.SHA1:
                # Spec from OpenSSH source code
                h = hashlib.sha1(self.to_bytes())
                fingerprint = base64.b64encode(h.digest()).rstrip(b'=').decode('ascii')
                return f'SHA1:{fingerprint}'
            case FingerprintFormat.MD5:
                # RFC 4716 Section 4
                h = hashlib.md5(self.to_bytes())
                fingerprint = ':'.join('%02x' % i for i in h.digest())
                return f'MD5:{fingerprint}'

    def to_crypto(self):
        return self._key

    @classmethod
    def from_crypto(klass, key) -> Public:
        return Public(key)

    def to_bytes(self) -> bytes:
        serialized = self.to_serialized()
        writer = buffer.Writer()
        writer.write_string(serialized.key_type)
        writer.write_bytes(serialized.key)
        return writer.to_bytes()

    def to_serialized(self) -> SerializedPublicKey:
        writer = buffer.Writer()
        match self._key:
            case cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey():
                # RFC 8709 Section 4
                key_type = b'ssh-ed25519'
                key = self._key.public_bytes_raw()
                writer.write_string(key)
                return writer.to_bytes()
            case cryptography.hazmat.primitives.asymmetric.ed448.Ed448PublicKey():
                # RFC 8709 Section 4
                key_type = b'ssh-ed448'
                key = self._key.public_bytes_raw()
                writer.write_string(key)
                return writer.to_bytes()
            case cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey():
                # RFC 4253 section 6.6
                key_type = b'ssh-rsa'
                numbers = self._key.public_numbers()
                writer.write_mpint(numbers.e)
                writer.write_mpint(numbers.n)
                return writer.to_bytes()
            case cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey():
                # RFC 5656 section 3.1
                match self._key.curve:
                    case cryptography.hazmat.primitives.asymmetric.ec.SECP256R1():
                        curve = b'nistp256'
                    case cryptography.hazmat.primitives.asymmetric.ec.SECP384R1():
                        curve = b'nistp384'
                    case cryptography.hazmat.primitives.asymmetric.ec.SECP521R1():
                        curve = b'nistp521'
                key_type = b'ecdsa-sha2-' + curve
                writer.write_string(curve)
                q = self._key.public_bytes(
                    encoding= cryptography.hazmat.primitives.serialization.Encoding.X962,
                    format=cryptography.hazmat.primitives.serialization.PublicFormat.UncompressedPoint,
                )
                writer.write_string(q)
                return writer.to_bytes()
            case cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey():
                key_type = b'ssh-dss'
                public_numbers = self._key.public_numbers()
                parameter_numbers = public_numbers.parameter.numbers
                writer.write_mpint(parameter_numbers.p)
                writer.write_mpint(parameter_numbers.q)
                writer.write_mpint(parameter_numbers.g)
                writer.write_mpint(public_numbers.y)
            case _:
                assert False
        return SerializedPublicKey(key_type=key_type, key=writer.to_bytes())

    @classmethod
    def from_ed25519_reader(klass, reader: buffer.Reader) -> Public:
        # RFC 8709 Section 4
        key = reader.read_string()
        assert len(key) == 32
        crypto_key = cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey.from_public_bytes(key)
        return Public(crypto_key)

    @classmethod
    def from_ed448_reader(klass, reader: buffer.Reader) -> Public:
        # RFC 8709 Section 4
        key = reader.read_string()
        assert len(key) == 57
        crypto_key = cryptography.hazmat.primitives.asymmetric.ed448.Ed448PublicKey.from_public_bytes(key)
        return Public(crypto_key)

    @classmethod
    def from_rsa_reader(klass, reader: buffer.Reader) -> Public:
        # RFC 4253 section 6.6
        e = reader.read_mpint()
        n = reader.read_mpint()
        numbers = cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicNumbers(e=e, n=n)
        return Public(numbers.public_key())

    @classmethod
    def from_ecdsa_reader(klass, reader: buffer.Reader) -> Public:
        # RFC 5656 section 3.1
        curve = reader.read_string()
        q = reader.read_string()
        match curve:
            case b'nistp256':
                crypto_curve = cryptography.hazmat.primitives.asymmetric.ec.SECP256R1()
            case b'nistp384':
                crypto_curve = cryptography.hazmat.primitives.asymmetric.ec.SECP384R1()
            case b'nistp521':
                crypto_curve = cryptography.hazmat.primitives.asymmetric.ec.SECP521R1()
        crypto_key = cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey.from_encoded_point(crypto_curve, q)
        return Public(crypto_key)

    @classmethod
    def from_dss_reader(klass, reader: buffer.Reader) -> Public:
        # RFC 4253 Section 6.6
        p = reader.read_mpint()
        q = reader.read_mpint()
        g = reader.read_mpint()
        y = reader.read_mpint()
        parameter_numbers =  cryptography.hazmat.primitives.asymmetric.dsa.DSAParameterNumbers(p, q, g)
        public_numbers =  cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicNumbers(y, parameter_numbers)
        return Public(public_numbers.public_key())

    @classmethod
    def from_bytes(klass, data: bytes) -> Public:
        reader = buffer.Reader(data)
        key_type = reader.read_string()
        match key_type:
            case b'ssh-dss':
                return klass.from_dss_reader(reader)
            case b'ssh-ed25519':
                return klass.from_ed25519_reader(reader)
            case b'ssh-ed448':
                return klass.from_ed448_reader(reader)
            case b'ssh-rsa':
                return klass.from_rsa_reader(reader)
            case b'ecdsa-sha2-nistp256':
                return klass.from_ecdsa_reader(reader)
            case b'ecdsa-sha2-nistp384':
                return klass.from_ecdsa_reader(reader)
            case b'ecdsa-sha2-nistp521':
                return klass.from_ecdsa_reader(reader)
            case _:
                assert False

    @classmethod
    def from_openssh_file(klass, data: bytes) -> Public:
        key = cryptography.hazmat.primitives.serialization.load_ssh_public_key(data)
        return Public(key)


class Private:
    def __init__(self, key):
        self._key = key

    def sign(self, data: bytes, flags: int) -> bytes:
        match self._key:
            case cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey():
                signature = self._key.sign(data, cryptography.hazmat.primitives.hashes.SHA1())
                signature_type = b'ssh-dss'
            case cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey():
                signature = self._key.sign(data)
                signature_type = b'ssh-ed25519'
            case cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey():
                signature = self._key.sign(data)
                signature_type = b'ssh-ed448'
            case cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey():
                match flags:
                    case constants.RSA.SHA2_256:
                        h = cryptography.hazmat.primitives.hashes.SHA256()
                        signature_type = b'rsa-sha2-256'
                    case constants.RSA.SHA2_512:
                        h = cryptography.hazmat.primitives.hashes.SHA512()
                        signature_type = b'rsa-sha2-512'
                    case _:
                        # If you are here, you are oh so badly fucked
                        h = cryptography.hazmat.primitives.hashes.SHA1()
                        signature_type = b'ssh-rsa'
                signature = self._key.sign(data, cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15(), h)
            case cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey():
                match self._key.curve:
                    case cryptography.hazmat.primitives.asymmetric.ec.SECP256R1():
                        h = cryptography.hazmat.primitives.hashes.SHA256()
                        signature_type = b'ecdsa-sha2-nistp256'
                    case cryptography.hazmat.primitives.asymmetric.ec.SECP384R1():
                        h = cryptography.hazmat.primitives.hashes.SHA384()
                        signature_type = b'ecdsa-sha2-nistp384'
                    case cryptography.hazmat.primitives.asymmetric.ec.SECP521R1():
                        h = cryptography.hazmat.primitives.hashes.SHA512()
                        signature_type = b'ecdsa-sha2-nistp512'
                    case _:
                        raise exceptions.Error('Invalid ECDSA curve')
                signature = self._key.sign(data, cryptography.hazmat.primitives.asymmetric.ec.ECDSA(h))
        writer = buffer.Writer()
        writer.write_string(signature_type)
        writer.write_string(signature)
        return writer.to_bytes()

    def public(self):
        return Public(self._key.public_key())

    @classmethod
    def from_openssh_file(klass, data: bytes, password: str=None) -> Private:
        key = cryptography.hazmat.primitives.serialization.load_ssh_private_key(data, password=password)
        return Private(key)

    def to_bytes(self) -> bytes:
        writer = buffer.Writer()
        match self._key:
            case cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey():
                # https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent#section-3.2.1
                writer.write_string(b'ssh-dss')
                private_numbers = self._key.private_numbers()
                public_numbers = private_numbers.public_numbers
                parameter_numbers = public_numbers.parameter.numbers
                writer.write_mpint(parameter_numbers.p)
                writer.write_mpint(parameter_numbers.q)
                writer.write_mpint(parameter_numbers.g)
                writer.write_mpint(public_numbers.y)
                writer.write_mpint(private_numbers.x)
                return writer.to_bytes()
            case cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey():
                # https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent#name-eddsa-keys
                writer.write_string(b'ssh-ed25519')
                public_key = self._key.public_key().public_bytes_raw()
                private_key = self._key.private_bytes_raw()
                writer.write_string(public_key)
                writer.write_string(private_key + public_key)
                return writer.to_bytes()
            case cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey():
                # https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent#name-eddsa-keys
                writer.write_string(b'ssh-ed448')
                public_key = self._key.public_key().public_bytes_raw()
                private_key = self._key.private_bytes_raw()
                writer.write_string(public_key)
                writer.write_string(private_key + public_key)
                return writer.to_bytes()
            case cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey():
                # https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent#name-rsa-keys
                writer.write_string(b'ssh-rsa')
                private_numbers = self._key.private_numbers()
                public_numbers = private_numbers.public_numbers
                writer.write_mpint(public_numbers.n)
                writer.write_mpint(public_numbers.e)
                writer.write_mpint(private_numbers.d)
                writer.write_mpint(private_numbers.iqmp)
                writer.write_mpint(private_numbers.p)
                writer.write_mpint(private_numbers.q)
                return writer.to_bytes()
            case cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey():
                # https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent#name-ecdsa-keys
                match self._key.curve:
                    case cryptography.hazmat.primitives.asymmetric.ec.SECP256R1():
                        curve = b'nistp256'
                    case cryptography.hazmat.primitives.asymmetric.ec.SECP384R1():
                        curve = b'nistp384'
                    case cryptography.hazmat.primitives.asymmetric.ec.SECP521R1():
                        curve = b'nistp521'
                writer.write_string(b'ecdsa-sha2-' + curve)
                writer.write_string(curve)
                q = self._key.public_key().public_bytes(
                    encoding= cryptography.hazmat.primitives.serialization.Encoding.X962,
                    format=cryptography.hazmat.primitives.serialization.PublicFormat.UncompressedPoint,
                )
                d = self._key.private_numbers().private_value
                writer.write_string(q)
                writer.write_mpint(d)
                return writer.to_bytes()
            case _:
                assert False
