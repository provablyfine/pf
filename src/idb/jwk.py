from __future__ import annotations
import json
import hashlib
import enum
import secrets
import base64

from . import base64url
from . import ssh_buffer

import cryptography.hazmat.primitives.asymmetric.ed25519
import cryptography.hazmat.primitives.asymmetric.ec
import cryptography.hazmat.primitives.serialization


@enum.unique
class KeyType(enum.Enum):
    ED25519 = 1
    EC = 2
    SYMMETRIC = 3
    RSA = 4

@enum.unique
class SshFingerprintFormat(enum.Enum):
    MD5 = 1
    SHA1 = 2
    SHA256 = 3


def rfc7638_thumbprint(data):
    needed = {
        # RFC 7638 Section 3.2
        'RSA': ['e', 'kty', 'n'],
        # RFC 7638 Section 3.2
        'EC': ['crv', 'kty', 'x', 'y'],
        # RFC 8037 Section 2
        'OKP': ['crv', 'kty', 'x'],
        # RFC 7638 Section 3.2
        'oct': ['k', 'kty']
    }
    d = {k: data[k] for k in needed[data['kty']]}
    encoded = json.dumps(d).encode('utf-8')
    h = hashlib.sha256(encoded).digest()
    return base64url.encode(h)


class Symmetric:
    def __init__(self, data: dict):
        self._data = data

    @property
    def type(self):
        return KeyType.SYMMETRIC

    @classmethod
    def generate(klass) -> Symmetric:
        key = secrets.token_bytes(32)
        return klass.from_bytes(key)

    def thumbprint(self) -> str:
        return rfc7638_thumbprint(self._data)

    def to_bytes(self) -> bytes:
        return base64url.decode(self._data['k'])

    @classmethod
    def from_bytes(klass, data: bytes) -> Symmetric:
        return Symmetric({'k': base64url.encode(data), 'kty': 'oct'})

    def to_dict(self) -> dict:
        return self._data

    @classmethod
    def from_dict(klass, data: dict) -> Symmetric:
        return Symmetric(data)


# RFC 8452 Appendix A
ec_nist_to_secg = {
    'P-256': cryptography.hazmat.primitives.asymmetric.ec.SECP256R1,
    'P-384': cryptography.hazmat.primitives.asymmetric.ec.SECP384R1,
    'P-521': cryptography.hazmat.primitives.asymmetric.ec.SECP521R1,
}


class Public:
    def __init__(self, key):
        self._key = key

    @property
    def type(self) -> KeyType:
        match self._key:
            case cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey():
                return KeyType.ED25519
            case cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey():
                return KeyType.EC
            case cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey():
                return KeyType.RSA

    def thumbprint(self) -> str:
        return rfc7638_thumbprint(self.to_dict())

    def match_ssh_fingerprint(self, expected_fingerprint):
        colon = expected_fingerprint.find(':')
        prefix = expected_fingerprint[:colon]
        match prefix:
            case 'MD5':
                format = SshFingerprintFormat.MD5
            case 'SHA1':
                format = SshFingerprintFormat.SHA1
            case 'SHA256':
                format = SshFingerprintFormat.SHA256
        got_fingerprint = self.ssh_fingerprint(format=format)
        return expected_fingerprint == got_fingerprint

    def ssh_fingerprint(self, format: SshFingerprintFormat = SshFingerprintFormat.SHA256) -> str:
        match format:
            case SshFingerprintFormat.SHA256:
                # Spec from OpenSSH source code
                h = hashlib.sha256(self.to_ssh_bytes())
                fingerprint = base64.b64encode(h.digest()).rstrip(b'=').decode('ascii')
                return f'SHA256:{fingerprint}'
            case SshFingerprintFormat.SHA1:
                # Spec from OpenSSH source code
                h = hashlib.sha1(self.to_ssh_bytes())
                fingerprint = base64.b64encode(h.digest()).rstrip(b'=').decode('ascii')
                return f'SHA1:{fingerprint}'
            case SshFingerprintFormat.MD5:
                # RFC 4716 Section 4
                h = hashlib.md5(self.to_ssh_bytes())
                fingerprint = ':'.join('%02x' % i for i in h.digest())
                return f'MD5:{fingerprint}'

    def to_dict(self) -> dict:
        match self._key:
            case cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey():
                # RFC 8037 Section 2
                x = base64url.encode(self._key.public_bytes_raw())
                return {'kty': 'OKP', 'crv': 'Ed25519', 'x': x}
            case cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey():
                # RFC 7518 Section 6.2
                public_numbers = self._key.public_numbers()
                x = base64url.encode(public_numbers.x)
                y = base64url.encode(public_numbers.y)
                secg_to_nist = {v.name: k for k, v in ec_nist_to_secg.items()}
                return {'kty': 'EC', 'crv': secg_to_nist[public_numbers.curve], 'x': x, 'y': y}
            case cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey():
                # RFC 7518 Section 6.3.1
                public_numbers = self._key.public_numbers()
                e = base64url.encode(public_numbers.e)
                n = base64url.encode(public_numbers.n)
                return {'kty': 'RSA', 'e': e, 'n': n}
            case _:
                assert False

    @classmethod
    def from_dict(klass, data: dict) -> Public:
        match data['kty']:
            case 'OKP':
                # RFC 8037 Section 2
                public_bytes = base64url.decode(data['x'])
                key = cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
                return Public(key)

            case 'EC':
                # RFC 7518 Section 6.2
                x = base64url.decode(data['x'])
                y = base64url.decode(data['y'])
                curve = ec_nist_to_secg[data['crv']]
                public_numbers = cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicNumbers(x, y, curve)
                key = public_numbers.public_key()
                return Public(key)

            case 'RSA':
                # RFC 7518 Section 6.3.1
                e = base64url.decode(data['e'])
                n = base64url.decode(data['n'])
                numbers = cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicNumbers(e=e, n=n)
                return Public(numbers.public_key())

            case _:
                assert False

    @classmethod
    def from_ssh_bytes(klass, data: bytes) -> Public:
        reader = ssh_buffer.Reader(data)
        key_type = reader.read_string()
        match key_type:
            case b'ssh-ed25519':
                # RFC 8709 Section 4
                key = reader.read_string()
                assert len(key) == 32
                crypto_key = cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey.from_public_bytes(key)
                return Public(crypto_key)
            case b'ssh-rsa':
                # RFC 4253 section 6.6
                e = reader.read_mpint()
                n = reader.read_mpint()
                numbers = cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicNumbers(e=e, n=n)
                return Public(numbers.public_key())
            case b'ecdsa-sha2-nistp256':
                # RFC 5656 section 3.1
                curve = reader.read_string()
                assert curve == b'nistp256'
                q = reader.read_string()
                crypto_curve = cryptography.hazmat.primitives.asymmetric.ec.SECP256R1()
                crypto_key = cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey.from_encoded_point(crypto_curve, q)
                return Public(crypto_key)
            case b'ecdsa-sha2-nistp384':
                # RFC 5656 section 3.1
                curve = reader.read_string()
                assert curve == b'nistp384'
                q = reader.read_string()
                crypto_curve = cryptography.hazmat.primitives.asymmetric.ec.SECP384R1()
                crypto_key = cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey.from_encoded_point(crypto_curve, q)
                return Public(crypto_key)
            case b'ecdsa-sha2-nistp521':
                # RFC 5656 section 3.1
                curve = reader.read_string()
                assert curve == b'nistp521'
                q = reader.read_string()
                crypto_curve = cryptography.hazmat.primitives.asymmetric.ec.SECP521R1()
                crypto_key = cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey.from_encoded_point(crypto_curve, q)
                return Public(crypto_key)

    def to_ssh_bytes(self) -> bytes:
        writer = ssh_buffer.Writer()
        match self._key:
            case cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey():
                # RFC 8709 Section 4
                key = self._key.public_bytes_raw()
                writer.write_string(b'ssh-ed25519')
                writer.write_string(key)
                return writer.to_bytes()
            case cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey():
                # RFC 4253 section 6.6
                writer.write_string(b'ssh-rsa')
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
                writer.write_string(b'ecdsa-sha2-' + curve)
                writer.write_string(curve)
                q = self._key.public_bytes(
                    encoding= cryptography.hazmat.primitives.serialization.Encoding.X962,
                    format=cryptography.hazmat.primitives.serialization.PublicFormat.UncompressedPoint,
                )
                writer.write_string(q)
                return writer.to_bytes()
            case _:
                assert False

    def to_crypto(self):
        return self._key

    @classmethod
    def from_crypto(klass, key) -> Private:
        return Public(key)

    def to_pem(self) -> bytes:
        return self._key.public_bytes(
            encoding=cryptography.hazmat.primitives.serialization.Encoding.PEM,
            format=cryptography.hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @classmethod
    def from_pem(klass, data: bytes) -> Public:
        key = cryptography.hazmat.primitives.serialization.load_pem_public_key(data)
        return Private(key)


class Private:
    def __init__(self, key):
        self._key = key

    @property
    def type(self) -> KeyType:
        return self.public().type

    @classmethod
    def generate(klass, key_type: KeyType) -> Private:
        match key_type:
            case KeyType.ED25519:
                return klass.generate_ed25519()
            case KeyType.EC:
                return klass.generate_ec()
            case _:
                assert False

    @classmethod
    def generate_ed25519(klass) -> Private:
        key = cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.generate()
        return Private(key)

    @classmethod
    def generate_ec(klass) -> Private:
        key = cryptography.hazmat.primitives.asymmetric.ec.generate_private_key(cryptography.hazmat.primitives.asymmetric.ec.SECP256R1)
        return key

    def thumbprint(self) -> str:
        return rfc7638_thumbprint(self.to_dict())

    def to_dict(self) -> dict:
        match self._key:
            case cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey():
                # RFC 8037 Section 2
                x = base64url.encode(self._key.public_key().public_bytes_raw())
                d = base64url.encode(self._key.private_bytes_raw())
                return {'kty': 'OKP', 'crv': 'Ed25519', 'x': x, 'd': d}

            case cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey():
                # RFC 7518 Section 6.2
                private_numbers = self._key.private_numbers()
                public_numbers = private_numbers.public_numbers()
                x = base64url.encode(public_numbers.x)
                y = base64url.encode(public_numbers.y)
                d = base64url.encode(private_numbers.private_value)
                secg_to_nist = {v.name: k for k, v in ec_nist_to_secg.items()}
                return {'kty': 'EC', 'crv': ec_secg_to_nist[public_numbers.curve], 'x': x, 'y': y, 'd': d}
            case _:
                assert False

    @classmethod
    def from_dict(klass, data: dict) -> Private:
        match data['kty']:
            case 'OKP':
                # RFC 8037 Section 2
                private_bytes = base64url.decode(data['d'])
                key = cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
                return Private(key)

            case 'EC':
                # RFC 7518 Section 6.2
                x = base64url.decode(data['x'])
                y = base64url.decode(data['y'])
                d = base64url.decode(data['d'])
                curve = ec_nist_to_secg[data['crv']]
                public_numbers = cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicNumbers(x, y, curve)
                private_numbers = cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateNumbers(d, public_numbers)
                key = private_numbers.private_key()
                return Private(key)
            case _:
                assert False

    def public(self) -> Public:
        return Public(self._key.public_key())


    def to_crypto(self):
        return self._key

    @classmethod
    def from_crypto(klass, key) -> Private:
        return Private(key)

    def to_pem(self) -> bytes:
        return self._key.private_bytes(
            encoding=cryptography.hazmat.primitives.serialization.Encoding.PEM,
            format=cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8,
            encryption_algorithm=cryptography.hazmat.primitives.serialization.NoEncryption,
        )

    @classmethod
    def from_pem(klass, data: bytes, password: str=None) -> Private:
        key = cryptography.hazmat.primitives.serialization.load_pem_private_key(data, password=password)
        return Private(key)

    @classmethod
    def from_ssh(klass, data: bytes, password: str=None) -> Private:
        key = cryptography.hazmat.primitives.serialization.load_ssh_private_key(data, password=password)
        return Private(key)

    def to_ssh_bytes(self) -> bytes:
        writer = ssh_buffer.Writer()
        match self._key:
            case cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey():
                # https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent#name-eddsa-keys
                writer.write_string(b'ssh-ed25519')
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
