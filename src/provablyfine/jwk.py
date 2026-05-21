from __future__ import annotations

import base64
import enum
import hashlib
import json
import secrets

import cryptography.hazmat.primitives.asymmetric.ec
import cryptography.hazmat.primitives.asymmetric.ed25519
import cryptography.hazmat.primitives.asymmetric.rsa
import cryptography.hazmat.primitives.hashes
import cryptography.hazmat.primitives.serialization

from . import base64url


@enum.unique
class SshFingerprintFormat(enum.Enum):
    MD5 = 1
    SHA256 = 3


@enum.unique
class KeyType(enum.Enum):
    ED25519 = 1
    SYMMETRIC = 3
    ECDSA_NISTP256 = 5
    ECDSA_NISTP384 = 6
    ECDSA_NISTP521 = 7
    # We do not provide smaller keys because the
    # current secure minimum key size for RSA is 3072
    RSA_3072 = 8
    RSA_7680 = 9
    RSA_15360 = 10

    @classmethod
    def _mapping(cls) -> dict[str, KeyType]:
        return {
            "ed25519": KeyType.ED25519,
            "ecdsa-256": KeyType.ECDSA_NISTP256,
            "ecdsa-384": KeyType.ECDSA_NISTP384,
            "ecdsa-521": KeyType.ECDSA_NISTP521,
            "rsa-3072": KeyType.RSA_3072,
            "rsa-7680": KeyType.RSA_7680,
            "rsa-15360": KeyType.RSA_15360,
        }

    @classmethod
    def from_string(cls, key_type: str) -> KeyType:
        return KeyType._mapping()[key_type]

    def to_string(self) -> str:
        reverse_mapping = {v.value: k for k, v in self._mapping().items()}
        return reverse_mapping[self.value]


def rfc7638_thumbprint(data: dict[str, str]) -> str:
    needed = {
        # RFC 7638 Section 3.2
        "RSA": ["e", "kty", "n"],
        # RFC 7638 Section 3.2
        "EC": ["crv", "kty", "x", "y"],
        # RFC 8037 Section 2
        "OKP": ["crv", "kty", "x"],
        # RFC 7638 Section 3.2
        "oct": ["k", "kty"],
    }
    d = {k: data[k] for k in needed[data["kty"]]}
    encoded = json.dumps(d).encode("utf-8")
    h = hashlib.sha256(encoded).digest()
    return base64url.encode(h)


class Symmetric:
    def __init__(self, data: dict[str, str]):
        self._data = data

    @property
    def type(self) -> KeyType:
        return KeyType.SYMMETRIC

    @classmethod
    def generate(cls) -> Symmetric:
        key = secrets.token_bytes(32)
        return Symmetric.from_bytes(key)

    def thumbprint(self) -> str:
        return rfc7638_thumbprint(self._data)

    def to_bytes(self) -> bytes:
        return base64url.decode(self._data["k"])

    @classmethod
    def from_bytes(cls, data: bytes) -> Symmetric:
        return Symmetric({"k": base64url.encode(data), "kty": "oct"})

    def to_dict(self) -> dict[str, str]:
        return self._data

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> Symmetric:
        return Symmetric(data)


# RFC 8452 Appendix A
ec_nist_to_secg = {
    "P-256": cryptography.hazmat.primitives.asymmetric.ec.SECP256R1,
    "P-384": cryptography.hazmat.primitives.asymmetric.ec.SECP384R1,
    "P-521": cryptography.hazmat.primitives.asymmetric.ec.SECP521R1,
}

CryptographyPublicKey = (
    cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey
    | cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey
    | cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey
)

CryptographyPrivateKey = (
    cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey
    | cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey
    | cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey
)


class Public:
    def __init__(self, key: CryptographyPublicKey):
        self._key = key

    @property
    def type(self) -> KeyType:
        match self._key:
            case cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey():
                return KeyType.ED25519
            case cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey():
                match self._key.curve:
                    case cryptography.hazmat.primitives.asymmetric.ec.SECP256R1():
                        return KeyType.ECDSA_NISTP256
                    case cryptography.hazmat.primitives.asymmetric.ec.SECP384R1():
                        return KeyType.ECDSA_NISTP384
                    case cryptography.hazmat.primitives.asymmetric.ec.SECP521R1():
                        return KeyType.ECDSA_NISTP521
                    case _:
                        assert False
            case cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey():
                match self._key.key_size:
                    case 3072:
                        return KeyType.RSA_3072
                    case 7680:
                        return KeyType.RSA_7680
                    case 15360:
                        return KeyType.RSA_15360
                    case _:
                        assert False
            case _:
                assert False

    def thumbprint(self) -> str:
        return rfc7638_thumbprint(self.to_dict())

    def match_ssh_fingerprint(self, expected_fingerprint: str) -> bool:
        colon = expected_fingerprint.find(":")
        prefix = expected_fingerprint[:colon]
        if prefix == "MD5":
            raise ValueError("We do not support MD5 hash fingerprints")
        got_fingerprint = self.ssh_fingerprint()
        return expected_fingerprint == got_fingerprint

    def ssh_fingerprint(self) -> str:
        h = cryptography.hazmat.primitives.serialization.ssh_key_fingerprint(
            self.to_crypto(),
            cryptography.hazmat.primitives.hashes.SHA256(),
        )
        fingerprint = base64.b64encode(h).rstrip(b"=").decode("ascii")
        return f"SHA256:{fingerprint}"

    def to_dict(self) -> dict[str, str]:
        match self._key:
            case cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey():
                # RFC 8037 Section 2
                x = base64url.encode(self._key.public_bytes_raw())
                return {"kty": "OKP", "crv": "Ed25519", "x": x}
            case cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey():
                # RFC 7518 Section 6.2
                public_numbers = self._key.public_numbers()
                x = base64url.encode_uint(public_numbers.x)
                y = base64url.encode_uint(public_numbers.y)
                for crv, typ in ec_nist_to_secg.items():
                    if isinstance(public_numbers.curve, typ):
                        return {"kty": "EC", "crv": crv, "x": x, "y": y}
                assert False
            case cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey():
                # RFC 7518 Section 6.3.1
                public_numbers = self._key.public_numbers()
                e = base64url.encode_uint(public_numbers.e)
                n = base64url.encode_uint(public_numbers.n)
                return {"kty": "RSA", "e": e, "n": n}
            case _:
                assert False

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> Public:
        match data["kty"]:
            case "OKP":
                # RFC 8037 Section 2
                public_bytes = base64url.decode(data["x"])
                key = cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
                return Public(key)

            case "EC":
                # RFC 7518 Section 6.2
                x = base64url.decode_uint(data["x"])
                y = base64url.decode_uint(data["y"])
                curve = ec_nist_to_secg[data["crv"]]
                public_numbers = cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicNumbers(x, y, curve())
                key = public_numbers.public_key()
                return Public(key)

            case "RSA":
                # RFC 7518 Section 6.3.1
                e = base64url.decode_uint(data["e"])
                n = base64url.decode_uint(data["n"])
                numbers = cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicNumbers(e=e, n=n)
                return Public(numbers.public_key())

            case _:
                assert False

    def to_crypto(self) -> CryptographyPublicKey:
        return self._key

    @classmethod
    def from_crypto(cls, key: CryptographyPublicKey) -> Public:
        return Public(key)

    def to_pem(self) -> bytes:
        return self._key.public_bytes(
            encoding=cryptography.hazmat.primitives.serialization.Encoding.PEM,
            format=cryptography.hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @classmethod
    def from_pem(cls, data: bytes) -> Public:
        key = cryptography.hazmat.primitives.serialization.load_pem_public_key(data)
        assert isinstance(key, CryptographyPublicKey)
        return Public(key)

    def to_openssh(self) -> bytes:
        return self._key.public_bytes(
            encoding=cryptography.hazmat.primitives.serialization.Encoding.OpenSSH,
            format=cryptography.hazmat.primitives.serialization.PublicFormat.OpenSSH,
        )

    @classmethod
    def from_openssh(cls, data: bytes) -> Public:
        key = cryptography.hazmat.primitives.serialization.load_ssh_public_key(data)
        assert isinstance(key, CryptographyPublicKey)
        return Public(key)


class Private:
    def __init__(self, key: CryptographyPrivateKey):
        self._key = key

    @property
    def type(self) -> KeyType:
        return self.public().type

    @classmethod
    def generate(cls, key_type: KeyType) -> Private:
        match key_type:
            case KeyType.ED25519:
                return Private.generate_ed25519()
            case KeyType.ECDSA_NISTP256:
                return Private.generate_ecdsa_nistp256()
            case KeyType.ECDSA_NISTP384:
                return Private.generate_ecdsa_nistp384()
            case KeyType.ECDSA_NISTP521:
                return Private.generate_ecdsa_nistp521()
            case KeyType.RSA_3072:
                return Private.generate_rsa(3072)
            case KeyType.RSA_7680:
                return Private.generate_rsa(7680)
            case KeyType.RSA_15360:
                return Private.generate_rsa(15360)
            case _:
                assert False

    @classmethod
    def generate_ed25519(cls) -> Private:
        key = cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.generate()
        return Private(key)

    @classmethod
    def generate_ecdsa_nistp256(cls) -> Private:
        key = cryptography.hazmat.primitives.asymmetric.ec.generate_private_key(
            cryptography.hazmat.primitives.asymmetric.ec.SECP256R1()
        )
        return Private(key)

    @classmethod
    def generate_ecdsa_nistp384(cls) -> Private:
        key = cryptography.hazmat.primitives.asymmetric.ec.generate_private_key(
            cryptography.hazmat.primitives.asymmetric.ec.SECP384R1()
        )
        return Private(key)

    @classmethod
    def generate_ecdsa_nistp521(cls) -> Private:
        key = cryptography.hazmat.primitives.asymmetric.ec.generate_private_key(
            cryptography.hazmat.primitives.asymmetric.ec.SECP521R1()
        )
        return Private(key)

    @classmethod
    def generate_rsa(cls, size: int) -> Private:
        key = cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key(public_exponent=65537, key_size=size)
        return Private(key)

    def thumbprint(self) -> str:
        return rfc7638_thumbprint(self.to_dict())

    def to_dict(self) -> dict[str, str]:
        match self._key:
            case cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey():
                # RFC 8037 Section 2
                x = base64url.encode(self._key.public_key().public_bytes_raw())
                d = base64url.encode(self._key.private_bytes_raw())
                return {"kty": "OKP", "crv": "Ed25519", "x": x, "d": d}

            case cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey():
                # RFC 7518 Section 6.2
                private_numbers = self._key.private_numbers()
                public_numbers = private_numbers.public_numbers
                x = base64url.encode_uint(public_numbers.x)
                y = base64url.encode_uint(public_numbers.y)
                d = base64url.encode_uint(private_numbers.private_value)
                for crv, typ in ec_nist_to_secg.items():
                    if isinstance(public_numbers.curve, typ):
                        return {"kty": "EC", "crv": crv, "x": x, "y": y, "d": d}
                assert False
            case _:
                assert False

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> Private:
        match data["kty"]:
            case "OKP":
                # RFC 8037 Section 2
                private_bytes = base64url.decode(data["d"])
                key = cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.from_private_bytes(
                    private_bytes
                )
                return Private(key)

            case "EC":
                # RFC 7518 Section 6.2
                x = base64url.decode_uint(data["x"])
                y = base64url.decode_uint(data["y"])
                d = base64url.decode_uint(data["d"])
                curve = ec_nist_to_secg[data["crv"]]
                public_numbers = cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicNumbers(x, y, curve())
                private_numbers = cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateNumbers(
                    d, public_numbers
                )
                key = private_numbers.private_key()
                return Private(key)
            case _:
                assert False

    def public(self) -> Public:
        return Public(self._key.public_key())

    def to_crypto(self):
        return self._key

    @classmethod
    def from_crypto(cls, key: CryptographyPrivateKey) -> Private:
        return Private(key)

    def to_pem(self) -> bytes:
        return self._key.private_bytes(
            encoding=cryptography.hazmat.primitives.serialization.Encoding.PEM,
            format=cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8,
            encryption_algorithm=cryptography.hazmat.primitives.serialization.NoEncryption(),
        )

    @classmethod
    def from_pem(cls, data: bytes, password: bytes | None = None) -> Private:
        key = cryptography.hazmat.primitives.serialization.load_pem_private_key(data, password=password)
        assert isinstance(key, CryptographyPrivateKey)
        return Private(key)

    def to_openssh(self) -> bytes:
        return self._key.private_bytes(
            encoding=cryptography.hazmat.primitives.serialization.Encoding.PEM,
            format=cryptography.hazmat.primitives.serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=cryptography.hazmat.primitives.serialization.NoEncryption(),
        )

    @classmethod
    def from_openssh(cls, data: bytes, password: bytes | None = None) -> Private:
        key = cryptography.hazmat.primitives.serialization.load_ssh_private_key(data, password=password)
        assert isinstance(key, CryptographyPrivateKey)
        return Private(key)
