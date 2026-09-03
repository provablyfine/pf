from __future__ import annotations

import abc
import hashlib
import hmac
import json

from . import _base64url


def _rfc7638_thumbprint(key_data: dict[str, str]) -> str:
    # The insertion order of key_data must match the required RFC 7638 lexicographic order.
    encoded = json.dumps(key_data, separators=(",", ":")).encode("utf-8")
    return _base64url.encode(hashlib.sha256(encoded).digest())


class Signer(abc.ABC):
    def __init__(self, prefix: str):
        self._prefix = prefix

    def prefix(self) -> str:
        return self._prefix

    @abc.abstractmethod
    def thumbprint(self) -> str:
        pass

    @abc.abstractmethod
    def sign(self, data: bytes) -> bytes:
        pass


class HmacSigner(Signer):
    def __init__(self, prefix: str, key: bytes):
        super().__init__(prefix)
        self._key = key

    def thumbprint(self) -> str:
        return _rfc7638_thumbprint({"k": _base64url.encode(self._key), "kty": "oct"})

    def sign(self, data: bytes) -> bytes:
        return hmac.new(self._key, data, hashlib.sha256).digest()
