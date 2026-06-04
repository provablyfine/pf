from __future__ import annotations

import hashlib
import secrets
import time
import typing
import urllib.parse

import http_sfv
import requests

from .signer import Signer

# http_sfv type stubs are incomplete (private imports, reportPrivateImportUsage)
# pyright: reportPrivateImportUsage=false


def _build_signature_base(
    request: requests.PreparedRequest,
    covered: tuple[str, ...],
    sig_params: str,
) -> str:
    parts: list[str] = []
    for c in covered:
        match c:
            case "@method":
                parts.append(f'"@method": {request.method}')
            case "@authority":
                parts.append(f'"@authority": {urllib.parse.urlparse(request.url).netloc}')
            case "@target-uri":
                parts.append(f'"@target-uri": {request.url}')
            case "@signature-params":
                parts.append(f'"@signature-params": {sig_params}')
            case _:
                parts.append(f'"{c}": {request.headers[c]}')
    return "\n".join(parts)


class Auth:
    """HTTP Message Signatures (RFC 9421) — signs a request with one or more Signer instances."""

    def __init__(self, signers: typing.Sequence[Signer]) -> None:
        self._signers = signers

    def _sign(self, signer: Signer, request: requests.PreparedRequest, covered: tuple[str, ...]) -> tuple[str, str]:
        key_id = f"{signer.prefix()}:{signer.thumbprint()}"

        inner = http_sfv.InnerList([http_sfv.Item(c) for c in covered])
        inner.params["created"] = int(time.time())
        inner.params["keyid"] = key_id
        inner.params["nonce"] = secrets.token_hex(16)

        sig_params = str(inner)
        sig_base = _build_signature_base(request, covered, sig_params)
        sig_bytes = signer.sign(sig_base.encode())

        return (
            f"{signer.prefix()}={sig_params}",
            f"{signer.prefix()}={http_sfv.Item(sig_bytes)}",
        )

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        if "Content-Digest" not in request.headers:
            body = request.body or b""
            if isinstance(body, str):
                body_bytes = body.encode()
            else:
                body_bytes = body if isinstance(body, bytes) else b""
            digest = hashlib.sha256(body_bytes).digest()
            request.headers["Content-Digest"] = str(http_sfv.Dictionary({"sha-256": digest}))
        covered = ("@method", "@authority", "@target-uri", "content-digest", "@signature-params")
        signatures_input: list[str] = []
        signatures: list[str] = []
        for signer in self._signers:
            signature_input, signature = self._sign(signer, request, covered)
            signatures_input.append(signature_input)
            signatures.append(signature)
        request.headers["Signature-Input"] = ", ".join(signatures_input)
        request.headers["Signature"] = ", ".join(signatures)
        return request
