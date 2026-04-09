from __future__ import annotations

import abc
import hashlib
import hmac
import logging
import os.path
import secrets
import time
import types
import typing
import urllib.parse

import cryptography.hazmat.primitives.asymmetric.ed25519
import http_sfv
import requests

from .. import base64url, jwk, ssh
from . import configuration, exceptions, ssh_utils

# http_sfv type stubs are incomplete (private imports, reportPrivateImportUsage)
# pyright: reportPrivateImportUsage=false

logger = logging.getLogger(__name__)


def _build_signature_base(
    request: requests.PreparedRequest,
    covered: tuple[str, ...],
    sig_params: str,
) -> str:
    """Build the signature base string per RFC 9421 §2.5."""
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


class PrivateSigner(Signer):
    @abc.abstractmethod
    def public_key(self) -> jwk.Public:
        pass


class FileSigner(PrivateSigner):
    def __init__(self, prefix: str, key: jwk.Private) -> None:
        super().__init__(prefix)
        self._key = key

    def public_key(self) -> jwk.Public:
        return self._key.public()

    def thumbprint(self) -> str:
        return self._key.thumbprint()

    def sign(self, data: bytes) -> bytes:
        key  = self._key.to_crypto()
        assert isinstance(key, cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey)
        return key.sign(data)


class AgentSigner(PrivateSigner):
    def __init__(self, prefix: str, key: jwk.Public) -> None:
        super().__init__(prefix)
        self._key = key

    def public_key(self) -> jwk.Public:
        return self._key

    def thumbprint(self) -> str:
        return self._key.thumbprint()

    def sign(self, data: bytes) -> bytes:
        fingerprint = self._key.ssh_fingerprint()
        ssh_agent = ssh.agent.Client()
        for identity in ssh_agent.list_identities():
            if identity.public_key.match_ssh_fingerprint(fingerprint):
                assert identity.public_key.type == jwk.KeyType.ED25519
                return ssh_agent.sign(identity, data, 0)
        raise exceptions.UI(f"Unable to find requested key={fingerprint}")


class HmacSigner(Signer):
    def __init__(self, prefix: str, key: jwk.Symmetric):
        super().__init__(prefix)
        self._key = key

    def thumbprint(self) -> str:
        return self._key.thumbprint()

    def sign(self, data: bytes) -> bytes:
        return hmac.new(self._key.to_bytes(), data, hashlib.sha256).digest()


def hmac_signer(prefix: str, key: str) -> Signer:
    k = jwk.Symmetric.from_bytes(base64url.decode(key))
    return HmacSigner(prefix, k)


@ssh_utils.exception
def private_key_signer(prefix: str, filename: str | None) -> PrivateSigner:
    if filename is None:
        raise exceptions.UI("Did you forget to login ?")

    if os.path.exists(filename):
        with open(filename, "rb") as f:
            data = f.read()
        try:
            key = ssh_utils.load_private_key(data, password=None)
        except ValueError:
            raise exceptions.UI("Unable to parse data either as PEM or SSH format")
        if key.type != jwk.KeyType.ED25519:
            raise exceptions.UI(f"Unsupported: {key.type}")
        return FileSigner(prefix, key)

    ssh_agent = ssh.agent.Client()
    for identity in ssh_agent.list_identities():
        if identity.comment == filename or identity.public_key.match_ssh_fingerprint(filename):
            if identity.public_key.type != jwk.KeyType.ED25519:
                raise exceptions.UI(f"Unsupported: {identity.public_key.type}")

            return AgentSigner(prefix, identity.public_key)
    raise exceptions.UI(f"Unable to find requested key={filename}")


class RequestsAuth:
    """HTTP Message Signature auth handler for requests library.

    Signs requests with one or more Signer instances and adds
    Signature-Input and Signature headers.
    """

    def __init__(self, signers: typing.Sequence[Signer]) -> None:
        self._signers = signers

    def _sign(self, signer: Signer, request: requests.PreparedRequest, covered: tuple[str, ...]) -> tuple[str, str]:
        """Generate HTTP signature headers for a single signer.

        Returns (Signature-Input entry, Signature entry) — caller joins multiple signers.
        """
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
            body = b"" if request.body is None else request.body
            if isinstance(body, str):
                body = body.encode()
            request.headers["Content-Digest"] = str(http_sfv.Dictionary({"sha-256": hashlib.sha256(body).digest()}))
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


class HttpClient:
    def __init__(self, client: Client, auth: RequestsAuth|None, timeout: float):
        self._client = client
        self._auth = auth
        self._session = requests.Session()
        self._timeout = timeout

    @property
    def config(self) -> configuration.Config:
        return self._client.config

    @property
    def directory(self) -> types.SimpleNamespace:
        return self._client.directory

    def request(
        self,
        method: str,
        url: str,
        data: typing.Any = None,
        json: typing.Any = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        params: dict[str, typing.Any] | None = None,
    ) -> requests.Response:
        request = requests.Request(
            method=method, url=url, data=data, json=json, headers=headers, params=params
        )
        request = request.prepare()
        if self._auth is not None:
            request = self._auth(request)

        logger.info(f"tx {request.method} to {request.url}")
        logger.debug(f"tx headers: {request.headers}")
        logger.debug(f"tx body: {request.body}")
        try:
            response = self._session.send(request, timeout=self._timeout)
        except requests.exceptions.ConnectionError:
            raise exceptions.UI("Unable to connect to server. #3")
        except requests.exceptions.ReadTimeout:
            raise exceptions.UI("Unable to connect to server. #4")
        logger.info(f"rx status: {response.status_code}")
        logger.debug(f"rx headers: {response.headers}")
        logger.debug(f"rx body: {response.content}")
        if response.status_code in [400, 422]:
            problem = response.json()
            title = problem.get("title")
            detail = problem.get("detail")
            if detail is not None:
                raise exceptions.UI(f"{title} {detail}")
            else:
                raise exceptions.UI(f"{title}")

        content_type = response.headers.get("Content-Type", "")
        if content_type in ["application/json", "application/problem+json"]:
            problem = response.json()
            instance = problem.get("instance")
            title = problem.get("title")
            detail = problem.get("detail")
            type = problem.get("type")
            if instance is not None and type is not None:
                logger.warning(f"{title} {detail} {instance}")
            if instance is not None:
                debug = requests.get(instance, timeout=0.5)
                if "backtrace" in debug.json():
                    raise exceptions.UI(debug.json()["backtrace"])
                raise exceptions.UI(str(debug.json()))
        return response

    def get(self, url: str, *, params: dict[str, typing.Any] | None = None) -> requests.Response:
        return self.request("GET", url, params=params)

    def post(self, url: str, *, json: typing.Any = None) -> requests.Response:
        return self.request("POST", url, json=json)

    def patch(self, url: str, *, json: typing.Any = None) -> requests.Response:
        return self.request("PATCH", url, json=json)

    def delete(self, url: str) -> requests.Response:
        return self.request("DELETE", url)

    def put(self, url: str, *, json: typing.Any = None) -> requests.Response:
        return self.request("PUT", url, json=json)

class InvitationHttpClient(HttpClient):
    def __init__(self, client: Client, auth: RequestsAuth|None, timeout: float, account_public_key: jwk.Public):
        super().__init__(client, auth, timeout)
        self._account_public_key = account_public_key

    @property
    def account_public_key(self) -> jwk.Public:
        return self._account_public_key


class Client:
    def __init__(self, config: configuration.Config, timeout: float=1.0):
        self._config = config
        self._directory = None
        self._timeout = timeout

    @property
    def config(self) -> configuration.Config:
        return self._config

    @property
    def directory(self) -> types.SimpleNamespace:
        if self._directory is not None:
            return self._directory
        if self._config.directory is not None:
            self._directory = types.SimpleNamespace(self._config.directory)
            return self._directory
        try:
            response = requests.get(self._config.directory_url, timeout=self._timeout)
        except requests.exceptions.ConnectionError:
            raise exceptions.UI("Unable to connect to server. #1")
        except requests.exceptions.ReadTimeout:
            raise exceptions.UI("Unable to connect to server #2")
        if response.status_code != 200:
            raise exceptions.UI("Unable to read directory from server")
        self._directory = types.SimpleNamespace(response.json())
        return self._directory

    @property
    def no_auth(self) -> HttpClient:
        return HttpClient(self, auth=None, timeout=self._timeout)

    def invitation_auth(self, account: str | None, invitation: str) -> InvitationHttpClient:
        invitation_signer = hmac_signer("invitation", invitation)
        account_signer = private_key_signer("account", account)
        signers = [ invitation_signer, account_signer]
        return InvitationHttpClient(
            self, 
            auth=RequestsAuth(signers),
            timeout=self._timeout,
            account_public_key=account_signer.public_key(),
        )

    def login_auth(self, account: str | None, session: str | None) -> HttpClient:
        signers = [
            private_key_signer("account", account),
            private_key_signer("session", session),
        ]
        return HttpClient(self, auth=RequestsAuth(signers), timeout=self._timeout)

    def session_auth(self, session: str | None) -> HttpClient:
        signers = [private_key_signer("session", session)]
        return HttpClient(self, auth=RequestsAuth(signers), timeout=self._timeout)
