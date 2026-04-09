from __future__ import annotations

import hashlib
import hmac
import logging
import os.path
import secrets
import time
import types
import typing
import urllib.parse

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
            case _:
                parts.append(f'"{c}": {request.headers[c]}')
    parts.append(f'"@signature-params": {sig_params}')
    return "\n".join(parts)


class Signer:
    def __init__(
        self,
        prefix: str,
        key: jwk.Symmetric | jwk.Public,
        sign_func: typing.Callable[[bytes], bytes],
    ) -> None:
        self._prefix = prefix
        self._key = key
        self._sign_func = sign_func

    def sign(self, request: requests.PreparedRequest, covered: tuple[str, ...]) -> tuple[str, str]:
        """Generate HTTP signature headers for a single signer.

        Returns (Signature-Input entry, Signature entry) — caller joins multiple signers.
        """
        key_id = f"{self._prefix}:{self._key.thumbprint()}"

        # Build Signature-Input params
        inner = http_sfv.InnerList([http_sfv.Item(c) for c in covered])
        inner.params["created"] = int(time.time())
        inner.params["keyid"] = key_id
        inner.params["nonce"] = secrets.token_hex(16)

        # Serialize to get sig_params value
        sig_params = str(inner)

        # Build and sign the signature base
        sig_base = _build_signature_base(request, covered, sig_params)
        sig_bytes = self._sign_func(sig_base.encode())

        # Format the header values
        return (
            f"{self._prefix}={sig_params}",
            f"{self._prefix}={http_sfv.Item(sig_bytes)}",
        )


def hmac_signer(prefix: str, key: str) -> Signer:
    """Create a Signer using HMAC-SHA256.

    Args:
        prefix: key ID prefix (e.g., 'invitation')
        key: base64url-encoded symmetric key

    Returns:
        Signer instance with HMAC-SHA256 signing function
    """
    key_bytes = base64url.decode(key)
    signing_key = jwk.Symmetric.from_bytes(key_bytes)

    def sign_func(data: bytes) -> bytes:
        return hmac.new(key_bytes, data, hashlib.sha256).digest()

    return Signer(prefix, signing_key, sign_func)


@ssh_utils.exception
def private_key_signer(prefix: str, filename: str | None) -> tuple[Signer, jwk.Public]:
    """Create a Signer using Ed25519 from a file or SSH agent.

    Args:
        prefix: key ID prefix (e.g., 'account', 'session')
        filename: path to private key file, or SSH agent key identifier

    Returns:
        (Signer, public_key_dict) tuple

    Raises:
        exceptions.UI if key not found or unsupported type
    """
    if filename is None:
        raise exceptions.UI("Did you forget to login ?")

    # File-based key
    if os.path.exists(filename):
        with open(filename, "rb") as f:
            data = f.read()
        try:
            key = ssh_utils.load_private_key(data, password=None)
        except ValueError:
            raise exceptions.UI("Unable to parse data either as PEM or SSH format")
        if key.type != jwk.KeyType.ED25519:
            raise exceptions.UI(f"Unsupported: {key.type}")
        private = key.to_crypto()
        # Cast to narrow the overloaded signature to the Ed25519 case: (bytes) -> bytes
        sign_func = typing.cast(typing.Callable[[bytes], bytes], private.sign)
        return Signer(prefix, key.public(), sign_func), key.public()

    # SSH agent-based key
    ssh_agent = ssh.agent.Client()
    for identity in ssh_agent.list_identities():
        if identity.comment == filename or identity.public_key.match_ssh_fingerprint(filename):
            if identity.public_key.type != jwk.KeyType.ED25519:
                raise exceptions.UI(f"Unsupported: {identity.public_key.type}")

            def sign_func(
                data: bytes, agent: ssh.agent.Client = ssh_agent, ident: ssh.agent.Identity = identity
            ) -> bytes:
                return agent.sign(ident, data, 0)

            return Signer(prefix, identity.public_key, sign_func), identity.public_key

    raise exceptions.UI(f"Unable to find key matching {filename}")


class RequestsAuth:
    """HTTP Message Signature auth handler for requests library.

    Signs requests with one or more Signer instances and adds
    Signature-Input and Signature headers.
    """

    def __init__(self, signers: list[Signer]) -> None:
        self._signers = signers

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        if "Content-Digest" not in request.headers:
            body = b"" if request.body is None else request.body
            request.headers["Content-Digest"] = str(http_sfv.Dictionary({"sha-256": hashlib.sha256(body).digest()}))
        covered = ("@method", "@authority", "@target-uri", "content-digest")
        signatures_input: list[str] = []
        signatures: list[str] = []
        for signer in self._signers:
            signature_input, signature = signer.sign(request, covered)
            signatures_input.append(signature_input)
            signatures.append(signature)
        request.headers["Signature-Input"] = ", ".join(signatures_input)
        request.headers["Signature"] = ", ".join(signatures)
        return request


class HttpClient:
    def __init__(self, client: Client, auth: RequestsAuth|None, public_key: jwk.Public|None, timeout: float):
        self._client = client
        self._auth = auth
        self._public_key = public_key
        self._session = requests.Session()
        self._timeout = timeout

    @property
    def config(self) -> configuration.Config:
        return self._client.config

    @property
    def directory(self) -> types.SimpleNamespace:
        return self._client.directory

    @property
    def public_key(self) -> jwk.Public|None:
        return self._public_key

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
        if response.status_code == 400:
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
        return HttpClient(self, auth=None, public_key=None, timeout=self._timeout)

    def invitation_auth(self, account: str | None, invitation: str) -> HttpClient:
        account_signer, account_public_key = private_key_signer("account", account)
        signers = [hmac_signer("invitation", invitation), account_signer]
        return HttpClient(self, auth=RequestsAuth(signers), public_key=account_public_key, timeout=self._timeout)

    def login_auth(self, account: str | None, session: str | None) -> HttpClient:
        account_signer, _account_public_key = private_key_signer("account", account)
        session_signer, session_public_key = private_key_signer("session", session)
        signers = [account_signer, session_signer]
        return HttpClient(self, auth=RequestsAuth(signers), public_key=session_public_key, timeout=self._timeout)

    def session_auth(self, session: str | None) -> HttpClient:
        signer, public_key = private_key_signer("session", session)
        return HttpClient(self, auth=RequestsAuth([signer]), public_key=public_key, timeout=self._timeout)
