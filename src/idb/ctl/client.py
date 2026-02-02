import types
import os.path
import logging
import hashlib
import urllib.parse
import secrets

import requests
import http_message_signatures

from . import exceptions
from . import ssh_commands
from .. import ssh
from .. import base64url
from .. import jwk


logger = logging.getLogger(__name__)


class KeyResolver:
    def __init__(self, private_key):
        self._private_key = private_key

    def resolve_public_key(self, key_id: str):
        raise NotImplementedError("This method must be implemented by a subclass.")

    def resolve_private_key(self, key_id: str):
        return self._private_key


class CaseInsensitiveDict(dict):
    def __init__(self, *args, **kwargs):
        self._signature_input = None
        self._signature = None
        super().__init__(*args, **kwargs)

    def __contains__(self, key):
        return super(CaseInsensitiveDict, self).__contains__(key.lower())
    def __getitem__(self, key):
        return super(CaseInsensitiveDict, self).__getitem__(key.lower())
    def __setitem__(self, key, value):
        if key.lower() == 'signature-input':
            self._signature_input = value
        elif key.lower() == 'signature':
            self._signature = value
        else:
            assert False
    @property
    def signature_input(self):
        return self._signature_input
    @property
    def signature(self):
        return self._signature


class RequestMessage:
    "Wrapper class to become compatible with http-message-signatures library"
    def __init__(self, request: requests.Request):
        self._request = request
        self._headers = CaseInsensitiveDict({k.lower(): v for k, v in request.headers.items()})

    @property
    def method(self):
        return self._request.method

    @property
    def url(self):
        return self._request.url

    @property
    def headers(self):
        return self._headers


class Signer:
    def __init__(self, prefix, key, signer):
        self._prefix = prefix
        self._key = key
        self._signer = signer

    def sign(self, request, covered):
        message = RequestMessage(request)
        key_id = f'{self._prefix}:{self._key.thumbprint()}'
        nonce = secrets.token_hex(16)
        self._signer.sign(
            message,
            key_id=key_id,
            label=self._prefix,
            covered_component_ids=covered,
            nonce=nonce,
        )
        return message.headers.signature_input, message.headers.signature


def hmac_signer(prefix: str, key: str):
    key = jwk.Symmetric.from_bytes(base64url.decode(key))
    signer = http_message_signatures.HTTPMessageSigner(
        signature_algorithm=http_message_signatures.algorithms.HMAC_SHA256,
        key_resolver=KeyResolver(key.to_bytes())
    )
    return Signer(prefix, key, signer)


def create_algorithm_class(agent: ssh.agent.Client, key: jwk.Public):
    match key.type:
        case jwk.KeyType.ED25519:
            algorithm_id = 'ed25519'
        case _:
            assert False, key.type
    def custom_init(self, *args, **kwargs):
        pass
    def custom_sign(self, message):
        return agent.sign(key.to_ssh_bytes(), message, 0)

    Type = type(
        'CustomSshAgentAlgorithm',
        (http_message_signatures.HTTPSignatureAlgorithm,),
        {
            "__init__": custom_init,
            "sign": custom_sign,
            'algorithm_id': algorithm_id
        }
    )
    return Type


@ssh_commands.ssh_exception
def private_key_signer(prefix: str, filename: str):
    if filename is None:
        raise exceptions.UI('Did you forget to login ?')
    elif os.path.exists(filename):
        with open(filename, 'rb') as f:
            data = f.read()
        try:
            key = jwk.Private.from_data(data, password=None)
        except ValueError:
            raise exceptions.UI('Unable to parse data either as PEM or SSH format')
        if key.type != jwk.KeyType.ED25519:
            raise exceptions.UI(f'Unsupported: {key.type}')
        algorithm = http_message_signatures.algorithms.ED25519
        resolver = KeyResolver(key.to_crypto())
        signer = http_message_signatures.HTTPMessageSigner(
            signature_algorithm=algorithm,
            key_resolver=resolver,
        )
        public_key = key.public()
    else:
        ssh_agent = ssh.agent.Client()
        algorithm = None
        for id in ssh_agent.list_identities():
            public_key = jwk.Public.from_ssh_bytes(id.public_key)
            if id.comment == filename or public_key.match_ssh_fingerprint(filename):
                if public_key.type != jwk.KeyType.ED25519:
                    raise exceptions.UI(f'Unsupported: {key.type}')
                algorithm = create_algorithm_class(ssh_agent, public_key)
                break
        if algorithm is None:
            raise exceptions.UI(f'Unable to find key matching {filename}')
        http_message_signatures._algorithms.signature_algorithms[algorithm.algorithm_id] = algorithm
        resolver = KeyResolver(None)
        signer = http_message_signatures.HTTPMessageSigner(
            signature_algorithm=algorithm,
            key_resolver=resolver,
        )
    return Signer(prefix, public_key, signer), public_key.to_dict()


class RequestsAuth(requests.auth.AuthBase):
    "wrapper class compatible with the requests Auth protocol"

    def __init__(self, signers):
        self._signers = signers

    def __call__(self, request):
        if 'Content-Digest' not in request.headers:
            body = b'' if request.body is None else request.body
            request.headers['Content-Digest'] = str(http_message_signatures.http_sfv.Dictionary({"sha-256": hashlib.sha256(body).digest()}))
        covered =  ("@method", "@authority", "@target-uri", "content-digest")
        signatures_input = []
        signatures = []
        for signer in self._signers:
            signature_input, signature = signer.sign(request, covered)
            signatures_input.append(signature_input)
            signatures.append(signature)

        request.headers['Signature-Input'] = ', '.join(signatures_input)
        request.headers['Signature'] = ', '.join(signatures)
        return request


class HttpClient:
    def __init__(self, client, auth, public_key):
        self._client = client
        self._auth = auth
        self._public_key = public_key
        self._session = requests.Session()

    @property
    def config(self):
        return self._client.config

    @property
    def directory(self):
        return self._client.directory

    @property
    def public_key(self):
        return self._public_key

    def request(self, method, url, data=None, json=None, headers=None, timeout=None, params=None) -> requests.Response:

        request = requests.Request(method=method, url=url, data=data, json=json, headers=headers, auth=self._auth, params=params)
        request = request.prepare()

        logger.info(f'tx {request.method} to {request.url}')
        logger.debug(f'tx headers: {request.headers}')
        logger.debug(f'tx body: {request.body}')
        response = self._session.send(request, timeout=timeout)
        logger.info(f'rx status: {response.status_code}')
        logger.debug(f'rx headers: {response.headers}')
        logger.debug(f'rx body: {response.content}')
        if 'Content-Type' in response.headers and response.headers['Content-Type'] == 'application/json':
            problem = response.json()
            instance = problem.get('instance')
            title = problem.get('title')
            detail = problem.get('detail')
            type = problem.get('type')
            if instance is not None and type is not None:
                logger.warn(f'{title} {detail} {instance}')
            if instance is not None:
                debug = requests.get(instance)
                raise exceptions.UI(str(debug.json()))
        return response

    def post(self, *args, **kwargs) -> requests.Response:
        return self.request('POST', *args, **kwargs)

    def get(self, *args, **kwargs) -> requests.Response:
        return self.request('GET', *args, **kwargs)

    def delete(self, *args, **kwargs) -> requests.Response:
        return self.request('DELETE', *args, **kwargs)

    def put(self, *args, **kwargs) -> requests.Response:
        return self.request('PUT', *args, **kwargs)

    def patch(self, *args, **kwargs) -> requests.Response:
        return self.request('PATCH', *args, **kwargs)


class Client:
    def __init__(self, config):
        self._config = config
        self._directory = None

    @property
    def config(self):
        return self._config

    @property
    def directory(self):
        if self._directory is not None:
            return self._directory
        response = requests.get(self._config.directory_url)
        response.raise_for_status()
        self._directory = types.SimpleNamespace(response.json())
        return self._directory

    @property
    def no_auth(self) -> HttpClient:
        return HttpClient(self, auth=None, public_key=None)

    def invitation_auth(self, account: str, invitation: str) -> HttpClient:
        account_signer, account_public_key = private_key_signer('account', account)
        signers = [hmac_signer('invitation', invitation), account_signer]
        return HttpClient(self, auth=RequestsAuth(signers), public_key=account_public_key)

    def login_auth(self, account: str, session: str) -> HttpClient:
        account_signer, account_public_key = private_key_signer('account', account)
        session_signer, session_public_key = private_key_signer('session', session)
        signers = [account_signer, session_signer]
        return HttpClient(self, auth=RequestsAuth(signers), public_key=session_public_key)

    def session_auth(self, session: str) -> HttpClient:
        signer, public_key = private_key_signer('session', session)
        return HttpClient(self, auth=RequestsAuth([signer]), public_key=public_key)
