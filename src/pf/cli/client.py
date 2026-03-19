import hashlib
import logging
import os.path
import secrets
import types

import http_message_signatures
import requests

from .. import base64url, jwk, ssh
from . import exceptions, ssh_utils

# Because we import stuff from http_message_signatures
# that is not explicitely exported.
# No good idea to fix this short of re-implementing our own
# pyright: reportPrivateImportUsage=false
# pyright: reportAttributeAccessIssue=false

logger = logging.getLogger(__name__)


class KeyResolver(http_message_signatures.HTTPSignatureKeyResolver):
    def __init__(self, private_key):
        self._private_key = private_key

    def resolve_public_key(self, key_id: str):
        raise NotImplementedError("This method must be implemented by a subclass.")

    def resolve_private_key(self, key_id: str):
        return self._private_key


class RequestMessage:
    "Wrapper class to become compatible with http-message-signatures library"
    def __init__(self, request: requests.Request):
        self._request = request
        self._headers = http_message_signatures.structures.CaseInsensitiveDict({k.lower(): v for k, v in request.headers.items()})

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
        return message.headers['Signature-Input'], message.headers['Signature']


def hmac_signer(prefix: str, key: str):
    signing_key = jwk.Symmetric.from_bytes(base64url.decode(key))
    signer = http_message_signatures.HTTPMessageSigner(
        signature_algorithm=http_message_signatures.algorithms.HMAC_SHA256,
        key_resolver=KeyResolver(signing_key.to_bytes())
    )
    return Signer(prefix, signing_key, signer)


def create_algorithm_class(agent: ssh.agent.Client, key: jwk.Public):
    match key.type:
        case jwk.KeyType.ED25519:
            algorithm_id = 'ed25519'
        case _:
            assert False, key.type
    def _search_identity():
        for identity in agent.list_identities():
            if identity.public_key.thumbprint() == key.thumbprint():
                return identity
        raise exceptions.UI('Unable to find key {key.ssh_fingerprint()}')
                
    def custom_init(self, *args, **kwargs):
        pass
    def custom_sign(self, message):
        identity = _search_identity()
        return agent.sign(identity, message, 0)

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


@ssh_utils.exception
def private_key_signer(prefix: str, filename: str|None):
    if filename is None:
        raise exceptions.UI('Did you forget to login ?')
    elif os.path.exists(filename):
        with open(filename, 'rb') as f:
            data = f.read()
        try:
            key = ssh_utils.load_private_key(data, password=None)
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
        public_key = None
        for id in ssh_agent.list_identities():
            if id.comment == filename or id.public_key.match_ssh_fingerprint(filename):
                if id.public_key.type != jwk.KeyType.ED25519:
                    raise exceptions.UI(f'Unsupported: {id.public_key.type}')
                algorithm = create_algorithm_class(ssh_agent, id.public_key)
                public_key = id.public_key
                break
        if algorithm is None:
            raise exceptions.UI(f'Unable to find key matching {filename}')
        assert public_key is not None
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
        try:
            response = self._session.send(request, timeout=1)
        except requests.exceptions.ConnectionError:
            raise exceptions.UI('Unable to connect to server. #3')
        except requests.exceptions.ReadTimeout:
            raise exceptions.UI('Unable to connect to server. #4')
        logger.info(f'rx status: {response.status_code}')
        logger.debug(f'rx headers: {response.headers}')
        logger.debug(f'rx body: {response.content}')
        if response.status_code == 400:
            problem = response.json()
            title = problem.get('title')
            detail = problem.get('detail')
            if detail is not None:
                raise exceptions.UI(f'{title} {detail}')
            else:
                raise exceptions.UI(f'{title}')
            
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
                if 'backtrace' in debug.json():
                    raise exceptions.UI(debug.json()['backtrace'])
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
        try:
            response = requests.get(self._config.directory_url, timeout=0.5)
        except requests.exceptions.ConnectionError:
            raise exceptions.UI('Unable to connect to server. #1')
        except requests.exceptions.ReadTimeout:
            raise exceptions.UI('Unable to connect to server #2')
        if response.status_code != 200:
            raise exceptions.UI('Unable to read directory from server')
        self._directory = types.SimpleNamespace(response.json())
        return self._directory

    @property
    def no_auth(self) -> HttpClient:
        return HttpClient(self, auth=None, public_key=None)

    def invitation_auth(self, account: str|None, invitation: str) -> HttpClient:
        account_signer, account_public_key = private_key_signer('account', account)
        signers = [hmac_signer('invitation', invitation), account_signer]
        return HttpClient(self, auth=RequestsAuth(signers), public_key=account_public_key)

    def login_auth(self, account: str|None, session: str|None) -> HttpClient:
        account_signer, account_public_key = private_key_signer('account', account)
        session_signer, session_public_key = private_key_signer('session', session)
        signers = [account_signer, session_signer]
        return HttpClient(self, auth=RequestsAuth(signers), public_key=session_public_key)

    def session_auth(self, session: str|None) -> HttpClient:
        signer, public_key = private_key_signer('session', session)
        return HttpClient(self, auth=RequestsAuth([signer]), public_key=public_key)
