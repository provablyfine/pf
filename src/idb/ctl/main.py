import argparse
import sys
import traceback
import os
import os.path
import logging
import secrets
import hashlib

import requests
import requests.auth
import http_message_signatures
import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.primitives.asymmetric.ed25519
import cryptography.hazmat.primitives.asymmetric.ec

from . import exceptions
from . import admin
from . import ssh
from . import config
from .. import base64url
from .. import jwk


logger = logging.getLogger(__name__)

def _config_function(args):
    response = requests.get(args.directory)
    response.raise_for_status()
    c = config.Config(
        directory_url=args.directory,
        root_key_id=args.root_key_id,
        ignore_ssh_agent=args.ignore_ssh_agent,
        directory=response.json()
    )
    c.save(args.config)


class KeyResolver:
    def __init__(self, private_key):
        self._private_key = private_key

    def resolve_public_key(self, key_id: str):
        raise NotImplementedError("This method must be implemented by a subclass.")

    def resolve_private_key(self, key_id: str):
        return self._private_key


class Auth(requests.auth.AuthBase):
    def __init__(self, private_key_filename, invitation_key):
        self._invitation_key = invitation_key

        if os.path.exists(private_key_filename):
            with open(private_key_filename, 'rb') as f:
                data = f.read()
                private_key = jwk.Private.from_pem(data, password=None)
                match private_key.type:
                    case jwk.KeyType.ED25519:
                        self._private_key_algorithm = http_message_signatures.algorithms.ED25519
                    case jwk.KeyType.EC:
                        self._private_key_algorithm = http_message_signatures.algorithms.ECDSA_P256_SHA256
                    case _:
                        assert False
                self._private_key = private_key
                self._private_key_resolver = KeyResolver(private_key.to_crypto())
        else:
            # Try to connect to ssh-agent
            assert False

    def public_jwk(self):
        return self._private_key.public().to_dict()

    def __call__(self, request):
        if 'Content-Digest' not in request.headers:
            request.headers['Content-Digest'] = str(http_message_signatures.http_sfv.Dictionary({"sha-256": hashlib.sha256(request.body).digest()}))
        covered =  ("@method", "@authority", "@target-uri", "content-digest")

        private_signer = http_message_signatures.HTTPMessageSigner(
            signature_algorithm=self._private_key_algorithm,
            key_resolver=self._private_key_resolver,
        )
        account_key_id = f'account:{self._private_key.thumbprint()}'
        private_signer.sign(
            request,
            key_id=account_key_id,
            label="account",
            covered_component_ids=covered
        )

        first_signature_input = request.headers['Signature-Input']
        first_signature = request.headers['Signature']

        hmac_signer = http_message_signatures.HTTPMessageSigner(
            signature_algorithm=http_message_signatures.algorithms.HMAC_SHA256,
            key_resolver=KeyResolver(self._invitation_key.to_bytes())
        )
        invitation_key_id = f'invitation:{self._invitation_key.thumbprint()}'
        hmac_signer.sign(
            request,
            key_id=invitation_key_id,
            label="invitation",
            covered_component_ids=covered
        )

        second_signature_input = request.headers['Signature-Input']
        second_signature = request.headers['Signature']

        request.headers['Signature-Input'] = f'{first_signature_input}, {second_signature_input}'
        request.headers['Signature'] = f'{first_signature}, {second_signature}'
        return request


def _accept_invitation_function(args):
    c = config.Config.load(args.config)
    invitation_key = jwk.Symmetric.from_bytes(base64url.decode(args.invitation))
    nonce = secrets.token_hex(16)
    auth = Auth(
        private_key_filename=args.key,
        invitation_key=invitation_key,
    )
    request = requests.Request(method='POST', url=c.directory['accept-invitation'], json={
        'account_public_key': auth.public_jwk(),
        'nonce': nonce,
    }, auth=auth)
    request = request.prepare()
    session = requests.Session()
    logger.info(f'tx {request.method} to {request.url}')
    logger.debug(f'tx headers: {request.headers}')
    logger.debug(f'tx body: {request.body}')
    response = session.send(request)
    logger.info(f'rx {response.status_code}')
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


def _login_function(args):
    c = config.Config.load(args.config)


def _ping_function(args):
    pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', help='Increase debugging level', action='count', default=0)
    parser.add_argument('-c', '--config', help='configuration file', default=os.path.abspath(os.path.join(os.getcwd(), 'config.json')))
    subparsers = parser.add_subparsers(required=True)

    config_parser = subparsers.add_parser('config', help='Create a configuration file')
    parser.add_argument('--directory', default='http://127.0.0.1:8000/idb/directory', help='Directory to connect to')
    parser.add_argument('--root-key-id', help='Key id of the public key of the root certificate.', default=None)
    parser.add_argument('--ignore-ssh-agent', action='store_true', help='Read and write keys from/to disk, regardless of whether or not there is an SSH agent')
    config_parser.set_defaults(func=_config_function)

    register_parser = subparsers.add_parser('accept-invitation', help='Accept an invitation')
    register_parser.add_argument('--key', help='Private key to register', default='account.key')
    register_parser.add_argument('--invitation', help='Invitation you were given')
    register_parser.set_defaults(func=_accept_invitation_function)

    login_parser = subparsers.add_parser('login', help='Login')
    login_parser.add_argument('--key', help='Key to login with', default='account.key')
    login_parser.add_argument('-o', '--output', help='Temporary key to associate with account', default='session.key')
    login_parser.set_defaults(func=_login_function)

    ping_parser = subparsers.add_parser('ping', help='Ping IDB')
    ping_parser.add_argument('--session-key', help='key to use to sign requests to the remote', default='session.key')
    ping_parser.set_defaults(func=_ping_function)

    admin_parser = subparsers.add_parser('admin', help='Admin-related functions')
    admin.add_subparsers(admin_parser)

    ssh_parser = subparsers.add_parser('ssh', help='SSH-related functions')
    ssh.add_subparsers(ssh_parser)

    args = parser.parse_args()

    if args.debug > 0:
        match args.debug:
            case 3:
                level = logging.DEBUG
            case 2:
                level = logging.INFO
            case 1:
                level = logging.WARN
        logging.basicConfig(stream=sys.stdout, level=level)


    try:
        args.func(args)
        exitcode = 0
    except exceptions.UI as e:
        print(e)
        exitcode = 2
    except:
        traceback.print_exc()
        exitcode = 1

    sys.exit(exitcode)
