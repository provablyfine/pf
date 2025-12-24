import contextlib
import types
import json
import datetime
import urllib.parse
import hashlib

import sqlalchemy
import cryptography.fernet
import http_message_signatures

from . import wa
from . import config
from . import db
from . import decorators
from . import openapi
from . import model
from . import base64url
from . import jwk



def idb_directory(request):
    return wa.JSONResponse(status_code=200, json={
        'initialize': f'{request.app.config.base_url}/idb/initialize',
        'accept-invitation': f'{request.app.config.base_url}/idb/accept-invitation',
    })



@decorators.transaction
def idb_initialize(request):
    one = request.state.dao.identity.read_one()
    if one is not None:
        return wa.Response(
            status_code=204
        )
    root_boundary = model.Boundary.create(name='Root Boundary', description='The Root boundary is not a boundary at all.')
    restricted_boundary = model.Boundary.create(name='Restricted Boundary', description='The Restricted boundary does not allow anything')
    for deny in ['identity:*', 'role:*', 'group:*', 'tag:*', 'boundary:*']:
        restricted_boundary.add_deny(deny)
    root = model.Identity.create(name='root', boundary_id=root_boundary.id)
    root_role = model.Role.create(name='root', description='The "root" role identifies a user that is able to do anything. It is created once at startup and should be deleted once a proper permission model is deployed.')
    root_role.add_permission('*:*')
    ii = model.IdentityInvitation.create(identity_id=root.id, expiration_delay_s=600)

    request.state.dao.boundary.create(id=root_boundary.id, boundary=root_boundary.serialize())
    request.state.dao.boundary.create(id=restricted_boundary.id, boundary=restricted_boundary.serialize())
    request.state.dao.default.create(boundary_id=restricted_boundary.id)
    request.state.dao.identity.create(id=root.id, identity=root.serialize())
    request.state.dao.role.create(id=root_role.id, role=root_role.serialize())
    request.state.dao.role_identity_grant.create(role_id=root_role.id, identity_id=root.id)
    request.state.dao.identity_invitation.create(id=ii.id, identity_invitation=ii.serialize(request.app.state.kek))
    
    for o in [root_boundary, restricted_boundary, root, root_role, ii]:
        for log in o.audit_log:
            request.state.dao.audit_log.create(log=log.serialize(None))
    return wa.JSONResponse(
        json=ii.format(),
        status_code=200
    )


class CaseInsensitiveDict(dict):
    def __contains__(self, key):
        return super(CaseInsensitiveDict, self).__contains__(key.lower())
    def __getitem__(self, key):
        return super(CaseInsensitiveDict, self).__getitem__(key.lower())


class RequestMessage:
    "Wrapper class to become compatible with http-message-signatures library"
    def __init__(self, request: wa.Request, label: str, signature: str, signature_input: str):
        self._request = request
        def _wrap(k, v):
            match k:
                case 'signature':
                    return f'{label}={signature}'
                case 'signature-input':
                    return f'{label}={signature_input}'
                case _:
                    return v
        self._headers = {k.lower(): _wrap(k.lower(), v) for k, v in request.headers.items()}

    @property
    def method(self):
        return self._request.method

    @property
    def url(self):
        return urllib.parse.urlunparse(self._request.url)

    @property
    def headers(self):
        return CaseInsensitiveDict(self._headers)


class KeyResolver:
    def __init__(self, private_key, public_key):
        self._private_key = private_key
        self._public_key = public_key

    def resolve_public_key(self, key_id: str):
        return self._public_key

    def resolve_private_key(self, key_id: str):
        return self._private_key


def verify_signatures(request: wa.Request, expected_keys):
    def _parse_signature_input(signature_input):
        keyid_by_label = {}
        for item in signature_input.split(','):
            item = item.strip()

            equal = item.find('=')
            if equal == -1:
                raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='Invalid Signature-Input: no label'))
            label = item[:equal]

            members = item.split(';')
            for i, member in enumerate(members):
                kv = member.split('=')
                if len(kv) != 2:
                    raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='Invalid Signature-Input'))
                if kv[0] == 'keyid':
                    keyid_by_label[label] = (kv[1], item[equal+1:])
        return keyid_by_label

    def _parse_signature(signature):
        signature_by_label = {}
        for item in signature.split(','):
            item = item.strip()

            equal = item.find('=')
            if equal == -1:
                raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='Invalid Signature-Input: no label'))
            label = item[:equal]
            signature_by_label[label] = item[equal+1:]
        return signature_by_label

    content_digest = str(http_message_signatures.http_sfv.Dictionary({"sha-256": hashlib.sha256(request.body).digest()}))
    if request.headers['Content-Digest'] != content_digest:
        raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='Content hash does not match Content-Digest header'))
    if 'Signature' not in request.headers:
        raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='Missing Signature header'))
    if 'Signature-Input' not in request.headers:
        raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='Missing Signature-Input header'))

    keyid_by_label = _parse_signature_input(request.headers['Signature-Input'])
    signature_by_label = _parse_signature(request.headers['Signature'])
    if set(keyid_by_label) != set(signature_by_label):
        raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='Signature and Signature-Input are not coherent'))
    n_got_signatures = len(set(keyid_by_label.values()))
    if n_got_signatures != len(expected_keys):
        raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='Number of signatures does not match number of expected signatures', detail=f'Got: {n_got_signatures} Expected: {len(expected_keys)}'))

    key_by_keyid = {key.thumbprint(): key for key in expected_keys}

    for label, signature in signature_by_label.items():

        keyid, signature_input = keyid_by_label[label]
        if keyid not in key_by_keyid:
            raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='No key matches keyid', detail=keyid))

        key = key_by_keyid[keyid]
        match key.type:
            case jwk.KeyType.SYMMETRIC:
                algorithm = http_message_signatures.algorithms.HMAC_SHA256
                resolver = KeyResolver(private_key=key.to_bytes(), public_key=key.to_bytes())
            case jwk.KeyType.ED25519:
                algorithm = http_message_signatures.algorithms.ED25519
                resolver = KeyResolver(private_key=None, public_key=key.to_crypto())
            case jwk.KeyType.EC:
                algorithm = http_message_signatures.algorithms.ECDSA_P256_SHA256
                resolver = KeyResolver(private_key=None, public_key=key.to_crypto())
            case _:
                raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='Unsupported key type', detail=keyid))
        verifier = http_message_signatures.HTTPMessageVerifier(
            signature_algorithm=algorithm,
            key_resolver=resolver,
        )

        message = RequestMessage(request, label, signature, signature_input)
        try:
            verified = verifier.verify(message, max_age=datetime.timedelta(hours=5))#minutes=5))
        except http_message_signatures.InvalidSignature as e:
            raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='Invalid signature', detail=f'{label}: {e}'))
        covered = set(c.strip('"') for c in verified[0].covered_components.keys())
        expected = set(["@authority", "@method", "@target-uri", "@signature-params", "content-digest"])
        if covered != expected:
            raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='Signature does not cover the expected fields', detail=f'Got: {covered}. Expected: {expected}'))


@decorators.transaction
def idb_accept_invitation(request) -> wa.Response:
    data = json.loads(request.body)
    invitation = model.IdentityInvitation.from_id(request.state.dao, data['key_id'], request.app.state.kek)
    if invitation is None:
        return wa.ProblemResponse(status_code=400, title=f'Invitation does not exist', detail=data['key_id'])
    if invitation.is_accepted:
        return wa.ProblemResponse(status_code=400, title=f'Invitation was already accepted. Get a new one.')
    if invitation.is_expired:
        return wa.ProblemResponse(status_code=400, title=f'Invitation is expired. Get a new one.')

    expected_keys = [
        jwk.Symmetric.from_bytes(invitation.key),
        jwk.Public.from_dict(data['account_public_key']),
    ]
    verify_signatures(request, expected_keys)

#    invitation.accept()
#    request.state.dao.identity_invitation.update(identity_invitation=invitation.serialize(request.app.state.kek)).where(id=invitation.id)
#    request.state.dao.identity_key.create(
#        
#    )
    print(data)
    #print(list(request.headers.items()))
    #pass
    return wa.Response(
        status_code=204
    )


@contextlib.contextmanager
def lifespan(config: config.Config, state: types.SimpleNamespace):
    engine = sqlalchemy.create_engine(config.database_url, echo=config.debug_sql)
    with open(config.kek_filename, 'rb') as f:
        kek = base64url.encode(f.read()) + '======'
        kek = cryptography.fernet.Fernet(kek)
    state.db_engine = engine
    state.kek = kek
    yield


def create(filename):
    conf = config.Config.load(filename)
    db.create_tables(conf.database_url)
    middlewares = [
        wa.debug_store.DebugStoreMiddleware(wa.debug_store.InMemoryDebugStore()),
#        wa.backtrace.BacktraceMiddleware(),
        openapi.create_middleware(conf.base_url),
    ]
    app = wa.Application(config=conf, middlewares=middlewares, lifespan=lifespan, debug=conf.debug)
    app.add('/idb/directory', idb_directory, methods=['GET'])
    app.add('/idb/initialize', idb_initialize, methods=['POST'])
    app.add('/idb/accept-invitation', idb_accept_invitation, methods=['POST'])
    return app
