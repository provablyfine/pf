import urllib.parse
import hashlib
import datetime
import functools
import time

from . import wa
from . import jwk
from .context import ctx

import http_message_signatures


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


def _parse_signature_input(signature_input):
    d = http_message_signatures.http_sfv.Dictionary()
    try:
        d.parse(signature_input.encode())
    except Exception as e:
        raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='Invalid Signature-Input header', detail=str(e)))
    keyid_by_label = {}
    for label, v in d.items():
        if 'keyid' not in v.params:
            raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='Invalid Signature-Input', detail=f'Missing keyid in {label}'))
        keyid_by_label[label] = (v.params['keyid'], d[label])
    return keyid_by_label


def _parse_signature(signature):
    d = http_message_signatures.http_sfv.Dictionary()
    try:
        d.parse(signature.encode())
    except Exception as e:
        raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='Invalid Signature header', detail=str(e)))
    signature_by_label = {}
    for label, v in d.items():
        signature_by_label[label] = v
    return signature_by_label


def verify(request: wa.Request, key_id: str, key):
    content_digest = str(http_message_signatures.http_sfv.Dictionary({"sha-256": hashlib.sha256(request.body).digest()}))
    if request.headers['Content-Digest'] != content_digest:
        raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='Content hash does not match Content-Digest header'))

    if 'Signature' not in request.headers:
        raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='Missing Signature header'))
    if 'Signature-Input' not in request.headers:
        raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='Missing Signature-Input header'))

    
    keyid_by_label = _parse_signature_input(request.headers['Signature-Input'])
    signature_by_label = _parse_signature(request.headers['Signature'])

    label_by_keyid = {keyid: (label, signature_input) for label, (keyid, signature_input) in keyid_by_label.items()}
    if key_id not in label_by_keyid:
        raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='Unable to find keyid in Signature-Input', detail=key_id))
    label, signature_input = label_by_keyid[key_id]
    if label not in signature_by_label:
        raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='Unable to find label in Signature', detail=label))
    signature = signature_by_label[label]
    message = RequestMessage(request, label, signature, signature_input)

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
            raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='Unsupported key type', detail=key_id))

    verifier = http_message_signatures.HTTPMessageVerifier(
        signature_algorithm=algorithm,
        key_resolver=resolver,
    )

    try:
        verified = verifier.verify(message, max_age=datetime.timedelta(hours=5))#minutes=5))
    except http_message_signatures.InvalidSignature as e:
        raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='Invalid signature', detail=f'{label}: {e}'))
    covered = set(c.strip('"') for c in verified[0].covered_components.keys())
    expected = set(["@authority", "@method", "@target-uri", "@signature-params", "content-digest"])
    if covered != expected:
        raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='Signature does not cover the expected fields', detail=f'Got: {covered}. Expected: {expected}'))


def _get_keyid(request: wa.Request, prefix: str) -> str:
    if 'Signature-Input' not in request.headers:
        raise wa.HTTPException(wa.ProblemResponse(status_code=403, title='Missing Signature-Input header'))
    keyid_by_label = _parse_signature_input(request.headers['Signature-Input'])
    for label, (keyid, signature_input) in keyid_by_label.items():
        if not keyid.startswith(f'{prefix}:'):
            continue
        return keyid[len(f'{prefix}:'):]
    raise wa.HTTPException(wa.ProblemResponse(status_code=403, title='Missing signature for prefix', detail=prefix))


def verify_invitation(f):
    @functools.wraps(f)
    def wrapper(request, *args, **kwargs):
        key_id = _get_keyid(request, 'invitation')
        invitation = ctx.db.identity_invitation_key.read_one(id=key_id)
        if invitation.is_revoked:
            return wa.ProblemResponse(status_code=403, title='Invitation is revoked')
        now = int(time.time())
        if invitation.expires_at <= now:
            return wa.ProblemResponse(status_code=403, title='Invitation is expired')
        key = jwk.Symmetric.from_dict(invitation.key)
        assert key.thumbprint() == key_id
        verify(request, key_id=f'invitation:{key_id}', key=key)
        request.state.invitation = invitation
        with ctx.set_identity_id(invitation.identity_id):
            return f(request, *args, **kwargs)
    return wrapper


def verify_identity(f):
    @functools.wraps(f)
    def wrapper(request, *args, **kwargs):
        key_id = _get_keyid(request, 'identity')
        account_key = ctx.db.identity_account_key.read_one(id=key_id)
        if account_key.is_revoked:
            return wa.ProblemResponse(status_code=403, title='Account key is revoked')
        key = jwk.Public.from_dict(account_key.public_key)
        assert key.thumbprint() == key_id
        verify(request, key_id=f'identity:{key_id}', key=key)
        request.state.account_key = account_key
        with ctx.set_identity_id(account_key.identity_id):
            return f(request, *args, **kwargs)
    return wrapper


def verify_session(f):
    @functools.wraps(f)
    def wrapper(request, *args, **kwargs):
        key_id = _get_keyid(request, 'session')
        session_key = request.state.dao.session_key.read_one(id=key_id)
        if session_key.is_revoked:
            return wa.ProblemResponse(status_code=403, title='Session key is revoked')
        now = int(time.time())
        if session_key.expires_at <= now:
            return wa.ProblemResponse(status_code=403, title='Session key is expired')
        key = jwk.Public.from_dict(session_key.public_key)
        assert key.thumbprint() == key_id
        verify(request, key_id=f'session:{key_id}', key=key)
        request.state.session_key = session_key
        with ctx.set_identity_id(session_key.identity_id):
            return f(request, *args, **kwargs)
    return wrapper
