from .. import jwk, wa


def enforce_key_is_allowed(key):
    if key.type != jwk.KeyType.ED25519:
        response = wa.ProblemResponse(status_code=403, title="Key type not supported", detail=str(key.type))
        raise wa.HTTPException(response)
