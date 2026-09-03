from .. import jwk
from . import responses


def enforce_key_is_allowed(key: jwk.Public) -> None:
    if key.type != jwk.KeyType.ED25519:
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=403, title="Key type not supported", detail=str(key.type))
        )
