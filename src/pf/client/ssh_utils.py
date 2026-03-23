from .. import jwk, ssh
from . import exceptions


def exception(f):
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except ssh.exceptions.Error as e:
            raise exceptions.UI(str(e))

    return wrapper


def load_public_key(data: bytes) -> jwk.Public:
    try:
        return jwk.Public.from_pem(data)
    except Exception:
        pass
    try:
        return jwk.Public.from_openssh(data)
    except Exception:
        raise exceptions.UI("Unable to load key as either a PEM or an OpenSSH-formatted public key")


def load_private_key(data: bytes, password: bytes | None = None) -> jwk.Private:
    try:
        return jwk.Private.from_pem(data, password)
    except Exception:
        pass
    try:
        return jwk.Private.from_openssh(data)
    except Exception:
        raise exceptions.UI("Unable to load key as either a PEM or an OpenSSH-formatted public key")
