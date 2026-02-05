from .. import ssh
from .. import jwk
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
    except:
        pass
    try:
        return jwk.Public.from_openssh(data)
    except:
        raise exceptions.UI('Unable to load key as either a PEM or an OpenSSH-formatted public key')


def load_private_key(data: bytes, password: str=None) -> jwk.Private:
    try:
        return jwk.Private.from_pem(data, password)
    except:
        pass
    try:
        return jwk.Private.from_openssh(data)
    except:
        raise exceptions.UI('Unable to load key as either a PEM or an OpenSSH-formatted public key')
