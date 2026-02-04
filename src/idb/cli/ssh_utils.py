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


def load_public_key(data: bytes) -> ssh.key.Public:
    try:
        key = jwk.Public.from_pem(data)
        return ssh.key.Public(key.to_crypto())
    except:
        return ssh.key.Public.from_openssh_file(data)


def load_private_key(data: bytes, password: str=None) -> ssh.key.Private:
    try:
        key = jwk.Private.from_pem(data, password)
        return ssh.key.Private(key.to_crypto())
    except:
        return ssh.key.Private.from_openssh_file(data)
