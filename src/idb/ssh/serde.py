import base64

import cryptography.hazmat.primitives.asymmetric.ed25519
import cryptography.hazmat.primitives.asymmetric.ec
import cryptography.hazmat.primitives.serialization

from . import buffer
from .. import jwk


def serialize_public(key: jwk.Public) -> bytes:
    data = key.to_openssh()
    items = data.split(b' ')
    assert len(items) == 2
    return base64.b64decode(items[1])


def deserialize_public(data: bytes) -> jwk.Public:
    # Extract the key type from the ssh buffer
    reader = buffer.Reader(data)
    key_type = reader.read_string()
    openssh = [
        key_type,
        base64.b64encode(data),
        b'username@host',
    ]
    return jwk.Public.from_openssh(b' '.join(openssh))


def serialize_private(key: jwk.Private) -> bytes:
    # The purpose of this method is to generate a binary blob for the private key
    # that is compatible with the ssh-agent protocol. Because this binary blob format
    # is pretty much the one used to store private keys within openssn private key files,
    # one might think that we just need to call to_openssh() above and extract from the
    # base64 output the private key binary blob and return it. Sadly, doing this correctly
    # would require us to know exactly the format of each private key type because
    # the private key blob is not framed.
    # Based on this, I decided to just generate the binary blob manually.
    # Hence, the code below.
    k = key.to_crypto()
    writer = buffer.Writer()
    match k:
        case cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey():
            # https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent#name-eddsa-keys
            writer.write_string(b'ssh-ed25519')
            public_key = k.public_key().public_bytes_raw()
            private_key = k.private_bytes_raw()
            writer.write_string(public_key)
            writer.write_string(private_key + public_key)
            return writer.to_bytes()
        case cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey():
            # https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent#name-rsa-keys
            writer.write_string(b'ssh-rsa')
            private_numbers = k.private_numbers()
            public_numbers = private_numbers.public_numbers
            writer.write_mpint(public_numbers.n)
            writer.write_mpint(public_numbers.e)
            writer.write_mpint(private_numbers.d)
            writer.write_mpint(private_numbers.iqmp)
            writer.write_mpint(private_numbers.p)
            writer.write_mpint(private_numbers.q)
            return writer.to_bytes()
        case cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey():
            # https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent#name-ecdsa-keys
            match k.curve:
                case cryptography.hazmat.primitives.asymmetric.ec.SECP256R1():
                    curve = b'nistp256'
                case cryptography.hazmat.primitives.asymmetric.ec.SECP384R1():
                    curve = b'nistp384'
                case cryptography.hazmat.primitives.asymmetric.ec.SECP521R1():
                    curve = b'nistp521'
            writer.write_string(b'ecdsa-sha2-' + curve)
            writer.write_string(curve)
            q = k.public_key().public_bytes(
                encoding= cryptography.hazmat.primitives.serialization.Encoding.X962,
                format=cryptography.hazmat.primitives.serialization.PublicFormat.UncompressedPoint,
            )
            d = k.private_numbers().private_value
            writer.write_string(q)
            writer.write_mpint(d)
            return writer.to_bytes()
        case _:
            assert False
