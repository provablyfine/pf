import base64

import cryptography.hazmat.primitives.asymmetric.ec
import cryptography.hazmat.primitives.asymmetric.ed25519
import cryptography.hazmat.primitives.asymmetric.rsa
import cryptography.hazmat.primitives.serialization

from .. import jwk
from . import buffer, cert


def _split_on_space(data: bytes) -> list[bytes]:
    # split(b" ") vs split(None) are equivalent here: callers only ever pass
    # cryptography's own public_bytes()/SSHCertificate.public_bytes() output,
    # which always emits exactly one ASCII space between fields, never other
    # whitespace or runs of it.
    return data.split(b" ")  # pragma: no mutate


def serialize_cert(cert: cert.Cert) -> bytes:
    data = cert.to_openssh()
    items = _split_on_space(data)
    assert len(items) >= 2
    return base64.b64decode(items[1])


def deserialize_cert(data: bytes) -> cert.Cert:
    reader = buffer.Reader(data)
    key_type = reader.read_string()
    openssh = [
        key_type,
        base64.b64encode(data),
    ]
    return cert.Cert.from_openssh(b" ".join(openssh))


def serialize_public(key: jwk.Public) -> bytes:
    data = key.to_openssh()
    items = _split_on_space(data)
    assert len(items) == 2
    return base64.b64decode(items[1])


def deserialize_public(data: bytes) -> jwk.Public:
    # Extract the key type from the ssh buffer
    reader = buffer.Reader(data)
    key_type = reader.read_string()
    # The comment is required by the OpenSSH public-key text format but its
    # content is never read back by anything — any placeholder value works.
    comment = b"username@host"  # pragma: no mutate
    openssh = [
        key_type,
        base64.b64encode(data),
        comment,
    ]
    return jwk.Public.from_openssh(b" ".join(openssh))


def _ec_curve_name(curve: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurve) -> bytes:
    # if/elif, not match/case: mutmut has no pragma support for MatchCase nodes,
    # so an unreachable "case _: assert False" branch there can't be excluded.
    if isinstance(curve, cryptography.hazmat.primitives.asymmetric.ec.SECP256R1):
        return b"nistp256"
    elif isinstance(curve, cryptography.hazmat.primitives.asymmetric.ec.SECP384R1):
        return b"nistp384"
    elif isinstance(curve, cryptography.hazmat.primitives.asymmetric.ec.SECP521R1):
        return b"nistp521"
    else:
        assert False  # pragma: no mutate — unreachable, only NIST P-256/384/521 keys are ever generated


def serialize_private_certificate(key: jwk.Private, cert: cert.Cert) -> bytes:
    k = key.to_crypto()
    writer = buffer.Writer()
    # if/elif, not match/case: mutmut has no pragma support for MatchCase nodes,
    # so an unreachable "case _: assert False" branch there can't be excluded.
    if isinstance(k, cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey):
        writer.write_string(b"ssh-ed25519-cert-v01@openssh.com")
        writer.write_string(serialize_cert(cert))
        public_key = k.public_key().public_bytes_raw()
        private_key = k.private_bytes_raw()
        writer.write_string(public_key)
        writer.write_string(private_key + public_key)
        return writer.to_bytes()
    elif isinstance(k, cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey):
        writer.write_string(b"ssh-rsa-cert-v01@openssh.com")
        writer.write_string(serialize_cert(cert))
        private_numbers = k.private_numbers()
        writer.write_mpint(private_numbers.d)
        writer.write_mpint(private_numbers.iqmp)
        writer.write_mpint(private_numbers.p)
        writer.write_mpint(private_numbers.q)
        return writer.to_bytes()
    else:
        assert isinstance(k, cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey)  # pragma: no mutate
        curve = _ec_curve_name(k.curve)
        writer.write_string(b"ecdsa-sha2-" + curve + b"-cert-v01@openssh.com")
        writer.write_string(serialize_cert(cert))
        d = k.private_numbers().private_value
        writer.write_mpint(d)
        return writer.to_bytes()


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
    # if/elif, not match/case: mutmut has no pragma support for MatchCase nodes,
    # so an unreachable "case _: assert False" branch there can't be excluded.
    if isinstance(k, cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey):
        # https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent#name-eddsa-keys
        writer.write_string(b"ssh-ed25519")
        public_key = k.public_key().public_bytes_raw()
        private_key = k.private_bytes_raw()
        writer.write_string(public_key)
        writer.write_string(private_key + public_key)
        return writer.to_bytes()
    elif isinstance(k, cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey):
        # https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent#name-rsa-keys
        writer.write_string(b"ssh-rsa")
        private_numbers = k.private_numbers()
        public_numbers = private_numbers.public_numbers
        writer.write_mpint(public_numbers.n)
        writer.write_mpint(public_numbers.e)
        writer.write_mpint(private_numbers.d)
        writer.write_mpint(private_numbers.iqmp)
        writer.write_mpint(private_numbers.p)
        writer.write_mpint(private_numbers.q)
        return writer.to_bytes()
    else:
        assert isinstance(k, cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey)  # pragma: no mutate
        # https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent#name-ecdsa-keys
        curve = _ec_curve_name(k.curve)
        writer.write_string(b"ecdsa-sha2-" + curve)
        writer.write_string(curve)
        q = k.public_key().public_bytes(
            encoding=cryptography.hazmat.primitives.serialization.Encoding.X962,
            format=cryptography.hazmat.primitives.serialization.PublicFormat.UncompressedPoint,
        )
        d = k.private_numbers().private_value
        writer.write_string(q)
        writer.write_mpint(d)
        return writer.to_bytes()
