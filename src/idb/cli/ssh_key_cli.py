import sys

from . import ssh_utils
from . import exceptions
from .. import jwk


def _convert_function(args):
    with open(args.filename, 'rb') as f:
        data = f.read()
    try:
        key = ssh_utils.load_public_key(data)
        match args.to:
            case 'openssh':
                output = key.to_openssh()
            case 'pem':
                output = jwk.Public(key.to_crypto()).to_pem()
    except:
        pass
    try:
        key = ssh_utils.load_private_key(data)
    except:
        raise exceptions.UI('Unable to load and convert key as either a public or a private key')
    else:
        output = _format(key, args.to)
    sys.stdout.write(output.decode('utf-8'))


def _format(key, format):
    match format:
        case 'openssh':
            return key.to_openssh()
        case 'pem':
            return key.to_pem()
        case _:
            assert False

def _generate_function(args):
    match args.type:
        case 'ed25519':
            key_type = jwk.KeyType.ED25519
        case 'ecdsa':
            key_type = jwk.KeyType.ECDSA
        case 'ecdsa-256':
            key_type = jwk.KeyType.ECDSA_NISTP256
        case 'ecdsa-384':
            key_type = jwk.KeyType.ECDSA_NISTP384
        case 'ecdsa-521':
            key_type = jwk.KeyType.ECDSA_NISTP521
        case 'rsa':
            key_type = jwk.KeyType.RSA
        case 'rsa-3072':
            key_type = jwk.KeyType.RSA_3072
        case 'rsa-7680':
            key_type = jwk.KeyType.RSA_7680
        case 'rsa-15360':
            key_type = jwk.KeyType.RSA_15360
    key = jwk.Private.generate(key_type)
    output = _format(key, args.format)
    sys.stdout.write(output.decode('utf-8'))


def add_subparsers(parser):
    # commands for debugging and testing
    subparsers = parser.add_subparsers(required=True)

    generate_parser = subparsers.add_parser('generate')
    generate_parser.add_argument('-t', '--type', choices=['ed25519', 'ecdsa', 'ecdsa-256', 'ecdsa-384', 'ecdsa-521', 'rsa', 'rsa-3072', 'rsa-7680', 'rsa-15360'], default='ed25519', help='Type of key to generate. ecdsa=ecdsa-256 and rsa=rsa-3072. Default: %(default)s.')
    generate_parser.add_argument('-f', '--format', choices=['openssh', 'pem'], help='Output format. Default: %(default)s', default='pem')
    generate_parser.set_defaults(func=_generate_function)

    convert_parser = subparsers.add_parser('convert', help='Convert key')
    convert_parser.add_argument('filename')
    convert_parser.add_argument('--to', choices=['openssh', 'pem'], help='Output format. Default: %(default)s', default='openssh')
    convert_parser.set_defaults(func=_convert_function)
