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
        match args.to:
            case 'openssh':
                output = key.to_openssh()
            case 'pem':
                output = jwk.Private(key.to_crypto()).to_pem()
    sys.stdout.write(output.decode('utf-8'))


def add_subparsers(parser):
    subparsers = parser.add_subparsers(required=True)

    convert_parser = subparsers.add_parser('convert', help='Convert key')
    convert_parser.add_argument('filename')
    convert_parser.add_argument('--to', choices=['openssh', 'pem'], help='Output format. Default: %(default)s', default='openssh')
    convert_parser.set_defaults(func=_convert_function)
