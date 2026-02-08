from . import config
from . import client
from . import exceptions
from .. import jwk


def _auth_function(args):
    c = config.Config.load(args.config)
    idb = client.Client(c)
    auth = idb.session_auth(c.session_key)

    user_key = jwk.Private.generate_ed25519()
    cert_response = auth.post(f'{auth.directory.ssh}/user/certificate', json={
        'public_key': user_key.public().to_dict(),
        'name': args.hostname,
    })
    if cert_response.status_code != 200:
        raise exceptions.UI(cert_response.json()['title'])

    host_ca_response = auth.get(f'{auth.directory.ssh}/host/ca')
    if host_ca_response.status_code != 200:
        raise exceptions.UI(host_ca_response.json()['title'])
    host_krl_response = auth.get(f'{auth.directory.ssh}/host/krl')
    if host_krl_response.status_code != 200:
        raise exceptions.UI(host_krl_response.json()['title'])

    # Write all output
    with open(args.identity_file, 'wb+') as f:
        f.write(user_key.public().to_openssh())
    with open(args.certificate_file, 'wb+') as f:
        f.write(cert_response.content)
    with open(args.known_hosts, 'wb+') as f:
        f.write(host_ca_response.content)
    with open(args.host_krl, 'wb+') as f:
        f.write(host_krl_response.content)


def add_subparsers(parser):
    subparsers = parser.add_subparsers(required=True)


    parser = subparsers.add_parser('auth')
    parser.add_argument('--hostname', help='Name of host we want to connect to')
    parser.add_argument('--known-hosts', help='Known hosts file to generate')
    parser.add_argument('--host-krl', help='KRL file to generate')
    parser.add_argument('--identity-file', help='Public key of the generated key')
    parser.add_argument('--certificate-file', help='Certificate for the generated key')
    parser.set_defaults(func=_auth_function)
