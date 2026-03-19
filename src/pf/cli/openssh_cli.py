import base64
import os
import time

from .. import jwk, ssh
from . import client, config, exceptions, ssh_utils


def _refresh_known_hosts(auth, known_hosts):
    known_hosts = os.path.abspath(os.path.expanduser(known_hosts))
    now = int(time.time())
    try:
        st = os.stat(known_hosts)
        if st.st_mtime + 60 > now:
            # We do not refresh known hosts more often than once every 60s
            return
    except FileNotFoundError:
        pass
    host_trusted_keys_response = auth.get(f'{auth.directory.ssh}/host/trusted-keys')
    if host_trusted_keys_response.status_code != 200:
        raise exceptions.UI(host_trusted_keys_response.json()['title'])
    with open(known_hosts, 'wb+') as f:
        for line in host_trusted_keys_response.content.split(b'\n'):
            f.write(line)


@ssh_utils.exception
def _auth_function(args):
    c = config.Config.load(args.config)
    api = client.Client(c)
    auth = api.session_auth(c.session_key)

    user_key = jwk.Private.generate_ed25519()
    cert_response = auth.post(f'{auth.directory.ssh}/user/certificate', json={
        'public_key': user_key.public().to_dict(),
        'hostname': args.host,
        'username': args.user
    })
    if cert_response.status_code != 200:
        raise exceptions.UI(cert_response.json()['title'])

    try:
        ssh_agent = ssh.agent.Client()
    except:
        raise exceptions.UI("Unable to connect to user's SSH agent")

    for certificate in cert_response.json()['certificates']:
        cert = ssh.cert.Cert.from_openssh(base64.b64decode(certificate))
        ssh_agent.add(user_key, cert=cert, comment=args.host, lifetime=60)

    #host_krl_response = auth.get(f'{auth.directory.ssh}/host/krl')
    #if host_krl_response.status_code != 200:
    #    raise exceptions.UI(host_krl_response.json()['title'])

    
    #with open(args.identity_file, 'wb+') as f:
    #    f.write(user_key.public().to_openssh())
    #with open(args.certificate_file, 'wb+') as f:
    #    f.write(cert_response.content)
    _refresh_known_hosts(auth, args.known_hosts)
    #with open(args.host_krl, 'wb+') as f:
    #    f.write(host_krl_response.content)


def _known_hosts_function(args):
    c = config.Config.load(args.config)
    api = client.Client(c)
    auth = api.session_auth(c.session_key)
    
    host_trusted_keys_response = auth.get(f'{auth.directory.ssh}/host/trusted-keys')
    if host_trusted_keys_response.status_code != 200:
        raise exceptions.UI(host_trusted_keys_response.json()['title'])
    for line in host_trusted_keys_response.text.split('\n'):
        print(line)



def _user_trusted_keys_function(args):
    c = config.Config.load(args.config)
    api = client.Client(c)
    response = api.no_auth.get(f'{api.directory.ssh}/user/trusted-keys')
    if response.status_code != 200:
        raise exceptions.UI(response.json()['title'])
    print(response.text)


def _sign_host_function(args):
    c = config.Config.load(args.config)
    api = client.Client(c)
    auth = api.session_auth(c.session_key)

    public_keys = []
    filename_from_fingerprint = {}
    for filename in args.public_key:
        with open(filename, 'rb') as f:
            key = f.read()
            public_key = jwk.Public.from_openssh(key)
            public_keys.append(public_key.to_dict())
            filename_from_fingerprint[public_key.ssh_fingerprint()] = filename

    cert_response = auth.post(f'{auth.directory.ssh}/host/certificate', json={
        'public_keys': public_keys
    })
    if cert_response.status_code != 200:
        raise exceptions.UI(cert_response.json()['title'])
    for certificate in cert_response.json()['certificates']:
        openssh_certificate = base64.b64decode(certificate)
        cert = ssh.cert.Cert.from_openssh(openssh_certificate)
        public_key_filename = filename_from_fingerprint[cert.public_key.ssh_fingerprint()]
        cert_filename = f"{public_key_filename.rstrip('.pub')}.cert"
        fd = os.open(cert_filename, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        with open(fd, 'wb+') as f:
            f.write(openssh_certificate + b'\n')


def _authorized_principals(args):
    with open(args.host_certificate, 'rb') as f:
        data = f.read()
        host_certificate = ssh.cert.Cert.from_openssh(data)
        host_items = host_certificate.identifier.split(':')
        if len(host_items) == 0:
            raise exceptions.UI(f'Invalid host identifier={host_certificate.identifier}')
        host_identifier = host_items[0]

    certificate = base64.b64decode(args.certificate.encode('ascii'))
    cert = ssh.serde.deserialize_cert(certificate)
    accepted = []
    for principal in cert.principals:
        items = principal.split('@')
        if len(items) != 2:
            raise exceptions.UI(f'Invalid user principal={principal}')
        username, host_id = items
        if username != args.username:
            # the certificate grants access to a username that is not the user that is currently
            # requested by the SSH connection
            continue
        if host_id != host_identifier:
            raise exceptions.UI(f'Invalid user host id={host_id} expected={host_identifier}')
        accepted.append(principal)
    print('\n'.join(accepted))


def add_subparsers(parser):
    subparsers = parser.add_subparsers(required=True)

    auth_parser = subparsers.add_parser('auth')
    auth_parser.add_argument('--host', help='Name of host we want to connect to', required=True)
    auth_parser.add_argument('--user', help='Name of user account we want to connect to', required=True)
    auth_parser.add_argument('--known-hosts', help='Known hosts file to generate', default='~/.ssh/known_hosts')
    auth_parser.add_argument('--host-krl', help='KRL file to generate')
    auth_parser.add_argument('--identity-file', help='Public key of the generated key')
    auth_parser.add_argument('--certificate-file', help='Certificate for the generated key')
    auth_parser.set_defaults(func=_auth_function)

    sign_host_parser = subparsers.add_parser('sign-host')
    sign_host_parser.add_argument('--public-key', action='append', default=[], help='Public key to sign')
    sign_host_parser.set_defaults(func=_sign_host_function)

    user_trusted_keys_parser = subparsers.add_parser('user-trusted-keys')
    user_trusted_keys_parser.set_defaults(func=_user_trusted_keys_function)

    known_hosts_parser = subparsers.add_parser('known-hosts')
    known_hosts_parser.set_defaults(func=_known_hosts_function)

    authorized_principals_parser = subparsers.add_parser('authorized-principals')
    authorized_principals_parser.add_argument('--host-certificate', help='One of the signed host certificates', default='/etc/sshd/ssh_host_ed25519_key.cert')
    authorized_principals_parser.add_argument('--username', required=True)
    authorized_principals_parser.add_argument('--certificate', help='base64 user certificate to parse', required=True)
    authorized_principals_parser.set_defaults(func=_authorized_principals)
