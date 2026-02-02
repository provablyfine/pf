import tabulate

from . import exceptions
from .. import ssh
from .. import jwk


def ssh_exception(f):
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except ssh.exceptions.Error as e:
            raise exceptions.UI(str(e))
    return wrapper


def _sign_host_key_function(args):
    pass


def _download_host_signing_key_function(args):
    pass


def _sign_user_key_function(args):
    pass


def _download_user_signing_key_function(args):
    pass


def _list_remotes_function(args):
    pass

@ssh_exception
def _agent_list_identities_function(args):
    ssh_agent = ssh.agent.Client()
    rows = []
    for id in ssh_agent.list_identities():
        key = jwk.Public.from_ssh_bytes(id.public_key)
        rows.append((key.ssh_fingerprint(), str(key.type)[len('KeyType.'):], id.comment))
        serialized = key.to_ssh_bytes()
        assert serialized == id.public_key
    if len(rows) > 0:
        print(tabulate.tabulate(rows, headers=['fingerprint', 'key type', 'comment']))


def _agent_find_by_fingerprint(ssh_agent, fingerprint):
    for identity in ssh_agent.list_identities():
        key = jwk.Public.from_ssh_bytes(identity.public_key)
        if key.match_ssh_fingerprint(fingerprint):
            return identity
    raise exceptions.UI(f'Unable to find key {fingerprint}')


@ssh_exception
def _agent_sign_function(args):
    ssh_agent = ssh.agent.Client()
    identity = _agent_find_by_fingerprint(ssh_agent, args.fingerprint)
    with open(args.data, 'rb') as f:
        data = f.read()
    match args.flags:
        case None:
            flags = 0
        case 'SHA2_256':
            flags = ssh.agent.RSA.SHA2_256
        case 'SHA2_512':
            flags = ssh.agent.RSA.SHA2_512
        case _:
            assert False
    signature = ssh_agent.sign(identity.public_key, data, flags=flags)
    print(signature)


@ssh_exception
def _agent_add_function(args):
    ssh_agent = ssh.agent.Client()
    with open(args.filename, 'rb') as f:
        data = f.read()
    key = jwk.Private.from_ssh(data)
    ssh_agent.add(key.to_ssh_bytes(), comment=args.comment, lifetime=args.lifetime, require_confirmation=args.require_confirmation)


@ssh_exception
def _agent_del_function(args):
    ssh_agent = ssh.agent.Client()
    if args.all:
        ssh_agent.remove_all()
    elif args.fingerprint:
        identity = _agent_find_by_fingerprint(ssh, args.fingerprint)
        ssh_agent.remove(identity.public_key)
    else:
        assert False


def add_subparsers(parser):
    parser.add_argument('--session-key', help='key to use to sign requests to the remote', default='session.key')
    subparsers = parser.add_subparsers(required=True)

    agent_parser = subparsers.add_parser('agent', help='ssh-agent')
    agent_subparsers = agent_parser.add_subparsers(required=True)

    agent_list_identities_parser = agent_subparsers.add_parser('ls')
    agent_list_identities_parser.set_defaults(func=_agent_list_identities_function)

    agent_sign_parser = agent_subparsers.add_parser('sign')
    agent_sign_parser.add_argument('--flags', choices=['SHA2_256', 'SHA2_512'], default=None)
    agent_sign_parser.add_argument('--fingerprint', required=True)
    agent_sign_parser.add_argument('--data', required=True)
    agent_sign_parser.set_defaults(func=_agent_sign_function)

    agent_add_key_parser = agent_subparsers.add_parser('add')
    agent_add_key_parser.add_argument('--comment', default='')
    agent_add_key_parser.add_argument('--lifetime', default=None, type=int)
    agent_add_key_parser.add_argument('--require-confirmation', action='store_true')
    agent_add_key_parser.add_argument('filename')
    agent_add_key_parser.set_defaults(func=_agent_add_function)

    agent_del_key_parser = agent_subparsers.add_parser('del')
    group = agent_del_key_parser.add_mutually_exclusive_group(required=True)
    group.add_argument('fingerprint', nargs='?')
    group.add_argument('-a', '--all', action='store_true')
    agent_del_key_parser.set_defaults(func=_agent_del_function)

    sign_host_key_parser = subparsers.add_parser('sign-host-key', help='Request signing a host key and download the resulting certificate')
    sign_host_key_parser.add_argument('--public-key', help='path to public key for which a certificate should be generated')
    sign_host_key_parser.add_argument('-o', '--output', help='path where the certificate for the key should be written', default='/dev/stdout')
    sign_host_key_parser.set_defaults(func=_sign_host_key_function)

    download_host_signing_key_parser = subparsers.add_parser('download-host-signing-key', help='Download the host signing key')
    download_host_signing_key_parser.add_argument('-o', '--output', help='Path where the host signing key should be written', default='/dev/stdout')
    download_host_signing_key_parser.set_defaults(func=_download_host_signing_key_function)

    sign_user_key_parser = subparsers.add_parser('sign-user-key', help='Request signing a user key and download the resulting certificate')
    sign_user_key_parser.add_argument('--public-key', help='path to public key for which a certificate should be generated')
    sign_user_key_parser.add_argument('-o', '--output', help='path where the certificate for the key should be written', default='/dev/stdout')
    sign_user_key_parser.set_defaults(func=_sign_user_key_function)

    download_user_signing_key_parser = subparsers.add_parser('download-user-signing-key', help='Download the user signing key')
    download_user_signing_key_parser.add_argument('-o', '--output', help='Path where the user signing key should be written', default='/dev/stdout')
    download_user_signing_key_parser.set_defaults(func=_download_user_signing_key_function)

    list_remotes_parser = subparsers.add_parser('list-remotes', help='List all remotes the current identity is allowed to connect to')
    list_remotes_parser.set_defaults(func=_list_remotes_function)

    #login_parser = subparsers.add_argument('login')
    #login_parser.set_defaults(func=_login_function)
