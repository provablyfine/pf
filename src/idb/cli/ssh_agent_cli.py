
import tabulate

from . import ssh_utils
from . import exceptions
from .. import ssh
from .. import jwk


@ssh_utils.exception
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


@ssh_utils.exception
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


@ssh_utils.exception
def _agent_add_function(args):
    ssh_agent = ssh.agent.Client()
    with open(args.filename, 'rb') as f:
        data = f.read()
    key = jwk.Private.from_ssh(data)
    ssh_agent.add(key.to_ssh_bytes(), comment=args.comment, lifetime=args.lifetime, require_confirmation=args.require_confirmation)


@ssh_utils.exception
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
    agent_subparsers = parser.add_subparsers(required=True)

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
