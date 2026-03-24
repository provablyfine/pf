import sys

import tabulate

from .. import jwk, ssh
from ..client import exceptions, ssh_utils


@ssh_utils.exception
def _agent_list_identities_function(args):
    ssh_agent = ssh.agent.Client()
    if args.quiet:
        rows = []
        for id in ssh_agent.list_identities():
            rows.append(id.public_key.ssh_fingerprint())
        output = "\n".join(rows)
    else:
        rows = []
        for id in ssh_agent.list_identities():
            rows.append((id.public_key.ssh_fingerprint(), str(id.public_key.type)[len("KeyType.") :], id.comment))
        if len(rows) > 0:
            output = tabulate.tabulate(rows, headers=["fingerprint", "key type", "comment"])
        else:
            output = ""
    if output:
        print(output)


def _agent_find_by_fingerprint(ssh_agent, fingerprint):
    for identity in ssh_agent.list_identities():
        if identity.public_key.match_ssh_fingerprint(fingerprint):
            return identity
    raise exceptions.UI(f"Unable to find key {fingerprint}")


@ssh_utils.exception
def _agent_sign_function(args):
    def is_rsa(key):
        return key.type in [
            jwk.KeyType.RSA_3072,
            jwk.KeyType.RSA_7680,
            jwk.KeyType.RSA_15360,
        ]

    ssh_agent = ssh.agent.Client()
    identity = _agent_find_by_fingerprint(ssh_agent, args.fingerprint)
    with open(args.data, "rb") as f:
        data = f.read()
    match args.flags:
        case None:
            if is_rsa(identity.public_key):
                flags = ssh.constants.RSA.SHA2_256
            else:
                flags = 0
        case "SHA2_256":
            flags = ssh.constants.RSA.SHA2_256
        case "SHA2_512":
            flags = ssh.constants.RSA.SHA2_512
        case _:
            assert False
    signature = ssh_agent.sign(identity, data, flags=flags)
    sys.stdout.buffer.write(signature)


@ssh_utils.exception
def _agent_add_function(args):
    ssh_agent = ssh.agent.Client()
    with open(args.key, "rb") as f:
        data = f.read()
    key = ssh_utils.load_private_key(data)
    if args.certificate is None:
        cert = None
    else:
        with open(args.certificate, "rb") as f:
            cert = ssh.cert.Cert.from_openssh(f.read())
    ssh_agent.add(
        key, cert=cert, comment=args.comment, lifetime=args.lifetime, require_confirmation=args.require_confirmation
    )


@ssh_utils.exception
def _agent_del_function(args):
    ssh_agent = ssh.agent.Client()
    if args.all:
        ssh_agent.remove_all()
    elif args.fingerprint:
        identity = _agent_find_by_fingerprint(ssh_agent, args.fingerprint)
        ssh_agent.remove(identity)
    else:
        assert False


def add_subparsers(parser):
    agent_subparsers = parser.add_subparsers(required=True)

    agent_list_identities_parser = agent_subparsers.add_parser("ls")
    agent_list_identities_parser.add_argument("-q", "--quiet", action="store_true")
    agent_list_identities_parser.set_defaults(func=_agent_list_identities_function)

    agent_sign_parser = agent_subparsers.add_parser("sign")
    agent_sign_parser.add_argument("--flags", choices=["SHA2_256", "SHA2_512"], default=None)
    agent_sign_parser.add_argument("--fingerprint", required=True)
    agent_sign_parser.add_argument("--data", required=True)
    agent_sign_parser.set_defaults(func=_agent_sign_function)

    agent_add_key_parser = agent_subparsers.add_parser("add")
    agent_add_key_parser.add_argument("--comment", default="")
    agent_add_key_parser.add_argument("--lifetime", default=None, type=int)
    agent_add_key_parser.add_argument("--require-confirmation", action="store_true")
    agent_add_key_parser.add_argument("--key", required=True)
    agent_add_key_parser.add_argument("--certificate")
    agent_add_key_parser.set_defaults(func=_agent_add_function)

    agent_del_key_parser = agent_subparsers.add_parser("del")
    group = agent_del_key_parser.add_mutually_exclusive_group(required=True)
    group.add_argument("fingerprint", nargs="?")
    group.add_argument("-a", "--all", action="store_true")
    agent_del_key_parser.set_defaults(func=_agent_del_function)
