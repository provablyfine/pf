from .. import client
from . import boundary_cli, grant_cli, identity_cli, role_cli, tag_cli, tenant_cli


def _initialize_function(args):
    c = client.Config.load(args.config)
    api = client.Client(c)
    response = api.no_auth.post(api.directory.initialize)
    if response.status_code == 204:
        raise client.exceptions.UI("Unable to initialize app: it is already initialized.")
    if response.status_code != 200:
        raise client.exceptions.UI("Unable to initialize app: expected error.")
    data = response.json()
    print(data["key"]["k"])


def add_subparsers(parser):
    subparsers = parser.add_subparsers(required=True)

    initialize_parser = subparsers.add_parser("initialize")
    initialize_parser.set_defaults(func=_initialize_function)

    boundary_parser = subparsers.add_parser("boundary", help="View and edit boundaries")
    boundary_cli.add_subparser(boundary_parser)

    tag_parser = subparsers.add_parser("tag", help="View and edit tags")
    tag_cli.add_subparser(tag_parser)

    role_parser = subparsers.add_parser("role", help="View and edit roles")
    role_cli.add_subparser(role_parser)

    identity_parser = subparsers.add_parser("identity", help="View and edit identities")
    identity_cli.add_subparser(identity_parser)

    grant_parser = subparsers.add_parser("grant", help="Generate grants")
    grant_cli.add_subparser(grant_parser)

    tenant_parser = subparsers.add_parser("tenant", help="View and manage tenants")
    tenant_cli.add_subparser(tenant_parser)
