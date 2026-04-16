import argparse

from . import auth_cli, bastion_cli, boundary_cli, grant_cli, identity_cli, role_cli, tag_cli, tenant_cli


# Note: argparse._SubParsersAction is private but has no public type alias in the standard library.
# typeshed itself uses it in its stubs. The alternative is to restructure all 8 sub-CLIs to
# receive their own parser from the pfa dispatcher, which is less convenient than the current
# pattern where admin_cli distributes them. See pf/bastion_cli.py and pf/ssh_cli.py for how
# we restructured those to avoid the private type.
def add_subparsers(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
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

    auth_parser = subparsers.add_parser("auth", help="Manage authentication configurations")
    auth_cli.add_subparser(auth_parser)

    bastion_parser = subparsers.add_parser("bastion", help="View and edit bastions")
    bastion_cli.add_subparser(bastion_parser)
