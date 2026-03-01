import sys
import json

import yaml

from . import exceptions


def add_parser(parser, f):
    def _add_grant_parser(parser):
        subparsers = parser.add_subparsers()

        tag_parser = subparsers.add_parser('tag')
        group = tag_parser.add_argument_group('filter')
        group.add_argument('--name-value', default=None)
        group = tag_parser.add_argument_group('permission')
        group.add_argument('-c', '--create', action='store_true')
        group.add_argument('-r', '--read', action='store_true')
        group.add_argument('-d', '--delete', action='store_true')
        tag_parser.set_defaults(grant_type='tag')

        role_parser = subparsers.add_parser('role')
        group = role_parser.add_argument_group('filter')
        group.add_argument('--name', default=None)
        group = role_parser.add_argument_group('permission')
        group.add_argument('-c', '--create', action='store_true')
        group.add_argument('-r', '--read', action='store_true')
        group.add_argument('-u', '--update', action='append', default=[], choices=['name', 'description', 'member_list', 'grant_list'])
        group.add_argument('-d', '--delete', action='store_true')
        role_parser.set_defaults(grant_type='role')

        boundary_parser = subparsers.add_parser('boundary')
        group = boundary_parser.add_argument_group('filter')
        group.add_argument('--name', default=None)
        group = boundary_parser.add_argument_group('permission')
        group.add_argument('-c', '--create', action='store_true')
        group.add_argument('-r', '--read', action='store_true')
        group.add_argument('-u', '--update', nargs='*', default=[], choices=['name', 'description', 'denied_list', 'ceiling_list'])
        group.add_argument('-d', '--delete', action='store_true')
        boundary_parser.set_defaults(grant_type='boundary')

        identity_parser = subparsers.add_parser('identity')
        group = identity_parser.add_argument_group('filter')
        group.add_argument('--name', default=None)
        group.add_argument('--tag', default=None, nargs='*')
        group.add_argument('--boundary', default=None, nargs='*')
        group = identity_parser.add_argument_group('permission')
        group.add_argument('--create-allowed', action='store_true')
        group.add_argument('--create-allowed-tag', default=None, nargs='*')
        group.add_argument('--create-required-boundary', default=None, nargs='*')
        group.add_argument('-r', '--read', action='store_true')
        group.add_argument('-u', '--update', action='append', default=[], choices=['name'])
        group.add_argument('-d', '--delete', action='store_true')
        group.add_argument('--add-tag', default=[], nargs='*')
        group.add_argument('--del-tag', default=[], nargs='*')
        group.add_argument('--invite', default=[], nargs='*', choices=['email', 'manual'])
        identity_parser.set_defaults(grant_type='identity')

        ssh_parser = subparsers.add_parser('ssh')
        group = ssh_parser.add_argument_group('filter')
        group.add_argument('--name', default=None)
        group.add_argument('--tag', default=None, nargs='*')
        group.add_argument('--boundary', default=None, nargs='*')
        group = ssh_parser.add_argument_group('permission')
        group.add_argument('--force-command', nargs='*', default=None)
        group.add_argument('--username', nargs='*', default=None)
        group.add_argument('--permit-pty', action='store_true')
        group.add_argument('--permit-user-rc', action='store_true')
        group.add_argument('--permit-x11-forwarding', action='store_true')
        group.add_argument('--permit-agent-forwarding', action='store_true')
        group.add_argument('--permit-port-forwarding', action='store_true')
        ssh_parser.set_defaults(grant_type='identity')

    def _to_dict(args):
        match args.grant_type:
            case 'tag':
                return {
                    'type': 'tag',
                    'filter': {'name_value': args.name_value},
                    'permission': {
                        'create': args.create,
                        'read': args.read,
                        'delete': args.delete,
                    },
                }
            case 'role':
                return {
                    'type': 'role',
                    'filter': {'name': args.name},
                    'permission': {
                        'create': args.create,
                        'read': args.read,
                        'update': {
                            'name': 'name' in args.update,
                            'description': 'description' in args.update,
                            'grant_list': 'grant_list' in args.update,
                            'member_list': 'member_list' in args.update,
                        },
                        'delete': args.delete,
                    },
                }
            case 'boundary':
                return {
                    'type': 'boundary',
                    'filter': {'instance': args.name},
                    'permission': {
                        'name': args.create,
                        'read': args.read,
                        'update': {
                            'name': 'name' in args.update,
                            'description': 'description' in args.update,
                            'denied_list': 'denied_list' in args.update,
                            'ceiling_list': 'ceiling_list' in args.update,
                        },
                        'delete': args.delete,
                    },
                }
            case 'identity':
                return {
                    'type': 'identity',
                    'filter': {
                        'name': args.name,
                        'tag_list': args.tag,
                        'boundary_list': args.boundary,
                    },
                    'permission': {
                        'create': {
                            'allowed': args.create_allowed,
                            'allowed_tag_list': args.create_allowed_tag,
                            'required_boundary_list': args.create_required_boundary,
                        },
                        'read': args.read,
                        'update': {
                            'name': 'name' in args.update,
                        },
                        'delete': args.delete,
                        'add_tag_list': args.add_tag,
                        'del_tag_list': args.del_tag,
                        'invite': args.invite,
                    }
                }
            case 'ssh':
                return {
                    'type': 'ssh',
                    'filter': {
                        'name': args.name,
                        'tag_list': args.tag,
                        'boundary_list': args.boundary,
                    },
                    'permission': {
                        'force_command_list': args.force_command,
                        'username_list': args.username,
                        'permit-pty': args.permit_pty,
                        'permit-user-rc': args.permit_user_rc,
                        'permit-x11-forwarding': args.permit_x11_forwarding,
                        'permit-agent-forwarding': args.permit_agent_forwarding,
                        'permit-port-forwarding': args.permit_port_forwarding,
                    }
                }
    def _read_grant_stdin():
        data = sys.stdin.read()
        try:
            grant = json.loads(data)
        except:
            try:
                grant = yaml.safe_load(data)
            except:
                raise exceptions.UI('Unable to read grant from stdin');
        return grant
    def _read_grant(args):
        if hasattr(args, 'grant_type'):
            return _to_dict(args)
        else:
            return _read_grant_stdin()
    def _check_grant(grant):
        if 'type' not in grant or 'filter' not in grant or 'permission' not in grant:
            raise exceptions.UI('Grant is missing mandatory fields')
    def _add(args):
        grant = _read_grant(args)
        _check_grant(grant)
        f(args, 'add', grant)
    def _del(args):
        grant = _read_grant(args)
        _check_grant(grant)
        f(args, 'del', grant)
    def _set(args):
        grant_list = _read_grant_stdin()
        if not isinstance(grant_list, list):
            raise exceptions.UI('Grant list is not a list')
        for grant in grant_list:
            _check_grant(grant)
        f(args, 'set', grant_list)

    subparsers = parser.add_subparsers(required=True)
    add_parser = subparsers.add_parser('add', help='Add one grant')
    _add_grant_parser(add_parser)
    add_parser.set_defaults(func=_add)

    del_parser = subparsers.add_parser('del', help='Delete one grant')
    _add_grant_parser(del_parser)
    del_parser.set_defaults(func=_del)

    set_parser = subparsers.add_parser('set', help='Set list of grants')
    _add_grant_parser(set_parser)
    set_parser.set_defaults(func=_set)
