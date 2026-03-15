import os.path
import os
import sys
import json

import yaml
import pydantic

from . import exceptions


def _none(f):
    def wrapper(a):
        if a is None:
            return '*'
        return f(a)
    return wrapper

def _bool(p: dict, name: str) -> list:
    if not p[name]:
        return []
    return [name]

def _update(p: dict) -> list:
    if p['update'] is None:
        return ['update.*']
    output = []
    for k, v in p['update'].items():
        if not v:
            continue
        output.append(f'update.{k}')
    return output

def _name_value(nv):
    return f'{nv["name"]}={nv["value"]}'

def _str(d, name) -> list:
    if d[name] is None:
        return []
    return [f'{name}:{d["name"]}']

def _filter_list(d, name, f) -> list:
    if d[name] is None:
        return []
    if len(d[name]) == 0:
        return [f'{name}:!']
    return [f'{name}:{",".join(f(i) for i in d[name])}']

def _permission_list(d, name, f) -> list:
    if d[name] is None:
        return [f'{name}:*']
    if len(d[name]) == 0:
        return []
    return [f'{name}:{",".join(f(i) for i in d[name])}']


@_none
def _tag_filter_name_value(nv):
    return f'name_value:{_name_value(nv)}'

def _tag_permission(p):
    output = _bool(p, 'create') + _bool(p, 'read') + _bool(p, 'delete')
    return  ' '.join(output)

def _tag_grant_to_text(grant):
    return 'tag', _tag_filter_name_value(grant['filter']['name_value']), _tag_permission(grant['permission'])

@_none
def _role_filter_name(name):
    return f'name:{name}'

def _role_permission(p):
    output = _bool(p, 'create') + _bool(p, 'read') + _update(p) + _bool(p, 'delete')
    return  ' '.join(output)

def _role_grant_to_text(grant):
    return 'role', _role_filter_name(grant['filter']['name']), _role_permission(grant['permission'])

@_none
def _boundary_filter_name(name):
    return f'name:{name}'

def _boundary_permission(p):
    output = _bool(p, 'create') + _bool(p, 'read') + _update(p) + _bool(p, 'delete')
    return  ' '.join(output)

def _boundary_grant_to_text(grant):
    return 'boundary', _boundary_filter_name(grant['filter']['name']), _boundary_permission(grant['permission'])

def _triplet_filter(filter):
    output = _str(filter, 'name') + _filter_list(filter, 'tag_list', _name_value) + _filter_list(filter, 'boundary_list', lambda i:i)
    if len(output) == 0:
        return '*'
    return ' '.join(output)

def _identity_permission(p):
    output = _bool(p, 'create') + _bool(p, 'read') + _update(p) + _bool(p, 'delete')
    output += _permission_list(p, 'add_tag_list', _name_value)
    output += _permission_list(p, 'del_tag_list', _name_value)
    output += _permission_list(p, 'invite_list', lambda i:i)
    return  ' '.join(output)

def _identity_grant_to_text(grant):
    return 'identity', _triplet_filter(grant['filter']), _identity_permission(grant['permission'])

def _ssh_permission(p):
    output = _permission_list(p, 'username_list', lambda i:i) + _permission_list(p, 'force_command_list', lambda i:i)
    output += _bool(p, 'permit_pty') + _bool(p, "permit_user_rc") + _bool(p, "permit_x11_forwarding") + _bool(p, "permit_agent_forwarding") + _bool(p, "permit_port_forwarding")
    return  ' '.join(output)

def _ssh_grant_to_text(grant):
    return 'ssh', _triplet_filter(grant['filter']), _ssh_permission(grant['permission'])

def to_text(grant):
    match grant['type']:
        case 'tag':
            return _tag_grant_to_text(grant)
        case 'role':
            return _role_grant_to_text(grant)
        case 'boundary':
            return _boundary_grant_to_text(grant)
        case 'identity':
            return _identity_grant_to_text(grant)
        case 'ssh':
            return _ssh_grant_to_text(grant)
        case 'invalid':
            return 'invalid', '!', '!'
        case _:
            assert False


def add_parser(parser, f):
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
    def _do(args):
        grant = _read_grant_stdin()
        if args.add:
            f(args, 'add', grant)
        if args.delete:
            f(args, 'del', grant)
        if args.set:
            if not isinstance(grant, list):
                grant = [grant]
            f(args, 'set', grant)

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-a', '--add', action='store_true', help='Add one grant')
    group.add_argument('-d', '--delete', action='store_true', help='Delete one grant')
    group.add_argument('-s', '--set', action='store_true', help='Set a list of grants')
    parser.set_defaults(func=_do)
