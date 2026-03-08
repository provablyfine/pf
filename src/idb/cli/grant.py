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
    output = []
    for k, v in p['update'].items():
        if not v:
            continue
        output.append(f'update.{k}')
    return output

def _name_value(nv):
    return f'{nv["name"]}={nv["value"]}'

@_none
def _str_list(l):
    return ','.join(l)

@_none
def _tag_list(l):
    return ','.join([_name_value(i) for i in l])


@_none
def _tag_filter_name_value(nv):
    return f'name_value:{_name_value(nv)}'

def _tag_permission(p):
    output = [] + _bool(p, 'create') + _bool(p, 'read') + _bool(p, 'delete')
    return  ' '.join(output)

def _tag_grant_to_text(grant):
    return 'tag', _tag_filter_name_value(grant['filter']['name_value']), _tag_permission(grant['permission'])

@_none
def _role_filter_name(name):
    return f'name:{name}'

def _role_permission(p):
    output = [] + _bool(p, 'create') + _bool(p, 'read') + _update(p) + _bool(p, 'delete')
    return  ' '.join(output)

def _role_grant_to_text(grant):
    return 'role', _role_filter_name(grant['filter']['name']), _role_permission(grant['permission'])

@_none
def _boundary_filter_name(name):
    return f'name:{name}'

def _boundary_permission(p):
    output = [] + _bool(p, 'create') + _bool(p, 'read') + _update(p) + _bool(p, 'delete')
    return  ' '.join(output)

def _boundary_grant_to_text(grant):
    return 'boundary', _boundary_filter_name(grant['filter']['name']), _boundary_permission(grant['permission'])

def _triplet_filter(filter):
    output = []
    output.append(f'name:{"*" if filter["name"] is None else filter["name"]}')
    output.append(f'tag_list:{_tag_list(filter["tag_list"])}')
    output.append(f'boundary_list:{"*" if filter["boundary_list"] is None else " ".join(filter["boundary_list"])}')
    return ' '.join(output)

def _identity_permission(p):
    output = [] + _bool(p, 'create') + _bool(p, 'read') + _update(p) + _bool(p, 'delete')
    output += [f"add_tag_list:{_tag_list(p['add_tag_list'])}"]
    output += [f"del_tag_list:{_tag_list(p['del_tag_list'])}"]
    output += [f"invite_list:{_str_list(p['invite_list'])}"]
    return  ' '.join(output)

def _identity_grant_to_text(grant):
    return 'identity', _triplet_filter(grant['filter']), _identity_permission(grant['permission'])

def _ssh_permission(p):
    output = []
    output += [f"username:{_str_list(p['username_list'])}"]
    output += [f"force_command:{_str_list(p['force_command_list'])}"]
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
            f(args, 'set', grant)

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-a', '--add', action='store_true', help='Add one grant')
    group.add_argument('-d', '--delete', action='store_true', help='Delete one grant')
    group.add_argument('-s', '--set', action='store_true', help='Set a list of grants')
    parser.set_defaults(func=_do)
