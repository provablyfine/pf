import sys

from . import exceptions


def dict_to_string(data: dict) -> str:
    output = [data['object'], data['action']]

    if len(data['object_fields']) == 0:
        output.append('*')
    else:
        object_fields = []
        for field in data['object_fields']:
            object_fields.append(f'{field["name"]}/{field["value"]}')
        output.append('&'.join(object_fields))

    if len(data['action_fields']) == 0:
        output.append('*')
    else:
        output.append('&'.join(f'{field["name"]}/{field["value"]}' for field in data['action_fields']))

    return ':'.join(output)


def _parse_fields(fields):
    parsed = []
    if fields != '*':
        tmp = fields.split('&')
        for i in tmp:
            field_items = i.split('/')
            if len(field_items) != 2:
                raise exceptions.UI(f'Invalid permission: fields should follow the name/value format but got: "{field_items}"')
            field_name, field_value = field_items
            parsed.append({'name': field_name, 'value': field_value})
    return parsed


def dict_from_string(s: str) -> dict:
    items = s.split(':')
    if len(items) != 4:
        raise exceptions.UI(f'Invalid permission: should have exactly 4 colon-delimited fields: "{s}"')
    object, action, object_fields, action_fields = items
    return {
        'object': object,
        'action': action,
        'object_fields': _parse_fields(object_fields),
        'action_fields': _parse_fields(action_fields)
    }


def is_equal(a: dict, b: dict):
    if a['object'] != b['object']:
        return False
    if a['action'] != b['action']:
        return False
    if sorted(a['object_fields']) != sorted(b['object_fields']):
        return False
    if sorted(a['action_fields']) != sorted(b['action_fields']):
        return False
    return True


def update_list(permissions: list[dict], to_add: list[str], to_delete: list[str], to_set: list[str], stdin: bool) -> list[dict]:
    for permission in to_add:
        one = dict_from_string(permission)
        if not any(is_equal(one, p) for p in permissions):
            permissions.append(one)

    for permission in to_delete:
        one = dict_from_string(permission)
        if not any(is_equal(one, p) for p in permissions):
            raise exceptions.UI(f'Cannot remove permission. It is not in the list. {permission}')
        permissions = [p for p in permissions if not is_equal(p, one)]

    if to_set is not None:
        permissions = [dict_from_string(p) for p in to_set]

    if stdin:
        permissions = [dict_from_string(line.strip('\n')) for line in sys.stdin]

    return permissions
