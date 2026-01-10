from . import exceptions


def dict_to_string(data: dict) -> str:
    output = [data['object'], data['action']]

    if len(data['object_fields']) == 0:
        output.append('*')
    else:
        object_fields = []
        for name, value in data['object_fields']:
            object_fields.append(f'{name}/{value}')
        output.append('&'.join(object_fields))

    if len(data['action_fields']) == 0:
        output.append('*')
    else:
        output.append('&'.join(f'{name}={value}' for name, value in data['action_fields']))

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
