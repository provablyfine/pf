def format(permission):
    return {
        'object': permission['object'],
        'action': permission['action'],
        'object_fields': [{'name': field['name'], 'value': field['value']} for field in permission['object_fields']],
        'action_fields': [{'name': field['name'], 'value': field['value']} for field in permission['action_fields']],
    }
