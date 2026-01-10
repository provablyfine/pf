from __future__ import annotations

import dataclasses
import logging


logger = logging.getLogger(__name__)


class Int:
    def matches(self, got, expected):
        assert isinstance(got, int) and isinstance(expected, int)
        return got == expected


class Str:
    def matches(self, got, expected):
        assert isinstance(got, str) and isinstance(expected, str)
        return got == expected

class ListOfInt:
    def matches(self, got, expected):
        assert isinstance(got, list) and all(map(lambda i: isinstance(i, int), got)) and isinstance(expected, int)
        return expected in got


@dataclasses.dataclass
class Field:
    name: str
    value: int | str

    @classmethod
    def from_db_dict(cls, data) -> Field:
        return Field(name=data['name'], value=data['value'])

    def to_db_dict(self) -> dict:
        return {
            'name': self.name,
            'value': self.value,
        }


@dataclasses.dataclass
class Grant:
    object: str
    action: str
    object_fields: list[Field]
    action_fields: list[Field]

    def __init__(self, object: str, action: str=None, object_fields: list[Field]=None, action_fields: list[Field]=None):
        if action is None:
            action = '*'
        if object_fields is None:
            object_fields = []
        if action_fields is None:
            action_fields = []
        self.object = object
        self.action = action
        self.object_fields = object_fields
        self.action_fields = action_fields

    def to_db_dict(self) -> dict:
        return {
            'object': self.object,
            'action': self.action,
            'object_fields': [field.to_db_dict() for field in self.object_fields],
            'action_fields': [field.to_db_dict() for field in self.action_fields],
        }
        return dataclasses.asdict(self)

    @classmethod
    def from_db_dict(cls, data):
        object_fields = [Field.from_db_dict(field) for field in data['object_fields']]
        action_fields = [Field.from_db_dict(field) for field in data['action_fields']]
        return Grant(object=data['object'], action=data['action'], object_fields=object_fields, action_fields=action_fields)


class Request:
    def __init__(self, schema, instance, action, parameters):
        self._schema = schema
        self._instance = instance
        self._action = action
        self._parameters = parameters

    def _instance_matches(self, granted_field):
        assert granted_field.name in self._schema.object_fields
        field = self._schema.object_fields[granted_field.name]
        request_value = getattr(self._instance, granted_field.name)
        return field.matches(request_value, granted_field.value)

    def _action_matches(self, granted_field):
        assert granted_field.name in self._schema.action_fields
        field = self._schema.action_fields[granted_field.name]
        request_value = getattr(self._instance, granted_field.name)
        return field.matches(request_value, granted_field.value)

    def matches(self, grant: Grant):
        if grant.object != self._schema._name:
            logger.debug(f'fail match object {grant.object} != {self._schema._name}')
            return False
        if not all(self._instance_matches(field) for field in grant.object_fields):
            return False
        if grant.action not in ['*', self._action]:
            logger.debug(f'fail match action {grant.action} != {self._action}')
            return False
        if not all(self._action_matches(field) for field in grant.action_fields):
            return False
        return True


class Schema:
    def __init__(self, name):
        self._name = name
        self._object_fields = {}
        self._actions_fields = {}

    @property
    def name(self):
        return self._name

    @property
    def object_fields(self):
        return self._object_fields

    def add_fields(self, **kwargs):
        for k, v in kwargs.items():
            self._object_fields[k] = v
        return self

    def add_action(self, name, **parameters):
        self._actions_fields[name] = parameters
        return self

    def create_request(self, instance, action, **parameters):
        assert action in self._actions_fields
        action_fields = self._actions_fields[action]
        for name, value in parameters.items():
            assert name in action_fields
            field = action_fields[name]
            assert field.check_compatible(value)
        return Request(self, instance, action, parameters)

    def create_grant(self, object_fields: list[Field]=None, action: str=None, action_fields: list[Field]=None):
        return Grant(
            object=self._name,
            object_fields=object_fields,
            action=action,
            action_fields=action_fields,
        )


identity = (
    Schema('identity')
        .add_fields(id=Int(), tag_id=ListOfInt(), created_by=Int())
        .add_action('read')
        .add_action('create')
        .add_action('add-tag', tag_id=Int())
        .add_action('del-tag', tag_id=Int())
        .add_action('ssh-shell', username=Str())
        .add_action('ssh-tunnel', username=Str(), dport=Int())
        .add_action('ssh-exec', username=Str(), command=Str())
        .add_action('cert', domain=Str())
)

role = (
    Schema('role')
        .add_fields(id=Int())
        .add_action('read')
        .add_action('create')
        .add_action('delete')
        .add_action('update')
        .add_action('add-grant')
        .add_action('del-grant')
        .add_action('add-member')
        .add_action('del-member')
)

tag = (
    Schema('tag')
        .add_fields(id=Int())
        .add_action('read')
        .add_action('create')
        .add_action('delete')
)

boundary = (
    Schema('boundary')
        .add_fields(id=Int())
        .add_action('read')
        .add_action('create')
        .add_action('delete')
        .add_action('add-deny')
        .add_action('del-deny')
)

def lookup(name):
    all_schemas = [identity, role, tag, boundary]
    schema_by_name = {s.name: s for s in all_schemas}
    return schema_by_name.get(name)
