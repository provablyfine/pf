from __future__ import annotations

import dataclasses
import logging

from .context import ctx


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
class PermissionField:
    name: str
    value: int | str

    @classmethod
    def from_dict(cls, data) -> PermissionField:
        return PermissionField(name=data['name'], value=data['value'])


@dataclasses.dataclass
class PermissionGrant:
    object: str
    action: str
    object_fields: list[PermissionField]
    action_fields: list[PermissionField]

    def __init__(self, object: str, action: str=None, object_fields: list[PermissionField]=None, action_fields: list[PermissionField]=None):
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


    def to_string(self) -> str:
        output = [self.object]
        if len(self.object_fields) == 0:
            output.append('*')
        output.append(self.action)
        if len(self.action_fields) == 0:
            output.append('*')
        return ':'.join(output)

    @classmethod
    def from_string(cls, s) -> PermissionGrant:
        pass

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, data):
        object_fields = [PermissionField.from_dict(field) for field in data['object_fields']]
        action_fields = [PermissionField.from_dict(field) for field in data['action_fields']]
        return PermissionGrant(object=data['object'], action=data['action'], object_fields=object_fields, action_fields=action_fields)


class PermissionRequest:
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

    def matches(self, grant: PermissionGrant):
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


class PermissionSchema:
    def __init__(self, name):
        self._name = name
        self._object_fields = {}
        self._actions_fields = {}

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
        return PermissionRequest(self, instance, action, parameters)

    def create_grant(self, object_fields: list[PermissionField]=None, action: str=None, action_fields: list[PermissionField]=None):
        return PermissionGrant(
            object=self._name,
            object_fields=object_fields,
            action=action,
            action_fields=action_fields,
        )


identity = (
    PermissionSchema('identity')
        .add_fields(id=Int(), tag_id=ListOfInt())
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
    PermissionSchema('role')
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
    PermissionSchema('tag')
        .add_fields(id=Int())
        .add_action('read')
        .add_action('create')
        .add_action('delete')
)

boundary = (
    PermissionSchema('boundary')
        .add_fields(id=Int())
        .add_action('read')
        .add_action('create')
        .add_action('delete')
        .add_action('add-deny')
        .add_action('del-deny')
)

class Verifier:
    def __init__(self):
        identity = ctx.db.identity.read_one(id=ctx.identity_id)
        assert identity is not None
        assert len(identity.boundaries) > 0
        boundaries = ctx.db.boundary.read_all(id=identity.boundaries)
        grants = ctx.db.role_grant.read_all(identity_id=identity.id)
        roles = ctx.db.role.read_all(id=list(set(g.role_id for g in grants)))
        self._denied = [PermissionGrant(**denied) for boundary in boundaries for denied in boundary.denies]
        self._allowed = [PermissionGrant(**permission) for role in roles for permission in role.permissions]

    def create_boundary_request(self, instance, action, **parameters):
        return boundary.create_request(instance, action, **parameters)

    def is_allowed(self, request: PermissionRequest) -> bool:
        if any(request.matches(denied) for denied in self._denied):
            return False
        if any(request.matches(allowed) for allowed in self._allowed):
            return True
        return False
