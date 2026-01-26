from __future__ import annotations

import dataclasses
import collections

from ..context import ctx
from .. import wa

FieldConverter = collections.namedtuple('FieldConverter', ['to_name', 'convert'])
ObjectConverter = collections.namedtuple('ObjectConverter', ['object_fields', 'action_fields'])


class Converter:
    def __init__(self):
        self._by_object = collections.defaultdict(lambda: ObjectConverter(object_fields={}, action_fields={}))
        self._data_by_convert_and_key = {}
    
    def _convert(self, convert, convert_key):
        key = (convert, convert_key)
        value = self._data_by_convert_and_key.get(key)
        if value is not None:
            return value
        value = convert(convert_key)
        self._data_by_convert_and_key[key] = value
        return value

    def add_object_field(self, object: str, from_name: str, to_name: str, convert):
        self._by_object[object].object_fields[from_name] = FieldConverter(to_name, convert)
        return self

    def add_action_field(self, object: str, from_name: str, to_name: str, convert):
        self._by_object[object].action_fields[from_name] = FieldConverter(to_name, convert)
        return self

    def convert(self, permission: Grant) -> Grant:
        def convert_fields(fields: list[Field], field_converters):
            output_fields = []
            for field in fields:
                field_converter = field_converters.get(field.name)
                if field_converter is None:
                    output_fields.append(field)
                else:
                    converted_value = self._convert(field_converter.convert, field.value)
                    converted_field = Field(
                        name=field_converter.to_name,
                        value=converted_value,
                    )
                    output_fields.append(converted_field)
            return output_fields

        object_converter = self._by_object[permission.object]
        object_fields = convert_fields(permission.object_fields, object_converter.object_fields)
        action_fields = convert_fields(permission.action_fields, object_converter.action_fields)
        return Grant.create(
            object=permission.object,
            action=permission.action,
            object_fields=object_fields,
            action_fields=action_fields,
        )

def _500(title, detail):
    return wa.HTTPException(wa.ProblemResponse(status_code=500, title=f'Permission field invalid. {title}', detail=detail))

def to_client() -> Converter:
    def _tag_id_to_name(tag_id):
        tag = ctx.db.tag.read_one(id=tag_id)
        if tag is None:
            raise _500('Tag cannot be found', detail=tag_id)
        return f'{tag.name}={tag.value}'

    def _identity_id_to_name(identity_id):
        identity = ctx.db.identity.read_one(id=identity_id)
        if identity is None:
            raise _500('Identity cannot be found', detail=identity_id)
        return identity.name

    def _role_id_to_name(role_id):
        assert role_id is not None
        role = ctx.db.role.read_one(id=role_id)
        if role is None:
            raise _500('Role cannot be found', detail=role_id)
        return role.name

    def _boundary_id_to_name(boundary_id):
        boundary = ctx.db.boundary.read_one(id=boundary_id)
        if boundary is None:
            raise _500('Boundary cannot be found', detail=boundary_id)
        return boundary.name

    converter = (Converter()
        .add_object_field(object='tag', from_name='id', to_name='name', convert=_tag_id_to_name)
        .add_object_field(object='role', from_name='id', to_name='name', convert=_role_id_to_name)
        .add_object_field(object='boundary', from_name='id', to_name='name', convert=_boundary_id_to_name)
        .add_object_field(object='identity', from_name='id', to_name='name', convert=_identity_id_to_name)
        .add_object_field(object='identity', from_name='tag_id', to_name='tag', convert=_tag_id_to_name)
        .add_object_field(object='identity', from_name='boundary_id', to_name='boundary', convert=_boundary_id_to_name)
    )
    return converter


def _400(title, detail):
    return wa.HTTPException(wa.ProblemResponse(status_code=400, title=f'Permission field invalid. {title}', detail=detail))

def from_client() -> Converter:
    def _tag_name_to_id(name):
        items = name.split('=')
        if len(items) != 2:
            raise _400('Expected: name=value', detail=name)
        name, value = items
        tag = ctx.db.tag.read_one(name=name, value=value)
        if tag is None:
            raise _400('Tag cannot be found', detail=name)
        return tag.id

    def _role_name_to_id(name):
        role = ctx.db.role.read_one(name=name)
        if role is None:
            raise _400('Role cannot be found', detail=name)
        return role.id

    def _identity_name_to_id(name):
        identity = ctx.db.identity.read_one(name=name)
        if identity is None:
            raise _400('Identity cannot be found', detail=name)
        return identity.id

    def _boundary_name_to_id(name):
        boundary = ctx.db.boundary.read_one(name=name)
        if boundary is None:
            raise _400('Boundary cannot be found', detail=name)
        return boundary.id

    converter = (Converter()
        .add_object_field(object='tag', from_name='name', to_name='id', convert=_tag_name_to_id)
        .add_object_field(object='role', from_name='name', to_name='id', convert=_role_name_to_id)
        .add_object_field(object='boundary', from_name='name', to_name='id', convert=_boundary_name_to_id)
        .add_object_field(object='identity', from_name='name', to_name='id', convert=_identity_name_to_id)
        .add_object_field(object='identity', from_name='tag', to_name='tag_id', convert=_tag_name_to_id)
        .add_object_field(object='identity', from_name='boundary', to_name='boundary_id', convert=_boundary_name_to_id)
    )
    return converter



@dataclasses.dataclass(frozen=True)
class Field:
    name: str
    value: int | str

    @classmethod
    def from_dict(cls, data) -> Field:
        return Field(name=data['name'], value=data['value'])

    def to_dict(self) -> dict:
        return {
            'name': self.name,
            'value': self.value,
        }

@dataclasses.dataclass(frozen=True)
class Grant:
    object: str
    action: str
    object_fields: tuple[Field]
    action_fields: tuple[Field]

    @classmethod
    def create(cls, object: str, action: str=None, object_fields: list[Field]=None, action_fields: list[Field]=None):
        if action is None:
            action = '*'
        if object_fields is None:
            object_fields = []
        if action_fields is None:
            action_fields = []
        return Grant(object=object, action=action, object_fields=tuple(sorted(object_fields)), action_fields=tuple(sorted(action_fields)))

    def to_dict(self) -> dict:
        return {
            'object': self.object,
            'action': self.action,
            'object_fields': [field.to_dict() for field in self.object_fields],
            'action_fields': [field.to_dict() for field in self.action_fields],
        }
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, data):
        object_fields = tuple(Field.from_dict(field) for field in data['object_fields'])
        action_fields = tuple(Field.from_dict(field) for field in data['action_fields'])
        return Grant.create(object=data['object'], action=data['action'], object_fields=object_fields, action_fields=action_fields)

identity_all = Grant.create(object='identity', action='*', object_fields=None, action_fields=None)
tag_all = Grant.create(object='tag', action='*', object_fields=None, action_fields=None)
role_all = Grant.create(object='role', action='*', object_fields=None, action_fields=None)
boundary_all = Grant.create(object='boundary', action='*', object_fields=None, action_fields=None)


def serialize(grant: Grant, to_client: Converter) -> dict:
    return to_client.convert(grant).to_dict()


def serialize_list(grants: list[Grant], to_client: Converter) -> list:
    return [serialize(g, to_client) for g in grants]


def deserialize(data: dict, from_client: Converter) -> Grant:
    return from_client.convert(Grant.from_dict(data))
