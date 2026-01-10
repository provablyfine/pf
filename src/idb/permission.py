import collections

from . import permission_schema
from . import wa
from .context import ctx


FieldsConverter = collections.namedtuple('FieldsConverter', ['client_name', 'read', 'convert'])
ObjectConverter = collections.namedtuple('ObjectConverter', ['object_fields', 'action_fields'])


class Converter:
    def __init__(self):
        self._by_object = collections.defaultdict(lambda: ObjectConverter(object_fields={}, action_fields={}))

    def add_object_field(self, object: str, from_name: str, to_name: str, read, convert):
        self._by_object[object].object_fields[from_name] = FieldsConverter(to_name, read, convert)
        return self

    def add_action_field(self, object: str, from_name: str, to_name: str, read, convert):
        self._by_object[object].action_fields[from_name] = FieldsConverter(to_name, read, convert)
        return self

    def convert(self, permissions: list[dict]) -> dict:
        "Return mapping from permission id to client-ready version"
        # collect ids to read from database
        ids_by_read = collections.defaultdict(lambda: [])
        for permission in permissions:
            converter = self._by_object[permission['object']]
            for field in permission['object_fields']:
                converter = self._by_object[permission['object']].object_fields.get(field['name'])
                if converter is None:
                    continue
                ids_by_read[converter.read].append(field['value'])
            for field in permission['action_fields']:
                converter = self._by_object[permission['object']].action_fields.get(field['name'])
                if converter is None:
                    continue
                ids_by_read[converter.read].append(field['value'])

        # read ids from database
        data_by_read = {}
        for read, ids in ids_by_read.items():
            data_by_read[read] = read(list(set(ids)))

        def convert_fields(fields, converters):
            # convert fields for which a convertion function is defined. Let data through otherwise.
            converted = []
            for field in fields:
                converter = converters.get(field['name'])
                if converter is None:
                    converted.append({'name': field['name'], 'value': field['value']})
                else:
                    value = converter.convert(data_by_read[converter.read][field['value']])
                    converted.append({'name': converter.to_name, 'value': value})
            return converted

        # generate output
        output = {}
        for permission in permissions:
            object_converter = self._by_object[permission['object']]
            object_fields = convert_fields(permission['object_fields'], object_converter.object_fields)
            action_fields = convert_fields(permission['action_fields'], object_converter.action_fields)
            output[id(permission)] = {
                'object': permission['object'],
                'action': permission['action'],
                'object_fields': object_fields,
                'action_fields': action_fields,
            }
        return output


def _read_tag_by_id(ids):
    return {i.id: i for i in ctx.db.tag.read_all(id=ids)}

def _read_identity_by_id(ids):
    return {i.id: i for i in ctx.db.identity.read_all(id=ids)}

def _read_role_by_id(ids):
    return {i.id: i for i in ctx.db.role.read_all(id=ids)}

def _read_boundary_by_id(ids):
    return {i.id: i for i in ctx.db.boundary.read_all(id=ids)}

def _tag_to_str(tag) -> str:
    return f'{tag.name}={tag.value}'


serializer = (Converter()
    .add_object_field(object='tag', from_name='id', to_name='name', read=_read_tag_by_id, convert=_tag_to_str)
    .add_object_field(object='role', from_name='id', to_name='name', read=_read_role_by_id, convert=lambda o: o.name)
    .add_object_field(object='boundary', from_name='id', to_name='name', read=_read_boundary_by_id, convert=lambda o: o.name)
    .add_object_field(object='identity', from_name='id', to_name='name', read=_read_identity_by_id, convert=lambda o: o.name)
    .add_object_field(object='identity', from_name='tag_id', to_name='tag', read=_read_tag_by_id, convert=_tag_to_str)
    .add_object_field(object='identity', from_name='created_by_id', to_name='created_by', read=_read_identity_by_id, convert=lambda o: o.name)
    .add_action_field(object='identity', from_name='tag_id', to_name='tag', read=_read_tag_by_id, convert=_tag_to_str)
)

def _read_tag_by_name_value(ids):
    output = {}
    for id in ids:
        items = id.split('=')
        if len(items) != 2:
            raise wa.HTTPException(wa.ProblemResponse(status_code=400, title='permission field invalid. Expected: a=b', detail=id))
        name, value = items
        tag = ctx.db.tag.read_one(name=name, value=value)
        output[id] = tag
    return output

def _read_role_by_name(ids):
    return {i.name: i for i in ctx.db.role.where(name=ids)}

def _read_boundary_by_name(ids):
    return {i.name: i for i in ctx.db.boundary.where(name=ids)}

def _read_identity_by_name(ids):
    return {i.name: i for i in ctx.db.identity.where(name=ids)}

deserializer = (Converter()
    .add_object_field(object='tag', from_name='name', to_name='id', read=_read_tag_by_name_value, convert=lambda o: o.id)
    .add_object_field(object='role', from_name='id', to_name='name', read=_read_role_by_name, convert=lambda o: o.id)
    .add_object_field(object='boundary', from_name='id', to_name='name', read=_read_boundary_by_name, convert=lambda o: o.id)
    .add_object_field(object='identity', from_name='id', to_name='name', read=_read_identity_by_name, convert=lambda o: o.id)
    .add_object_field(object='identity', from_name='tag_id', to_name='tag', read=_read_tag_by_name_value, convert=lambda o: o.id)
    .add_object_field(object='identity', from_name='created_by_id', to_name='created_by', read=_read_identity_by_name, convert=lambda o: o.id)
    .add_action_field(object='identity', from_name='tag_id', to_name='tag', read=_read_tag_by_name_value, convert=lambda o: o.id)
)


class Verifier:
    def __init__(self):
        identity = ctx.db.identity.read_one(id=ctx.identity_id)
        assert identity is not None
        assert len(identity.boundaries) > 0
        boundaries = ctx.db.boundary.read_all(id=identity.boundaries)
        grants = ctx.db.role_grant.read_all(identity_id=identity.id)
        roles = ctx.db.role.read_all(id=list(set(g.role_id for g in grants)))
        self._denied = [permission_schema.Grant.from_db_dict(denied) for boundary in boundaries for denied in boundary.denies]
        self._allowed = [permission_schema.Grant.from_db_dict(permission) for role in roles for permission in role.permissions]

    def create_boundary_request(self, instance, action, **parameters) -> permission_schema.Request:
        return permission_schema.boundary.create_request(instance, action, **parameters)

    def is_allowed(self, request: permission_schema.Request) -> bool:
        if any(request.matches(denied) for denied in self._denied):
            return False
        if any(request.matches(allowed) for allowed in self._allowed):
            return True
        return False
