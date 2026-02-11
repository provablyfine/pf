import collections
import logging

from .. import wa

from . import model
from .context import ctx


logger = logging.getLogger(__name__)


def _500():
    return wa.HTTPException(wa.ProblemResponse(status_code=500, title='Unable to verify permission grant'))


class Checker:
    def __init__(self, object_checker, action_checker):
        self._object_checker = object_checker
        self._action_checker = action_checker

    def matches(self, grant: model.permission.Grant):
        if not self._object_checker.matches(grant):
            return False
        if not self._action_checker.matches(grant):
            return False
        return True


class ObjectChecker:
    def __init__(self, object, **fields):
        self._object = object
        self._fields = fields

    def _field_match(self, granted_field):
        field_checker = self._fields.get(granted_field.name)
        if field_checker is None:
            return False
        match = field_checker(granted_field.value)
        return match

    def matches(self, grant: model.permission.Grant):
        if grant.object != self._object:
            return False
        if not all(self._field_match(field) for field in grant.object_fields):
            return False
        return True


class ActionChecker:
    def __init__(self, action: str, **kwargs):
        self._action = action
        self._requested = kwargs

    def matches(self, grant: model.permission.Grant):
        if grant.action not in ['*', self._action]:
            return False
        if not all(self._requested.get(g.name) == g.value for g in grant.action_fields):
            return False
        return True


class TagChecker:
    def __init__(self, tag_id: int):
        self._object_checker = ObjectChecker('tag', id=lambda v: v == tag_id)

    def create(self) -> Checker:
        return Checker(self._object_checker, ActionChecker('create'))

    def read(self) -> Checker:
        return Checker(self._object_checker, ActionChecker('read'))

    def delete(self) -> Checker:
        return Checker(self._object_checker, ActionChecker('delete'))


class BoundaryChecker:
    def __init__(self, boundary_id: int):
        self._object_checker = ObjectChecker('boundary', id=lambda v: v == boundary_id)

    def create(self) -> Checker:
        return Checker(self._object_checker, ActionChecker('create'))

    def read(self) -> Checker:
        return Checker(self._object_checker, ActionChecker('read'))

    def update(self, field: str) -> Checker:
        if field not in ['name', 'description', 'denied_list', 'ceiling_list']:
            logger.error(f'Update on field={field} was allowed by openapi checks. It is invalid.')
            raise _500()
        return Checker(self._object_checker, ActionChecker('update', field=field))

    def delete(self) -> Checker:
        return Checker(self._object_checker, ActionChecker('delete'))


class RoleChecker:
    def __init__(self, role_id: int):
        self._object_checker = ObjectChecker('role', id=lambda v: v==role_id)

    def create(self) -> Checker:
        return Checker(self._object_checker, ActionChecker('create'))

    def read(self) -> Checker:
        return Checker(self._object_checker, ActionChecker('read'))

    def update(self, field: str) -> Checker:
        if field not in ['name', 'description', 'permission_list', 'member_list']:
            logger.error(f'Update on field={field} was allowed by openapi checks. It is invalid.')
            raise _500()
        return Checker(self._object_checker, ActionChecker('update', field=field))

    def delete(self) -> Checker:
        return Checker(self._object_checker, ActionChecker('delete'))


class IdentityChecker:
    def __init__(self, identity_id: int, tag_id_list: list[int], boundary_id_list: list[int]):
        self._object_checker = ObjectChecker(
            'identity',
            id=lambda v: v==identity_id,
            tag_id=lambda v: v in tag_id_list,
            boundary_id=lambda v: v in boundary_id_list,
        )

    def create(self) -> Checker:
        return Checker(self._object_checker, ActionChecker('create'))

    def read(self) -> Checker:
        return Checker(self._object_checker, ActionChecker('read'))

    def update(self, field: str) -> Checker:
        if field not in ['name']:
            logger.error(f'Update on field={field} was allowed by openapi checks. It is invalid.')
            raise _500()
        return Checker(self._object_checker, ActionChecker('update', field=field))

    def delete(self) -> Checker:
        return Checker(self._object_checker, ActionChecker('delete'))

    def add_tag(self, tag_id: int) -> Checker:
        return Checker(self._object_checker, ActionChecker('add-tag', tag_id=tag_id))

    def del_tag(self, tag_id: int) -> Checker:
        return Checker(self._object_checker, ActionChecker('del-tag', tag_id=tag_id))

    def invite(self, delivery: str) -> Checker:
        return Checker(self._object_checker, ActionChecker('invite', delivery=delivery))


class Verifier:
    def __init__(self):
        identity = ctx.db.identity.read_one(id=ctx.identity_id)
        assert identity is not None
        identity_boundaries = ctx.db.identity_boundary.read_all(identity_id=identity.id)
        assert len(identity_boundaries) > 0
        self._boundaries = model.boundary.read_all(id=[i.boundary_id for i in identity_boundaries])
        member_of = ctx.db.role_member.read_all(identity_id=identity.id)
        self._roles = model.role.read_all(id=list(set(member.role_id for member in member_of)))

    def is_allowed(self, request: Checker) -> bool:
        for boundary in self._boundaries:
            if any(request.matches(denied) for denied in boundary.denied_list):
                logger.info(f'request denied by boundary id={boundary.id}')
                return False
            if len(boundary.ceiling_list) > 0 and not any(request.matches(ceiling) for ceiling in boundary.ceiling_list):
                logger.info(f'request above ceiling of boundary id={boundary.id}')
                return False
        for role in self._roles:
            if any(request.matches(permission) for permission in role.permission_list):
                return True
        logger.info('request not allowed by any role')
        return False
