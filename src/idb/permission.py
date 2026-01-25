import collections
import logging

from . import wa
from .context import ctx
from . import model


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


class IdObjectChecker:
    def __init__(self, object, instance):
        self._object = object
        self._instance = instance

    def _instance_matches(self, granted_field):
        if granted_field != 'id':
            logger.error('I have no fucking clue')
            raise _500()
        return self._instance.id == granted_field.value

    def matches(self, grant: model.permission.Grant):
        if grant.object != self._object:
            return False
        if not all(self._instance_matches(field) for field in grant.object_fields):
            return False
        return True


class ArgsActionChecker:
    def __init__(self, action: str, **kwargs):
        self._action = action
        self._requested = kwargs

    def matches(self, grant: model.permission.Grant):
        if grant.action not in ['*', self._action]:
            return False
        if not all(self._requested.get(g.name) == g.value for g in grant.action_fields):
            return False
        return True


class CRD:
    def __init__(self, name, instance):
        self._object_checker = IdObjectChecker(name, instance)

    def _checker(self, action_checker):
        return Checker(self._object_checker, action_checker)

    def create(self) -> Checker:
        return self._checker(ArgsActionChecker('create'))

    def read(self) -> Checker:
        return self._checker(ArgsActionChecker('read'))

    def delete(self) -> Checker:
        return self._checker(ArgsActionChecker('delete'))


class CRUD(CRD):
    def __init__(self, name, instance, update_fields):
        super().__init__(name, instance)
        self._update_fields = update_fields

    def update(self, field: str) -> Checker:
        if field not in self._update_fields:
            # This should be caught upstream by the openapi structural checks
            # We are just being a bit paranoid.
            logger.error(f'Update on field={field} was allowed by openapi checks. It is invalid.')
            raise _500()
        action_checker = ArgsActionChecker('update', field=field)
        return self._checker(action_checker)


class BoundaryChecker(CRUD):
    def __init__(self, instance):
        super().__init__('boundary', instance, ['name', 'description', 'denied_list', 'ceiling_list'])


class TagChecker(CRD):
    def __init__(self, instance):
        super().__init__('tag', instance)


class RoleChecker(CRUD):
    def __init__(self, instance):
        super().__init__('role', instance, ['name', 'description', 'permission_list', 'member_list'])


class Identity(CRUD):
    def __init__(self, instance):
        super().__init__('identity', instance, ['name'])

    def add_tag(self, tag_id: int) -> Checker:
        action_checker = ArgsActionChecker('add-tag', id=tag_id)
        return self._checker(action_checker)

    def del_tag(self, tag_id: int) -> Checker:
        action_checker = ArgsActionChecker('del-tag', id=tag_id)
        return self._checker(action_checker)


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
