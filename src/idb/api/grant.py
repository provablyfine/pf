from __future__ import annotations
import dataclasses
import typing
import abc
import logging

logger = logging.getLogger(__name__)

from . import model
from .context import ctx


class BaseWrapper:
    def __init__(self, boundaries, roles, filter):
        self._boundaries = boundaries
        self._roles = roles
        self._filter = filter

    def list_can(self, cmp) -> list[model.Grant]:
        for boundary in self._boundaries:
            if any(self._filter(denied.filter) and cmp(denied.permission) for denied in boundary.denied_list):
                logger.info(f'request denied by boundary id={boundary.id}')
                return []
            if boundary.ceiling_list is not None and not any(self._filter(ceiling.filter) and cmp(ceiling.permission) for ceiling in boundary.ceiling_list):
                logger.info(f'request above ceiling of boundary id={boundary.id}')
                return []
        allowed = []
        for role in self._roles:
            for grant in role.grant_list:
                if self._filter(grant.filter) and cmp(grant.permission):
                    allowed.append(grant)
        return allowed

    def can(self, cmp) -> bool:
        for boundary in self._boundaries:
            if any(self._filter(denied.filter) and cmp(denied.permission) for denied in boundary.denied_list):
                logger.info(f'request denied by boundary id={boundary.id}')
                return False
            if boundary.ceiling_list is not None and not any(self._filter(ceiling.filter) and cmp(ceiling.permission) for ceiling in boundary.ceiling_list):
                logger.info(f'request above ceiling of boundary id={boundary.id}')
                return False
        for role in self._roles:
            for grant in role.grant_list:
                if self._filter(grant.filter) and cmp(grant.permission):
                    return True
        logger.info('request not allowed by any role')
        return False


class RDWrapper(BaseWrapper):
    def can_read(self) -> bool:
        return self.can(lambda p: p.read)

    def can_delete(self) -> bool:
        return self.can(lambda p: p.delete)


class CRDWrapper(RDWrapper):
    def can_create(self) -> bool:
        return self.can(lambda p: p.create)


class CRUDWrapper(CRDWrapper):
    @abc.abstractmethod
    def _check_update_field(self, field: str) -> bool:
        pass

    def can_update(self, field: str) -> bool:
        assert self._check_update_field(field), "You tried to update a field that does not exist"
        def check(p) -> bool:
            if p.update is None:
                return True
            return p.update[field]
        return self.can(check)


class TagWrapper(CRDWrapper):
    pass


class BoundaryWrapper(CRUDWrapper):
    def _check_update_field(self, field: str) -> bool:
        return field in ['name', 'description', 'ceiling_list', 'denied_list']


class RoleWrapper(CRUDWrapper):
    def _check_update_field(self, field: str) -> bool:
        return field in ['name', 'description', 'grant_list']


class IdentityWrapper(RDWrapper):
    def can_create(self, tag_id_list: list[int], boundary_id_list: list[int]) -> bool:
        def check(p) -> bool:
            if p.create.allowed_tag_id_list is not None and \
                not all(tag_id in p.create.allowed_tag_id_list for tag_id in tag_id_list):
                return False
            if p.create.required_boundary_id_list is not None and \
                not all(boundary_id in boundary_id_list for boundary_id in p.create.required_boundary_id_list):
                return False
            return True
        return self.can(check)

    def can_update(self, field: str) -> bool:
        assert field == 'name', 'You are not allowed to update any field but the name field.'
        def check(p) -> bool:
            if p.update is None:
                return True
            return p.update[field]
        return self.can(check)

    def can_add_tag(self, tag_id: int) -> bool:
        def check(p) -> bool:
            if p.add_tag_id_list is None:
                return True
            return tag_id in p.add_tag_id_list
        return self.can(check)

    def can_del_tag(self, tag_id: int) -> bool:
        def check(p) -> bool:
            if p.del_tag_list is None:
                return True
            return tag_id in p.del_tag_id_list
        return self.can(check)

    def can_invite(self, delivery: str) -> bool:
        def check(p) -> bool:
            if p.invite_list is None:
                return True
            return delivery in p.invite_list
        return self.can(check)


class SSHWrapper(BaseWrapper):
    def list_can_username(self, username: str) -> list[model.Grant]:
        return self.list_can(lambda p: username in p.username_list)


class Grants:
    def __init__(self, boundaries, roles):
        self._boundaries = boundaries
        self._roles = roles

    @classmethod
    def create(klass) -> typing.Self:
        identity = ctx.db.identity.read_one(id=ctx.identity_id)
        assert identity is not None
        identity_boundaries = ctx.db.identity_boundary.read_all(identity_id=identity.id)
        assert len(identity_boundaries) > 0
        boundaries = model.boundary.read_all(id=[i.boundary_id for i in identity_boundaries])
        member_of = ctx.db.role_member.read_all(identity_id=identity.id)
        roles = model.role.read_all(id=list(set(member.role_id for member in member_of)))
        return Grants(boundaries, roles)

    def boundary(self, boundary_id: int) -> BoundaryWrapper:
        def cmp(filter: model.grant.BoundaryFilter) -> bool:
            if not isinstance(filter, model.grant.BoundaryFilter):
                return False
            if filter.id is not None and filter.id != boundary_id:
                return False
            return True
        return BoundaryWrapper(self._boundaries, self._roles, cmp)

    def tag(self, tag_id: int) -> TagWrapper:
        def cmp(filter: model.grant.TagFilter) -> bool:
            if not isinstance(filter, model.grant.TagFilter):
                return False
            if filter.id is not None and filter.id != tag_id:
                return False
            return True
        return TagWrapper(self._boundaries, self._roles, cmp)

    def role(self, role_id: int) -> RoleWrapper:
        def cmp(filter: model.grant.RoleFilter) -> bool:
            if not isinstance(filter, model.grant.RoleFilter):
                return False
            if filter.id is not None and filter.id != role_id:
                return False
            return True
        return RoleWrapper(self._boundaries, self._roles, cmp)

    def identity(self, identity_id: int|None=None, tag_id_list: list[int]|None=None, boundary_id_list: list[int]|None=None) -> IdentityWrapper:
        def cmp(filter: model.grant.IdentityFilter) -> bool:
            if not isinstance(filter, model.grant.IdentityFilter):
                return False
            if filter.id is not None and filter.id != identity_id:
                return False
            if filter.tag_id_list is not None and not all(tag_id in tag_id_list for tag_id in filter.tag_id_list):
                return False
            if filter.boundary_id_list is not None and not all(boundary_id in boundary_id_list for boundary_id in filter.boundary_id_list):
                return False
            return True
        return IdentityWrapper(self._boundaries, self._roles, cmp)

    def ssh(self, identity_id: int, tag_id_list: list[int], boundary_id_list: list[int]) -> SSHWrapper:
        def cmp(filter: model.grant.SSHFilter) -> bool:
            if not isinstance(filter, model.grant.SSHFilter):
                return False
            if filter.id is not None and filter.id != identity_id:
                return False
            if filter.tag_id_list is not None and not all(tag_id in tag_id_list for tag_id in filter.tag_id_list):
                return False
            if filter.boundary_id_list is not None and not all(boundary_id in boundary_id_list for boundary_id in filter.boundary_id_list):
                return False
            return True
        return SSHWrapper(self._boundaries, self._roles, cmp)
