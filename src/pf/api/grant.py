from __future__ import annotations

import logging

from . import model
from .context import ctx

logger = logging.getLogger(__name__)


class Checker:
    def __init__(self, boundaries: list[model.boundary.Boundary], roles: list[model.role.Role], filter):
        self._boundaries = boundaries
        self._roles = roles
        self._filter = filter

    def list_can(self, cmp) -> list:
        for boundary in self._boundaries:
            if any(self._filter(denied.filter) and cmp(denied.permission) for denied in boundary.denied_list):
                logger.info(f"request denied by boundary id={boundary.id}")
                return []
            if boundary.ceiling_list is not None and not any(
                self._filter(ceiling.filter) and cmp(ceiling.permission) for ceiling in boundary.ceiling_list
            ):
                logger.info(f"request above ceiling of boundary id={boundary.id}")
                return []
        allowed = []
        for role in self._roles:
            for grant in role.grant_list:
                if self._filter(grant.filter) and cmp(grant.permission):
                    allowed.append(grant)
        if len(allowed) == 0:
            logger.info("request not allowed by any role")
        return allowed

    def can(self, cmp) -> bool:
        allowed = self.list_can(cmp)
        return len(allowed) > 0


class TagChecker:
    def __init__(self, boundaries: list[model.boundary.Boundary], roles: list[model.role.Role], tag_id: int | None):
        def cmp(filter: model.grant.TagFilter) -> bool:
            if not isinstance(filter, model.grant.TagFilter):
                return False
            if filter.id is not None and filter.id != tag_id:
                return False
            return True

        self._checker = Checker(boundaries, roles, cmp)

    def can_create(self) -> bool:
        return self._checker.can(lambda p: p.create)

    def can_read(self) -> bool:
        return self._checker.can(lambda p: p.read)

    def can_delete(self) -> bool:
        return self._checker.can(lambda p: p.delete)


class BoundaryChecker:
    def __init__(
        self, boundaries: list[model.boundary.Boundary], roles: list[model.role.Role], boundary_id: int | None
    ):
        def cmp(filter: model.grant.BoundaryFilter) -> bool:
            if not isinstance(filter, model.grant.BoundaryFilter):
                return False
            if filter.id is not None and filter.id != boundary_id:
                return False
            return True

        self._checker = Checker(boundaries, roles, cmp)

    def can_create(self) -> bool:
        return self._checker.can(lambda p: p.create)

    def can_read(self) -> bool:
        return self._checker.can(lambda p: p.read)

    def can_update(self, field: str) -> bool:
        assert field in ["name", "description", "denied_list", "ceiling_list"], (
            "You tried to update a field that does not exist"
        )

        def check(p) -> bool:
            if p.update is None:
                return True
            return getattr(p.update, field)

        return self._checker.can(check)

    def can_delete(self) -> bool:
        return self._checker.can(lambda p: p.delete)


class RoleChecker:
    def __init__(self, boundaries: list[model.boundary.Boundary], roles: list[model.role.Role], role_id: int | None):
        def cmp(filter: model.grant.RoleFilter) -> bool:
            if not isinstance(filter, model.grant.RoleFilter):
                return False
            if filter.id is not None and filter.id != role_id:
                return False
            return True

        self._checker = Checker(boundaries, roles, cmp)

    def can_create(self) -> bool:
        return self._checker.can(lambda p: p.create)

    def can_read(self) -> bool:
        return self._checker.can(lambda p: p.read)

    def can_update(self, field: str) -> bool:
        assert field in ["name", "description", "member_list", "grant_list"], (
            "You tried to update a field that does not exist"
        )

        def check(p) -> bool:
            if p.update is None:
                return True
            return getattr(p.update, field)

        return self._checker.can(check)

    def can_delete(self) -> bool:
        return self._checker.can(lambda p: p.delete)


class IdentityChecker:
    def __init__(
        self,
        boundaries: list[model.boundary.Boundary],
        roles: list[model.role.Role],
        identity_id: int | None = None,
        tag_id_list: list[int] | None = None,
        boundary_id_list: list[int] | None = None,
    ):
        def cmp(filter: model.grant.Filter) -> bool:
            if not isinstance(filter, model.grant.IdentityFilter):
                return False
            if filter.id is not None and filter.id != identity_id:
                return False
            if filter.tag_id_list is not None:
                if tag_id_list is None:
                    return False
                if not all(tag_id in tag_id_list for tag_id in filter.tag_id_list):
                    return False
            if filter.boundary_id_list is not None:
                if boundary_id_list is None:
                    return False
                if not all(boundary_id in boundary_id_list for boundary_id in filter.boundary_id_list):
                    return False
            return True

        self._checker = Checker(boundaries, roles, cmp)

    def can_create(self, tag_id_list: list[int], boundary_id_list: list[int]) -> bool:
        def check(p) -> bool:
            if not p.create.allowed:
                return False
            if p.create.allowed_tag_id_list is not None and not all(
                tag_id in p.create.allowed_tag_id_list for tag_id in tag_id_list
            ):
                return False
            if p.create.required_boundary_id_list is not None and not all(
                boundary_id in boundary_id_list for boundary_id in p.create.required_boundary_id_list
            ):
                # Note how the semantics of this are oh so very slightly different
                # from the semantics of allowed_tag_id_list because the above for loop
                # is looping over the REQUIRED items rather than the PROVIDED items.
                # the result is that required_boundary_id_list really behaves like
                # list of items that MUST be present in the PROVIDED list.
                # the reason why the two lists (allowed_tag vs required_boundary) behave
                # differently is because if you create an identity with more tags than
                # allowed, you might grant more power to this identity while if you
                # create an identity with more boundaries that required, you will merely
                # add more constraints on this identity.
                # So, creating identities with more tags is not safe while creating
                # identities with more boundaries is safe.
                # Where "safe" is defined as meaning: "not getting more permissions than
                # expected".
                # Another note: a side-effect of the required boundary semantics is that
                # specifying a required_boundary_id_list as None or as an empty list
                # is equivalent: both allow the user to provide any boundary or no boundary.
                return False
            return True

        return self._checker.can(check)

    def can_read(self) -> bool:
        return self._checker.can(lambda p: p.read)

    def can_update(self, field: str) -> bool:
        assert field == "name", "You are not allowed to update any field but the name field."

        def check(p) -> bool:
            if p.update is None:
                return True
            return getattr(p.update, field)

        return self._checker.can(check)

    def can_delete(self) -> bool:
        return self._checker.can(lambda p: p.delete)

    def can_add_tag(self, tag_id: int) -> bool:
        def check(p) -> bool:
            if p.add_tag_id_list is None:
                return True
            return tag_id in p.add_tag_id_list

        return self._checker.can(check)

    def can_del_tag(self, tag_id: int) -> bool:
        def check(p) -> bool:
            if p.del_tag_id_list is None:
                return True
            return tag_id in p.del_tag_id_list

        return self._checker.can(check)

    def can_invite(self, delivery: str) -> bool:
        def check(p) -> bool:
            if p.invite_list is None:
                return True
            return delivery in p.invite_list

        return self._checker.can(check)


class TenantChecker:
    def __init__(self, boundaries: list[model.boundary.Boundary], roles: list[model.role.Role], tenant_id: int | None):
        def cmp(filter: model.grant.Filter) -> bool:
            if not isinstance(filter, model.grant.TenantFilter):
                return False
            if filter.id is not None and filter.id != tenant_id:
                return False
            return True

        self._checker = Checker(boundaries, roles, cmp)

    def can_create(self) -> bool:
        return self._checker.can(lambda p: p.create)

    def can_read(self) -> bool:
        return self._checker.can(lambda p: p.read)

    def can_update(self, field: str) -> bool:
        assert field in ["display_name", "is_enabled"]

        def check(p) -> bool:
            if p.update is None:
                return True
            return getattr(p.update, field)

        return self._checker.can(check)

    def can_delete(self) -> bool:
        return self._checker.can(lambda p: p.delete)


class SSHChecker:
    def __init__(
        self,
        boundaries: list[model.boundary.Boundary],
        roles: list[model.role.Role],
        identity_id: int,
        tag_id_list: list[int],
        boundary_id_list: list[int],
    ):
        def cmp(filter: model.grant.Filter) -> bool:
            if not isinstance(filter, model.grant.SSHFilter):
                return False
            if filter.id is not None and filter.id != identity_id:
                return False
            if filter.tag_id_list is not None and not all(tag_id in tag_id_list for tag_id in filter.tag_id_list):
                return False
            if filter.boundary_id_list is not None and not all(
                boundary_id in boundary_id_list for boundary_id in filter.boundary_id_list
            ):
                return False
            return True

        self._checker = Checker(boundaries, roles, cmp)

    def can_shell(self, username: str) -> model.grant.SSHShellPermission | None:
        matching = [
            g
            for g in self._checker.list_can(
                lambda p: (
                    isinstance(p, model.grant.SSHShellPermission)
                    and (p.username_list is None or username in p.username_list)
                )
            )
            if isinstance(g, model.grant.SSHShellGrant)
        ]
        if not matching:
            return None
        return model.grant.SSHShellPermission(
            username_list=[username],
            permit_agent_forwarding=any(g.permission.permit_agent_forwarding for g in matching),
            permit_x11_forwarding=any(g.permission.permit_x11_forwarding for g in matching),
        )

    def can_port_forward(self, username: str) -> bool:
        return self._checker.can(
            lambda p: (
                isinstance(p, model.grant.SSHPortForwardingPermission)
                and (p.username_list is None or username in p.username_list)
            )
        )

    def can_command(self, username: str, command: str) -> bool:
        return self._checker.can(
            lambda p: (
                isinstance(p, model.grant.SSHCommandPermission)
                and (p.username_list is None or username in p.username_list)
                and command in p.command_list
            )
        )


class AuthChecker:
    def __init__(self, boundaries: list[model.boundary.Boundary], roles: list[model.role.Role], auth_id: int | None):
        def cmp(filter: model.grant.Filter) -> bool:
            if not isinstance(filter, model.grant.AuthFilter):
                return False
            if filter.id is not None and filter.id != auth_id:
                return False
            return True

        self._checker = Checker(boundaries, roles, cmp)

    def can_create(self) -> bool:
        return self._checker.can(lambda p: p.create)

    def can_read(self) -> bool:
        return self._checker.can(lambda p: p.read)

    def can_update(self, field: str) -> bool:
        assert field in ["name", "description", "is_enabled", "config"], (
            "You tried to update a field that does not exist"
        )

        def check(p) -> bool:
            if p.update is None:
                return True
            return getattr(p.update, field)

        return self._checker.can(check)

    def can_delete(self) -> bool:
        return self._checker.can(lambda p: p.delete)


class Grants:
    def __init__(self, boundaries, roles):
        self._boundaries = boundaries
        self._roles = roles

    @classmethod
    def create(cls) -> Grants:
        identity = ctx.db.identity.read_one(id=ctx.identity_id)
        assert identity is not None
        identity_boundaries = ctx.db.identity_boundary.read_all(identity_id=identity.id)
        assert len(identity_boundaries) > 0
        boundaries = model.boundary.read_all(id=[i.boundary_id for i in identity_boundaries])
        member_of = ctx.db.role_member.read_all(identity_id=identity.id)
        roles = model.role.read_all(id=list(set(member.role_id for member in member_of)))
        return Grants(boundaries, roles)

    def boundary(self, boundary_id: int | None) -> BoundaryChecker:
        return BoundaryChecker(self._boundaries, self._roles, boundary_id)

    def tag(self, tag_id: int | None) -> TagChecker:
        return TagChecker(self._boundaries, self._roles, tag_id)

    def role(self, role_id: int | None) -> RoleChecker:
        return RoleChecker(self._boundaries, self._roles, role_id)

    def identity(
        self,
        identity_id: int | None = None,
        tag_id_list: list[int] | None = None,
        boundary_id_list: list[int] | None = None,
    ) -> IdentityChecker:
        return IdentityChecker(self._boundaries, self._roles, identity_id, tag_id_list, boundary_id_list)

    def ssh(self, identity_id: int, tag_id_list: list[int], boundary_id_list: list[int]) -> SSHChecker:
        return SSHChecker(self._boundaries, self._roles, identity_id, tag_id_list, boundary_id_list)

    def tenant(self, tenant_id: int | None) -> TenantChecker:
        return TenantChecker(self._boundaries, self._roles, tenant_id)

    def auth(self, auth_id: int | None) -> AuthChecker:
        return AuthChecker(self._boundaries, self._roles, auth_id)
