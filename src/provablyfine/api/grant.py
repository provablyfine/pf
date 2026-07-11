from __future__ import annotations

import logging
import typing

from . import model
from .context import ctx

logger = logging.getLogger(__name__)


class Checker[G]:
    def __init__(
        self,
        boundaries: list[model.boundary.Boundary],
        roles: list[model.role.Role],
        filter: typing.Callable[[G], bool],
        cls: type[G],
    ):
        self._boundaries = boundaries
        self._roles = roles
        self._filter = filter
        self._cls = cls

    def list_can(self, cmp: typing.Callable[[G], bool]) -> list[G]:
        for boundary in self._boundaries:
            if any(isinstance(g, self._cls) and self._filter(g) and cmp(g) for g in boundary.denied_list):
                logger.info(f"request denied by boundary id={boundary.id}")
                return []

            if boundary.ceiling_list is not None and not any(
                isinstance(g, self._cls) and self._filter(g) and cmp(g) for g in boundary.ceiling_list
            ):
                logger.info(f"request above ceiling of boundary id={boundary.id}")
                return []
        allowed: list[G] = []
        for role in self._roles:
            for g in role.grant_list:
                if isinstance(g, self._cls) and self._filter(g) and cmp(g):
                    allowed.append(g)
        if len(allowed) == 0:
            logger.info("request not allowed by any role")
        return allowed

    def can(self, cmp: typing.Callable[[G], bool]) -> bool:
        allowed = self.list_can(cmp)
        return len(allowed) > 0


class TagChecker:
    def __init__(self, boundaries: list[model.boundary.Boundary], roles: list[model.role.Role], tag_id: int | None):
        def cmp(g: model.grant.TagGrant) -> bool:
            if g.filter.id is not None and g.filter.id != tag_id:
                return False
            return True

        self._checker = Checker[model.grant.TagGrant](boundaries, roles, cmp, model.grant.TagGrant)

    def can_create(self) -> bool:
        def check(g: model.grant.TagGrant):
            return g.permission.create

        return self._checker.can(check)

    def can_read(self) -> bool:
        def check(g: model.grant.TagGrant):
            return g.permission.read

        return self._checker.can(check)

    def can_delete(self) -> bool:
        def check(g: model.grant.TagGrant):
            return g.permission.delete

        return self._checker.can(check)


class BoundaryChecker:
    def __init__(
        self, boundaries: list[model.boundary.Boundary], roles: list[model.role.Role], boundary_id: int | None
    ):
        def cmp(g: model.grant.BoundaryGrant) -> bool:
            if g.filter.id is not None and g.filter.id != boundary_id:
                return False
            return True

        self._checker = Checker[model.grant.BoundaryGrant](boundaries, roles, cmp, model.grant.BoundaryGrant)

    def can_create(self) -> bool:
        def check(g: model.grant.BoundaryGrant):
            return g.permission.create

        return self._checker.can(check)

    def can_read(self) -> bool:
        def check(g: model.grant.BoundaryGrant):
            return g.permission.read

        return self._checker.can(check)

    def can_update(self, field: str) -> bool:
        assert field in ["name", "description", "denied_list", "ceiling_list"], (
            "You tried to update a field that does not exist"
        )

        def check(g: model.grant.BoundaryGrant) -> bool:
            if g.permission.update is None:
                return True
            return getattr(g.permission.update, field)

        return self._checker.can(check)

    def can_delete(self) -> bool:
        def check(g: model.grant.BoundaryGrant):
            return g.permission.delete

        return self._checker.can(check)


class RoleChecker:
    def __init__(self, boundaries: list[model.boundary.Boundary], roles: list[model.role.Role], role_id: int | None):
        def cmp(g: model.grant.RoleGrant) -> bool:
            if g.filter.id is not None and g.filter.id != role_id:
                return False
            return True

        self._checker = Checker[model.grant.RoleGrant](boundaries, roles, cmp, model.grant.RoleGrant)

    def can_create(self) -> bool:
        def check(g: model.grant.RoleGrant) -> bool:
            return g.permission.create

        return self._checker.can(check)

    def can_read(self) -> bool:
        def check(g: model.grant.RoleGrant) -> bool:
            return g.permission.read

        return self._checker.can(check)

    def can_update(self, field: str) -> bool:
        assert field in ["name", "description", "member_list", "grant_list"], (
            "You tried to update a field that does not exist"
        )

        def check(g: model.grant.RoleGrant) -> bool:
            if g.permission.update is None:
                return True
            return getattr(g.permission.update, field)

        return self._checker.can(check)

    def can_delete(self) -> bool:
        def check(g: model.grant.RoleGrant) -> bool:
            return g.permission.delete

        return self._checker.can(check)


class IdentityChecker:
    def __init__(
        self,
        boundaries: list[model.boundary.Boundary],
        roles: list[model.role.Role],
        identity_id: int | None = None,
        tag_id_list: list[int] | None = None,
        boundary_id_list: list[int] | None = None,
    ):
        def cmp(g: model.grant.IdentityGrant) -> bool:
            if g.filter.id is not None and g.filter.id != identity_id:
                return False
            if g.filter.tag_id_list is not None:
                if tag_id_list is None:
                    return False
                if not all(tag_id in tag_id_list for tag_id in g.filter.tag_id_list):
                    return False
            if g.filter.boundary_id_list is not None:
                if boundary_id_list is None:
                    return False
                if not all(boundary_id in boundary_id_list for boundary_id in g.filter.boundary_id_list):
                    return False
            return True

        self._checker = Checker[model.grant.IdentityGrant](boundaries, roles, cmp, model.grant.IdentityGrant)

    def can_create(self, tag_id_list: list[int], boundary_id_list: list[int]) -> bool:
        def check(g: model.grant.IdentityGrant) -> bool:
            if g.permission.create is None:
                return True
            if not g.permission.create.allowed:
                return False
            if g.permission.create.allowed_tag_id_list is not None and not all(
                tag_id in g.permission.create.allowed_tag_id_list for tag_id in tag_id_list
            ):
                return False
            if g.permission.create.required_boundary_id_list is not None and not all(
                boundary_id in boundary_id_list for boundary_id in g.permission.create.required_boundary_id_list
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
        def check(g: model.grant.IdentityGrant) -> bool:
            return g.permission.read

        return self._checker.can(check)

    def can_update(self, field: str) -> bool:
        assert field == "name", "You are not allowed to update any field but the name field."

        def check(g: model.grant.IdentityGrant) -> bool:
            if g.permission.update is None:
                return True
            return getattr(g.permission.update, field)

        return self._checker.can(check)

    def can_delete(self) -> bool:
        def check(g: model.grant.IdentityGrant) -> bool:
            return g.permission.delete

        return self._checker.can(check)

    def can_add_tag(self, tag_id: int) -> bool:
        def check(g: model.grant.IdentityGrant) -> bool:
            if g.permission.add_tag_id_list is None:
                return True
            return tag_id in g.permission.add_tag_id_list

        return self._checker.can(check)

    def can_del_tag(self, tag_id: int) -> bool:
        def check(g: model.grant.IdentityGrant) -> bool:
            if g.permission.del_tag_id_list is None:
                return True
            return tag_id in g.permission.del_tag_id_list

        return self._checker.can(check)

    def can_invite(self, delivery: str) -> bool:
        def check(g: model.grant.IdentityGrant) -> bool:
            if g.permission.invite_list is None:
                return True
            return delivery in g.permission.invite_list

        return self._checker.can(check)


class TenantChecker:
    def __init__(self, boundaries: list[model.boundary.Boundary], roles: list[model.role.Role], tenant_id: int | None):
        def cmp(g: model.grant.TenantGrant) -> bool:
            if g.filter.id is not None and g.filter.id != tenant_id:
                return False
            return True

        self._checker = Checker[model.grant.TenantGrant](boundaries, roles, cmp, model.grant.TenantGrant)

    def can_create(self) -> bool:
        def check(g: model.grant.TenantGrant):
            return g.permission.create

        return self._checker.can(check)

    def can_read(self) -> bool:
        def check(g: model.grant.TenantGrant):
            return g.permission.read

        return self._checker.can(check)

    def can_update(self, field: str) -> bool:
        assert field in ["display_name", "is_enabled"]

        def check(g: model.grant.TenantGrant):
            if g.permission.update is None:
                return True
            return getattr(g.permission.update, field)

        return self._checker.can(check)

    def can_delete(self) -> bool:
        def check(g: model.grant.TenantGrant):
            return g.permission.delete

        return self._checker.can(check)


class IdentityFilterChecker[G: model.grant.TripletGrant](Checker[G]):
    def __init__(
        self,
        boundaries: list[model.boundary.Boundary],
        roles: list[model.role.Role],
        identity_id: int,
        tag_id_list: list[int],
        boundary_id_list: list[int],
        cls: type[G],
    ):
        def cmp(g: G) -> bool:
            if g.filter.id is not None and g.filter.id != identity_id:
                return False
            if g.filter.tag_id_list is not None and not all(tag_id in tag_id_list for tag_id in g.filter.tag_id_list):
                return False
            if g.filter.boundary_id_list is not None and not all(
                boundary_id in boundary_id_list for boundary_id in g.filter.boundary_id_list
            ):
                return False
            return True

        super().__init__(boundaries, roles, cmp, cls)


class SSHShellChecker:
    def __init__(
        self,
        boundaries: list[model.boundary.Boundary],
        roles: list[model.role.Role],
        identity_id: int,
        tag_id_list: list[int],
        boundary_id_list: list[int],
    ):
        self._checker = IdentityFilterChecker[model.grant.SSHShellGrant](
            boundaries, roles, identity_id, tag_id_list, boundary_id_list, model.grant.SSHShellGrant
        )

    def can(self, username: str) -> model.grant.SSHShellPermission | None:
        def check(g: model.grant.SSHShellGrant) -> bool:
            return username in g.permission.username_list

        matching = [g for g in self._checker.list_can(check)]
        if not matching:
            return None
        return model.grant.SSHShellPermission(
            username_list=[username],
            permit_agent_forwarding=any(g.permission.permit_agent_forwarding for g in matching),
            permit_x11_forwarding=any(g.permission.permit_x11_forwarding for g in matching),
        )

    def list_can(self) -> list[model.grant.SSHShellGrant]:
        def check(g: model.grant.SSHShellGrant) -> bool:
            return True

        return [g for g in self._checker.list_can(check)]


class SSHPortForwardChecker:
    def __init__(
        self,
        boundaries: list[model.boundary.Boundary],
        roles: list[model.role.Role],
        identity_id: int,
        tag_id_list: list[int],
        boundary_id_list: list[int],
    ):
        self._checker = IdentityFilterChecker[model.grant.SSHPortForwardingGrant](
            boundaries, roles, identity_id, tag_id_list, boundary_id_list, model.grant.SSHPortForwardingGrant
        )

    def can(self, username: str) -> bool:
        def check(g: model.grant.SSHPortForwardingGrant) -> bool:
            return username in g.permission.username_list

        return self._checker.can(check)

    def list_can(self) -> list[model.grant.SSHPortForwardingGrant]:
        def check(g: model.grant.SSHPortForwardingGrant) -> bool:
            return True

        return self._checker.list_can(check)


class SSHCommandChecker:
    def __init__(
        self,
        boundaries: list[model.boundary.Boundary],
        roles: list[model.role.Role],
        identity_id: int,
        tag_id_list: list[int],
        boundary_id_list: list[int],
    ):
        self._checker = IdentityFilterChecker[model.grant.SSHCommandGrant](
            boundaries, roles, identity_id, tag_id_list, boundary_id_list, model.grant.SSHCommandGrant
        )

    def can(self, username: str, command: str) -> bool:
        def check(g: model.grant.SSHCommandGrant) -> bool:
            return username in g.permission.username_list and command in g.permission.command_list

        return self._checker.can(check)

    def list_can(self) -> list[model.grant.SSHCommandGrant]:
        def check(g: model.grant.SSHCommandGrant) -> bool:
            return True

        return self._checker.list_can(check)


class AuthChecker:
    def __init__(self, boundaries: list[model.boundary.Boundary], roles: list[model.role.Role], auth_id: int | None):
        def cmp(g: model.grant.AuthGrant) -> bool:
            if g.filter.id is not None and g.filter.id != auth_id:
                return False
            return True

        self._checker = Checker[model.grant.AuthGrant](boundaries, roles, cmp, model.grant.AuthGrant)

    def can_create(self) -> bool:
        def check(g: model.grant.AuthGrant) -> bool:
            return g.permission.create

        return self._checker.can(check)

    def can_read(self) -> bool:
        def check(g: model.grant.AuthGrant) -> bool:
            return g.permission.read

        return self._checker.can(check)

    def can_update(self, field: str) -> bool:
        assert field in ["name", "description", "is_enabled", "config"], (
            "You tried to update a field that does not exist"
        )

        def check(g: model.grant.AuthGrant) -> bool:
            if g.permission.update is None:
                return True
            return getattr(g.permission.update, field)

        return self._checker.can(check)

    def can_delete(self) -> bool:
        def check(g: model.grant.AuthGrant) -> bool:
            return g.permission.delete

        return self._checker.can(check)


class Grants:
    def __init__(self, boundaries: list[model.boundary.Boundary], roles: list[model.role.Role]):
        self._boundaries = boundaries
        self._roles = roles

    @classmethod
    def create(cls) -> Grants:
        identity = ctx.app_db.identity.read_one(id=ctx.identity_id)
        assert identity is not None
        identity_boundaries = ctx.app_db.identity_boundary.read_all(identity_id=identity.id)
        assert len(identity_boundaries) > 0
        boundaries = model.boundary.read_all(id=[i.boundary_id for i in identity_boundaries])
        if ctx.active_role_id is None:
            roles: list[model.role.Role] = []
        else:
            roles = model.role.read_all(id=[ctx.active_role_id])
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

    def ssh_shell(self, identity_id: int, tag_id_list: list[int], boundary_id_list: list[int]) -> SSHShellChecker:
        return SSHShellChecker(self._boundaries, self._roles, identity_id, tag_id_list, boundary_id_list)

    def ssh_port_forward(
        self, identity_id: int, tag_id_list: list[int], boundary_id_list: list[int]
    ) -> SSHPortForwardChecker:
        return SSHPortForwardChecker(self._boundaries, self._roles, identity_id, tag_id_list, boundary_id_list)

    def ssh_command(self, identity_id: int, tag_id_list: list[int], boundary_id_list: list[int]) -> SSHCommandChecker:
        return SSHCommandChecker(self._boundaries, self._roles, identity_id, tag_id_list, boundary_id_list)

    def tenant(self, tenant_id: int | None) -> TenantChecker:
        return TenantChecker(self._boundaries, self._roles, tenant_id)

    def auth(self, auth_id: int | None) -> AuthChecker:
        return AuthChecker(self._boundaries, self._roles, auth_id)
