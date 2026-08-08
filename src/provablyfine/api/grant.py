from __future__ import annotations

import dataclasses
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
        assert field in ("name", "unix_username"), f"Unknown identity update field: {field}"

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


def triplet_match(
    g: model.grant.TripletGrant,
    identity_id: int,
    tag_id_list: list[int],
    boundary_id_list: list[int],
) -> bool:
    if g.filter.id is not None and g.filter.id != identity_id:
        return False
    if g.filter.tag_id_list is not None and not all(tag_id in tag_id_list for tag_id in g.filter.tag_id_list):
        return False
    if g.filter.boundary_id_list is not None and not all(
        boundary_id in boundary_id_list for boundary_id in g.filter.boundary_id_list
    ):
        return False
    return True


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
            return triplet_match(g, identity_id, tag_id_list, boundary_id_list)

        super().__init__(boundaries, roles, cmp, cls)


def resolve_username(entry: str, unix_username: str | None) -> str | None:
    if entry == "{self}":
        return unix_username
    return entry


_ALL_SSH_CAPABILITIES = frozenset(model.grant.SSHCapability)

# None denotes the whole command axis (any command). Ordered rather than a set:
# `/ssh/hosts` displays these, and grant order is what an administrator wrote.
type _CommandSet = tuple[str, ...] | None


def _ssh_grants(grant_list: list[model.grant.Grant]) -> list[model.grant.SSHGrant]:
    return [g for g in grant_list if isinstance(g, model.grant.SSHGrant)]


def _capabilities(p: model.grant.SSHPermission) -> frozenset[model.grant.SSHCapability]:
    if p.capability_list is None:
        return _ALL_SSH_CAPABILITIES
    return frozenset(p.capability_list)


def _commands(p: model.grant.SSHPermission) -> _CommandSet:
    if p.command_list is None:
        return None
    return tuple(p.command_list)


def _covers_username(p: model.grant.SSHPermission, username: str, unix_username: str | None) -> bool:
    if p.username_list is None:
        return True
    resolved = [r for e in p.username_list if (r := resolve_username(e, unix_username)) is not None]
    return username in resolved


def _covers_command(entries: tuple[_CommandSet, ...], command: str) -> bool:
    return any(e is None or command in e for e in entries)


@dataclasses.dataclass(frozen=True)
class _CommandAxis:
    """Command patterns captured per layer, evaluated per command.

    Capabilities are a finite universe and are materialized eagerly, but
    commands are not: a grant of every command minus a deny of "rm" is a
    cofinite set. So the same union/intersect/subtract structure is kept as a
    predicate instead.
    """

    granted: tuple[_CommandSet, ...]
    ceilings: tuple[tuple[_CommandSet, ...] | None, ...]  # one entry per boundary; None = no ceiling
    denied: tuple[_CommandSet, ...]

    def permits(self, command: str) -> bool:
        if not _covers_command(self.granted, command):
            return False
        for ceiling in self.ceilings:
            if ceiling is not None and not _covers_command(ceiling, command):
                return False
        return not _covers_command(self.denied, command)

    def candidates(self) -> tuple[list[str], bool]:
        """The permitted commands that can be enumerated, in grant order, plus
        whether a grant covers the whole axis (in which case the permitted set
        is cofinite and cannot be listed)."""
        output: list[str] = []
        for entry in self.granted:
            if entry is None:
                continue
            for command in entry:
                if command not in output and self.permits(command):
                    output.append(command)
        return output, any(entry is None for entry in self.granted)


@dataclasses.dataclass(frozen=True)
class SSHDecision:
    """Resolution of the SSH policy for one (host, username) pair.

    Deliberately not a pydantic schema: a decision is not policy. It has no
    type tag, no filter and no wildcards, and cannot be serialized back into a
    grant_list, ceiling_list or denied_list.
    """

    capabilities: frozenset[model.grant.SSHCapability]
    commands: _CommandAxis

    def permits_command(self, command: str) -> bool:
        return self.commands.permits(command)

    def candidate_commands(self) -> tuple[list[str], bool]:
        return self.commands.candidates()


class SSHChecker:
    def __init__(
        self,
        boundaries: list[model.boundary.Boundary],
        roles: list[model.role.Role],
        identity_id: int,
        tag_id_list: list[int],
        boundary_id_list: list[int],
    ):
        self._boundaries = boundaries
        self._roles = roles
        self._identity_id = identity_id
        self._tag_id_list = tag_id_list
        self._boundary_id_list = boundary_id_list

    def _matching(self, grant_list: list[model.grant.Grant]) -> list[model.grant.SSHGrant]:
        return [
            g
            for g in _ssh_grants(grant_list)
            if triplet_match(g, self._identity_id, self._tag_id_list, self._boundary_id_list)
        ]

    def _covering(
        self, grant_list: list[model.grant.Grant], username: str, unix_username: str | None
    ) -> list[model.grant.SSHPermission]:
        return [
            g.permission for g in self._matching(grant_list) if _covers_username(g.permission, username, unix_username)
        ]

    def decide(self, username: str, unix_username: str | None) -> SSHDecision:
        granted: list[model.grant.SSHPermission] = []
        for role in self._roles:
            granted += self._covering(role.grant_list, username, unix_username)
        capabilities = frozenset[model.grant.SSHCapability]().union(*(_capabilities(p) for p in granted))
        commands_granted = tuple(_commands(p) for p in granted)

        ceilings: list[tuple[_CommandSet, ...] | None] = []
        commands_denied: list[_CommandSet] = []
        for boundary in self._boundaries:
            if boundary.ceiling_list is None:
                ceilings.append(None)
            else:
                # Ceiling entries union first, then intersect; an atom no entry
                # covers is denied.
                covering = self._covering(boundary.ceiling_list, username, unix_username)
                capabilities &= frozenset[model.grant.SSHCapability]().union(*(_capabilities(p) for p in covering))
                ceilings.append(tuple(_commands(p) for p in covering))
            # A deny is targeted: it removes only the atoms it covers.
            for p in self._covering(boundary.denied_list, username, unix_username):
                capabilities -= _capabilities(p)
                commands_denied.append(_commands(p))

        if not capabilities and not commands_granted:
            logger.info(f"no ssh grant covers username={username}")
        return SSHDecision(
            capabilities=capabilities,
            commands=_CommandAxis(granted=commands_granted, ceilings=tuple(ceilings), denied=tuple(commands_denied)),
        )

    def candidate_usernames(self, unix_username: str | None) -> tuple[list[str], bool]:
        """Usernames worth calling decide() on, plus whether a wildcard grant exists.

        Only role grants are considered, and boundaries are deliberately not
        applied: this enumerates candidates, it does not authorize them. A
        grant with username_list None cannot be enumerated at all, hence the
        flag. Ordered by first appearance, because these end up on screen.
        """
        usernames: list[str] = []
        wildcard = False
        for role in self._roles:
            for g in self._matching(role.grant_list):
                if g.permission.username_list is None:
                    wildcard = True
                    continue
                for entry in g.permission.username_list:
                    resolved = resolve_username(entry, unix_username)
                    if resolved is not None and resolved not in usernames:
                        usernames.append(resolved)
        return usernames, wildcard

    def _named_usernames(self, unix_username: str | None) -> set[str]:
        grant_lists = [role.grant_list for role in self._roles]
        for boundary in self._boundaries:
            if boundary.ceiling_list is not None:
                grant_lists.append(boundary.ceiling_list)
            grant_lists.append(boundary.denied_list)
        names: set[str] = set()
        for grant_list in grant_lists:
            for g in self._matching(grant_list):
                for entry in g.permission.username_list or []:
                    if (resolved := resolve_username(entry, unix_username)) is not None:
                        names.add(resolved)
        return names

    def list_decisions(self, unix_username: str | None) -> list[tuple[str | None, SSHDecision]]:
        """Decisions for enumeration: one per candidate username, plus one for
        "any other username" (key None) when a wildcard grant exists.

        The wildcard decision is exact, not an approximation: the only
        username-sensitivity in the algebra is exact membership in a resolved
        username_list, so every username named by no entry -- in a grant, a
        ceiling or a deny -- resolves identically.
        """
        usernames, wildcard = self.candidate_usernames(unix_username)
        output: list[tuple[str | None, SSHDecision]] = [(u, self.decide(u, unix_username)) for u in usernames]
        if wildcard:
            named = self._named_usernames(unix_username)
            unnamed = "*"
            while unnamed in named:
                unnamed += "*"
            output.append((None, self.decide(unnamed, unix_username)))
        return output


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


class BastionChecker:
    def __init__(self, boundaries: list[model.boundary.Boundary], roles: list[model.role.Role], bastion_id: int | None):
        def cmp(g: model.grant.BastionGrant) -> bool:
            if g.filter.id is not None and g.filter.id != bastion_id:
                return False
            return True

        self._checker = Checker[model.grant.BastionGrant](boundaries, roles, cmp, model.grant.BastionGrant)

    def can_create(self) -> bool:
        def check(g: model.grant.BastionGrant):
            return g.permission.create

        return self._checker.can(check)

    def can_read(self) -> bool:
        def check(g: model.grant.BastionGrant):
            return g.permission.read

        return self._checker.can(check)

    def can_update(self, field: str) -> bool:
        assert field in ["url", "ssh_proxy_jump", "tag_list"], "You tried to update a field that does not exist"

        def check(g: model.grant.BastionGrant) -> bool:
            if g.permission.update is None:
                return True
            return getattr(g.permission.update, field)

        return self._checker.can(check)

    def can_delete(self) -> bool:
        def check(g: model.grant.BastionGrant):
            return g.permission.delete

        return self._checker.can(check)


class AuditLogChecker:
    def __init__(self, boundaries: list[model.boundary.Boundary], roles: list[model.role.Role]):
        self._checker = Checker[model.grant.AuditLogGrant](boundaries, roles, lambda g: True, model.grant.AuditLogGrant)

    def can_read(self) -> bool:
        def check(g: model.grant.AuditLogGrant) -> bool:
            return g.permission.read

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

    def ssh(self, identity_id: int, tag_id_list: list[int], boundary_id_list: list[int]) -> SSHChecker:
        return SSHChecker(self._boundaries, self._roles, identity_id, tag_id_list, boundary_id_list)

    def tenant(self, tenant_id: int | None) -> TenantChecker:
        return TenantChecker(self._boundaries, self._roles, tenant_id)

    def auth(self, auth_id: int | None) -> AuthChecker:
        return AuthChecker(self._boundaries, self._roles, auth_id)

    def bastion(self, bastion_id: int | None) -> BastionChecker:
        return BastionChecker(self._boundaries, self._roles, bastion_id)

    def audit_log(self) -> AuditLogChecker:
        return AuditLogChecker(self._boundaries, self._roles)
