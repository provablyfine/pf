from __future__ import annotations

import collections.abc
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
                    allowed.append(g)  # pragma: no mutate — list_can's only caller, can(), reads len(allowed) only
        if len(allowed) == 0:  # pragma: no mutate — this condition only gates a log call, callers only read len()
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


def resolve_username(entry: str, unix_username: str | None) -> str | None:
    if entry == "{self}":
        return unix_username
    return entry


_ALL_SSH_CAPABILITIES = frozenset(model.grant.SSHCapability)


def _ssh_grants(grant_list: list[model.grant.Grant]) -> list[model.grant.SSHGrant]:
    return [g for g in grant_list if isinstance(g, model.grant.SSHGrant)]


def _capabilities(p: model.grant.SSHPermission) -> frozenset[model.grant.SSHCapability]:
    if p.capability_list is None:
        return _ALL_SSH_CAPABILITIES
    return frozenset(p.capability_list)


# Which entries apply to the session being decided. The username is the only
# thing an entry can discriminate on, so decisions differ only in this.
type _Covers = typing.Callable[[model.grant.SSHPermission], bool]


def _covers_username(p: model.grant.SSHPermission, username: str, unix_username: str | None) -> bool:
    if p.username_list is None:
        return True
    resolved = [r for e in p.username_list if (r := resolve_username(e, unix_username)) is not None]
    return username in resolved


def _covers_unnamed_username(p: model.grant.SSHPermission) -> bool:
    """Coverage for the group of usernames no entry names.

    An entry either names usernames or covers every one of them, so the only
    entries that reach a username nobody names are the latter. This is why the
    group resolves to a single exact decision rather than an approximation.
    """
    return p.username_list is None


def _ttl_max(a: int | None, b: int | None) -> int | None:
    if a is None:
        return None
    if b is None:
        return None
    return max(a, b)


def _ttl_min(a: int | None, b: int | None) -> int | None:
    if a is None:
        return b
    if b is None:
        return a
    return min(a, b)


def deadline(now: int, ttl_list: list[int | None]) -> int | None:
    """The absolute unix-seconds deadline for a credential embedding the given capability TTLs.

    None entries are unbounded and skipped. If every entry is unbounded, the
    session itself is unbounded, so the deadline is omitted (None).
    Otherwise the tightest bound wins: the deadline governs the whole
    session, which hosts every embedded capability.
    """
    bounded = [ttl for ttl in ttl_list if ttl is not None]
    if not bounded:
        return None
    return now + min(bounded)


class CapabilityTtl(collections.abc.Mapping[model.grant.SSHCapability, int | None]):
    """The session TTL bound of each granted capability.

    A capability is granted if and only if it has an entry. Entries with None
    values are unbounded. The bound is per capability because a
    grant of port-forwarding for 8h alongside a grant of shell for 1h must not
    give the shell session 8h.

    """

    def __init__(self, ttl: typing.Mapping[model.grant.SSHCapability, int | None]) -> None:
        self._ttl = ttl

    def __getitem__(self, capability: model.grant.SSHCapability) -> int | None:
        return self._ttl[capability]

    def __iter__(self) -> typing.Iterator[model.grant.SSHCapability]:
        return iter(self._ttl)

    def __len__(self) -> int:
        return len(self._ttl)

    @classmethod
    def allowed_by(cls, permissions: list[model.grant.SSHPermission]) -> CapabilityTtl:
        ttl: dict[model.grant.SSHCapability, int | None] = {}
        for p in permissions:
            for c in _capabilities(p):
                ttl[c] = p.max_session_ttl_s if c not in ttl else _ttl_max(ttl[c], p.max_session_ttl_s)
        return cls(ttl)

    def intersect(self, ceiling: CapabilityTtl) -> CapabilityTtl:
        return CapabilityTtl({c: _ttl_min(ttl, ceiling[c]) for c, ttl in self.items() if c in ceiling})

    def subtract(self, permissions: list[model.grant.SSHPermission]) -> CapabilityTtl:
        ttl = dict(self._ttl)
        for p in permissions:
            for c in _capabilities(p) & ttl.keys():
                if p.max_session_ttl_s is None:
                    del ttl[c]
                else:
                    ttl[c] = _ttl_min(ttl[c], p.max_session_ttl_s)
        return CapabilityTtl(ttl)


@dataclasses.dataclass(frozen=True)
class SSHCommandAllowed:
    ttl: int | None


# A command is permitted if and only if it has an SSHCommandAllowed: None means
# not permitted, which is not the same as a None ttl, which means unbounded.
def _covered_union(a: SSHCommandAllowed | None, b: SSHCommandAllowed | None) -> SSHCommandAllowed | None:
    if a is None:
        return b
    if b is None:
        return a
    return SSHCommandAllowed(_ttl_max(a.ttl, b.ttl))


def _covered_intersection(a: SSHCommandAllowed | None, b: SSHCommandAllowed | None) -> SSHCommandAllowed | None:
    if a is None or b is None:
        return None
    return SSHCommandAllowed(_ttl_min(a.ttl, b.ttl))


def _covered_deny(a: SSHCommandAllowed | None, ttl: int | None) -> SSHCommandAllowed | None:
    if a is None or ttl is None:
        return None
    return SSHCommandAllowed(_ttl_min(a.ttl, ttl))


class SSHCommandPermissions:
    """Which commands may be run, and the session TTL bound of each.

    We track this via two variables:
    - `_named` tracks per-command permissions
    - `_other` tracks default permissions that apply to commands not matched by `_named`.

    Examples:
    - `_named={"ls": SSHCommandAllowed(3600)}, _other=None` permits
      `ls` and nothing else
    - `_named={"ls": None}, _other=allowed` permits
      everything except `ls`.
    """

    def __init__(
        self,
        named: typing.Mapping[str, SSHCommandAllowed | None],  # None as a value means the command is denied.
        other: SSHCommandAllowed | None,  # None means all commands not matched via `named` are denied.
    ) -> None:
        self._named = named
        self._other = other

    @classmethod
    def allowed_by(cls, permissions: list[model.grant.SSHPermission]) -> SSHCommandPermissions:
        named: dict[str, SSHCommandAllowed | None] = {}
        other: SSHCommandAllowed | None = None
        for p in permissions:
            allowed = SSHCommandAllowed(p.max_session_ttl_s)
            if p.command_list is None:
                named = {c: _covered_union(a, allowed) for c, a in named.items()}
                other = _covered_union(other, allowed)
            else:
                for command in p.command_list:
                    # A command named here for the first time starts from what
                    # we already allow for every unnamed command.
                    named[command] = _covered_union(named.get(command, other), allowed)
        return cls(named, other)

    def intersect(self, ceiling: SSHCommandPermissions) -> SSHCommandPermissions:
        named = {c: _covered_intersection(self.permits(c), ceiling.permits(c)) for c in [*self._named, *ceiling._named]}
        return SSHCommandPermissions(named, _covered_intersection(self._other, ceiling._other))

    def subtract(self, permissions: list[model.grant.SSHPermission]) -> SSHCommandPermissions:
        named = dict(self._named)
        other = self._other
        for p in permissions:
            if p.command_list is None:
                named = {c: _covered_deny(a, p.max_session_ttl_s) for c, a in named.items()}
                other = _covered_deny(other, p.max_session_ttl_s)
            else:
                for command in p.command_list:
                    named[command] = _covered_deny(named.get(command, other), p.max_session_ttl_s)
        return SSHCommandPermissions(named, other)

    def permits(self, command: str) -> SSHCommandAllowed | None:
        return self._named.get(command, self._other)

    def candidates(self) -> tuple[list[str], bool]:
        """
        Returns the list of allowed commands as first member and whether
        or not all not-explicitely allowed commands are allowed or not
        """
        return [c for c, a in self._named.items() if a is not None], self._other is not None


@dataclasses.dataclass(frozen=True)
class SSHDecision:
    """
    SSH permission for one (host, username) pair.
    """

    commands: SSHCommandPermissions
    capability_ttl: CapabilityTtl

    @property
    def capabilities(self) -> frozenset[model.grant.SSHCapability]:
        return frozenset(self.capability_ttl)


class SSHChecker:
    def __init__(
        self,
        boundaries: list[model.boundary.Boundary],
        roles: list[model.role.Role],
        identity_id: int,
        tag_id_list: list[int],
        boundary_id_list: list[int],
    ):
        def matching(grant_list: list[model.grant.Grant]) -> list[model.grant.SSHGrant]:
            return [g for g in _ssh_grants(grant_list) if triplet_match(g, identity_id, tag_id_list, boundary_id_list)]

        # The triplet filter does not depend on the username, so it is resolved
        # once here instead of on every decide().
        self._granted = [g for role in roles for g in matching(role.grant_list)]
        self._ceilings = [matching(b.ceiling_list) for b in boundaries if b.ceiling_list is not None]
        self._denied = [g for b in boundaries for g in matching(b.denied_list)]

    @staticmethod
    def _covering(grants: list[model.grant.SSHGrant], covers: _Covers) -> list[model.grant.SSHPermission]:
        return [g.permission for g in grants if covers(g.permission)]

    def _decide(self, covers: _Covers, username: str | None) -> SSHDecision:
        # role grants
        granted = self._covering(self._granted, covers)
        if not granted:  # pragma: no mutate — this condition only gates a log call
            # None is the group of usernames no entry names
            logger.info(f"no ssh grant covers username={'*' if username is None else username}")
        ttl_by_cap = CapabilityTtl.allowed_by(granted)
        commands = SSHCommandPermissions.allowed_by(granted)

        # boundary ceiling_list
        for ceiling in self._ceilings:
            covering = self._covering(ceiling, covers)
            ttl_by_cap = ttl_by_cap.intersect(CapabilityTtl.allowed_by(covering))
            commands = commands.intersect(SSHCommandPermissions.allowed_by(covering))

        # boundary denied_list
        denied = self._covering(self._denied, covers)
        ttl_by_cap = ttl_by_cap.subtract(denied)
        commands = commands.subtract(denied)

        return SSHDecision(commands=commands, capability_ttl=ttl_by_cap)

    def decide(self, username: str, unix_username: str | None) -> SSHDecision:
        def covers(p: model.grant.SSHPermission) -> bool:
            return _covers_username(p, username, unix_username)

        return self._decide(covers, username)  # pragma: no mutate — username here is log-only, see _decide

    def _candidate_usernames(self, unix_username: str | None) -> tuple[list[str], bool]:
        """Usernames worth calling decide() on, plus whether a wildcard grant exists.
        Ordered by first appearance, because these end up on screen.
        """
        usernames: list[str] = []
        wildcard = False  # pragma: no mutate — mutant only swaps False for None (equally falsy for the
        # sole `if wildcard:` read below); a swap to True is a real, already-killed mutant
        # (test_ssh_list_decisions asserts no extra (None, ...) decision without a wildcard grant).
        for g in self._granted:
            if g.permission.username_list is None:
                wildcard = True
                continue
            for entry in g.permission.username_list:
                resolved = resolve_username(entry, unix_username)
                if resolved is not None and resolved not in usernames:
                    usernames.append(resolved)
        return usernames, wildcard

    def list_decisions(self, unix_username: str | None) -> list[tuple[str | None, SSHDecision]]:
        """Decisions for enumeration: one per candidate username, plus one for
        "any other username" (key None) when a wildcard grant exists.
        """
        usernames, wildcard = self._candidate_usernames(unix_username)
        output: list[tuple[str | None, SSHDecision]] = [(u, self.decide(u, unix_username)) for u in usernames]
        if wildcard:
            output.append((None, self._decide(_covers_unnamed_username, None)))
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
        assert field in ["url", "ssh_proxy_jump", "tag_list"], (
            # Message kept on its own physical line: do_not_mutate_patterns in
            # pyproject.toml excludes the line matching this message text from
            # mutation, so splitting it out keeps that exclusion from also
            # swallowing the field-list literal above, which stays
            # mutation-tested (asserted per-field by
            # test_filter_all_bastion/test_filter_one_bastion/test_empty_bastion).
            "You tried to update a field that does not exist"
        )

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
