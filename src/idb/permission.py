from . import permission_schema
from .context import ctx


class Verifier:
    def __init__(self):
        identity = ctx.db.identity.read_one(id=ctx.identity_id)
        assert identity is not None
        assert len(identity.boundaries) > 0
        boundaries = ctx.db.boundary.read_all(id=identity.boundaries)
        grants = ctx.db.role_grant.read_all(identity_id=identity.id)
        roles = ctx.db.role.read_all(id=list(set(g.role_id for g in grants)))
        self._denied = [permission_schema.Grant.from_dict(denied) for boundary in boundaries for denied in boundary.denies]
        self._allowed = [permission_schema.Grant.from_dict(permission) for role in roles for permission in role.permissions]

    def create_boundary_request(self, instance, action, **parameters) -> permission_schema.Request:
        return permission_schema.boundary.create_request(instance, action, **parameters)

    def is_allowed(self, request: permission_schema.Request) -> bool:
        if any(request.matches(denied) for denied in self._denied):
            return False
        if any(request.matches(allowed) for allowed in self._allowed):
            return True
        return False
