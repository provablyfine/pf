import collections
import logging

from . import permission_schema
from . import wa
from .context import ctx
from . import model


logger = logging.getLogger(__name__)


class Verifier:
    def __init__(self):
        identity = ctx.db.identity.read_one(id=ctx.identity_id)
        assert identity is not None
        identity_boundaries = ctx.db.identity_boundary.read_all(identity_id=identity.id)
        assert len(identity_boundaries) > 0
        self._boundaries = model.boundary.read_all(id=[i.boundary_id for i in identity_boundaries])
        grants = ctx.db.role_grant.read_all(identity_id=identity.id)
        self._roles = model.role.read_all(id=list(set(g.role_id for g in grants)))

    def create_boundary_request(self, instance, action, **parameters) -> permission_schema.Request:
        return permission_schema.boundary.create_request(instance, action, **parameters)

    def is_allowed(self, request: permission_schema.Request) -> bool:
        logger.info(f'is_allowed("{request}")')
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
