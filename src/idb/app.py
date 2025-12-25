import contextlib
import types
import json
import datetime
import urllib.parse
import hashlib

import sqlalchemy
import cryptography.fernet
import http_message_signatures

from . import wa
from . import config
from . import db
from . import decorators
from . import openapi
from . import model
from . import base64url
from . import jwk
from . import signature



def idb_directory(request):
    return wa.JSONResponse(status_code=200, json={
        'initialize': f'{request.app.config.base_url}/idb/initialize',
        'accept-invitation': f'{request.app.config.base_url}/idb/accept-invitation',
    })



@decorators.transaction
def idb_initialize(request):
    one = request.state.dao.identity.read_one()
    if one is not None:
        return wa.Response(
            status_code=204
        )
    root_boundary = model.Boundary.create(name='Root Boundary', description='The Root boundary is not a boundary at all.')
    restricted_boundary = model.Boundary.create(name='Restricted Boundary', description='The Restricted boundary does not allow anything')
    for deny in ['identity:*', 'role:*', 'group:*', 'tag:*', 'boundary:*']:
        restricted_boundary.add_deny(deny)
    root = model.Identity.create(name='root', boundary_id=root_boundary.id)
    root_role = model.Role.create(name='root', description='The "root" role identifies a user that is able to do anything. It is created once at startup and should be deleted once a proper permission model is deployed.')
    root_role.add_permission('*:*')
    ii = model.IdentityInvitation.create(identity_id=root.id, expiration_delay_s=600)

    request.state.dao.boundary.create(id=root_boundary.id, boundary=root_boundary.serialize())
    request.state.dao.boundary.create(id=restricted_boundary.id, boundary=restricted_boundary.serialize())
    request.state.dao.default.create(boundary_id=restricted_boundary.id)
    request.state.dao.identity.create(id=root.id, identity=root.serialize())
    request.state.dao.role.create(id=root_role.id, role=root_role.serialize())
    request.state.dao.role_identity_grant.create(role_id=root_role.id, identity_id=root.id)
    request.state.dao.identity_invitation.create(id=ii.id, identity_invitation=ii.serialize(request.app.state.kek))
    
    for o in [root_boundary, restricted_boundary, root, root_role, ii]:
        for log in o.audit_log:
            request.state.dao.audit_log.create(log=log.serialize(None))
    return wa.JSONResponse(
        json=ii.format(),
        status_code=200
    )


@decorators.transaction
@signature.verify_invitation
def idb_accept_invitation(request) -> wa.Response:
    data = json.loads(request.body)
    invitation = model.IdentityInvitation.from_id(request.state.dao, data['key_id'], request.app.state.kek)
    if invitation is None:
        return wa.ProblemResponse(status_code=400, title=f'Invitation does not exist', detail=data['key_id'])
    if invitation.is_accepted:
        return wa.ProblemResponse(status_code=400, title=f'Invitation was already accepted. Get a new one.')
    if invitation.is_expired:
        return wa.ProblemResponse(status_code=400, title=f'Invitation is expired. Get a new one.')

    signature.verify(request, jwk.Public.from_dict(data['account_public_key']))

#    invitation.accept()
#    request.state.dao.identity_invitation.update(identity_invitation=invitation.serialize(request.app.state.kek)).where(id=invitation.id)
#    request.state.dao.identity_key.create(
#        
#    )
    print(data)
    #print(list(request.headers.items()))
    #pass
    return wa.Response(
        status_code=204
    )


@contextlib.contextmanager
def lifespan(config: config.Config, state: types.SimpleNamespace):
    engine = sqlalchemy.create_engine(config.database_url, echo=config.debug_sql)
    with open(config.kek_filename, 'rb') as f:
        kek = base64url.encode(f.read()) + '======'
        kek = cryptography.fernet.Fernet(kek)
    state.db_engine = engine
    state.kek = kek
    yield


def create(filename):
    conf = config.Config.load(filename)
    db.create_tables(conf.database_url)
    middlewares = [
        wa.debug_store.DebugStoreMiddleware(wa.debug_store.InMemoryDebugStore()),
#        wa.backtrace.BacktraceMiddleware(),
        openapi.create_middleware(conf.base_url),
    ]
    app = wa.Application(config=conf, middlewares=middlewares, lifespan=lifespan, debug=conf.debug)
    app.add('/idb/directory', idb_directory, methods=['GET'])
    app.add('/idb/initialize', idb_initialize, methods=['POST'])
    app.add('/idb/accept-invitation', idb_accept_invitation, methods=['POST'])
    return app
