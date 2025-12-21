import contextlib

import starlette.applications
import starlette.responses
import starlette.routing
import databases

from . import config
from . import db
from . import dao_factory
from . import decorators
from . import openapi


async def admin_directory(request):
    return starlette.responses.JSONResponse({
        'initialize': f'{config.BASE_URL}/admin/initialize',
    })


@decorators.transaction
async def admin_initialize(request):
    return starlette.responses.JSONResponse(
        {},
        status_code=200
    )


@contextlib.asynccontextmanager
async def lifespan(app):
    database = databases.Database(config.DATABASE_URL)
    await database.connect()
    app.state.dao = dao_factory.create(database, db.metadata)
    app.state.database = database
    yield
    await database.disconnect()


def create_application():
    db.create_tables(config.DATABASE_URL)
    acme = starlette.applications.Starlette(
        debug=config.DEBUG,
        routes=[
            starlette.routing.Route('/admin/directory', admin_directory, methods=['GET']),
            starlette.routing.Route('/admin/initialize', admin_initialize, methods=['POST']),
            #starlette.routing.Route('/admin/identity/create', create_identity, methods=['POST']),
            #starlette.routing.Route('/admin/identity/list', list_identities, methods=['POST']),
            #starlette.routing.Route('/admin/identity/{identity_id}/update', update_identity, methods=['POST']),
            #starlette.routing.Route('/admin/role/create', create_role, methods=['POST']),
            #starlette.routing.Route('/admin/role/list', list_roles, methods=['POST']),
            #starlette.routing.Route('/admin/role/{role_id}/update', update_role, methods=['POST']),
            #starlette.routing.Route('/admin/group/create', create_group, methods=['POST']),
            #starlette.routing.Route('/admin/group/list', list_group, methods=['POST']),
            #starlette.routing.Route('/admin/group/{group_id}/update', update_group, methods=['POST']),
            #starlette.routing.Route('/admin/boundary/create', create_boundary, methods=['POST']),
            #starlette.routing.Route('/admin/boundary/list', list_boundary, methods=['POST']),
            #starlette.routing.Route('/admin/boundary/{boundary_id}/update', update_boundary, methods=['POST']),
            #starlette.routing.Route('/admin/boundary/{boundary_id}/set-default', set_default_boundary, methods=['POST']),
        ],
        lifespan=lifespan,
        middleware=openapi.create_middleware(),
    )
    return acme


app = create_application()
