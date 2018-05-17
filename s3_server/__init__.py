import os
import logging
from sanic import Sanic
from sanic.log import LOGGING_CONFIG_DEFAULTS
from . import api, admin, vhost, auth
from ..fs import get_manager

debug = os.environ.get('DEBUG') == 'true'

if not debug:
    LOGGING_CONFIG_DEFAULTS['loggers']['sanic.access']['level'] = 'ERROR'

app = Sanic('s3-server', log_config=LOGGING_CONFIG_DEFAULTS)
app.debug = debug

@app.listener('before_server_start')
async def setup_db(app, loop):
    app.fs = get_manager(os.getenv('FS_DSN', 'fdb'), event_model='asyncio')

@app.listener('before_server_start')
async def setup_routes(app, loop):
    vhost.init_app(app)

    app.blueprint(admin.bp)
    app.blueprint(api.bp)


# @app.listener('after_server_stop')
# async def close_db(app, loop):
#     pass

@app.middleware('request')
async def get_user(request):
    request['user'] = auth.user_from_headers(
                                    app.fs,
                                    request.headers,
                                    method=request.method,
                                    url=request.url)
    if request['user']:
        request['username'] = request['user']['username']
    else:
        request['username'] = None



