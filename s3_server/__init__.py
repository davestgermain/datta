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
app.root_host = os.environ.get('HOST', 'localhost')


@app.listener('before_server_start')
async def setup_db(app, loop):
    app.fs = get_manager(os.getenv('FS_DSN', 'fdb'), event_model='asyncio')

@app.listener('before_server_start')
async def setup_routes(app, loop):
    vhost.init_app(app)

    app.blueprint(admin.bp)
    app.blueprint(api.bp)



@app.middleware('request')
async def get_user(request):
    request['user'] = auth.user_from_request(app.fs, request)
    if request['user']:
        request['username'] = request['user']['username']
    else:
        request['username'] = None


@app.middleware('request')
async def handle_wildcard(request):
    if not request.host.startswith(app.root_host):
        # this is a wildcard request
        bucket, host = request.host.split('.', 1)
        url = '/%s%s' % (bucket, request.path)
        func, args, kwargs, pat = app.router._get(url, request.method, '')
        return await func(request, *args, **kwargs)
