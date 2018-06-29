# import logging
from sanic import Sanic, log
from . import api, admin, vhost, auth
from ..fs import get_manager
import atexit



# if not debug:
#     LOGGING_CONFIG_DEFAULTS['loggers']['sanic.access']['level'] = 'ERROR'

app = Sanic('s3-server')



@app.listener('before_server_start')
async def setup_routes_and_db(app, loop):
    app.fs = get_manager(app.config.FS_DSN, debug=app.debug, event_model='asyncio')
    atexit.register(app.fs.close)
    
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


async def handle_wildcard(request):
    log.logger.debug(request.url)
    if not request.host.startswith(app.root_host):
        # this is a wildcard request
        bucket, host = request.host.split('.', 1)
        url = '/%s%s' % (bucket, request.path)
        func, args, kwargs, pat = app.router._get(url, request.method, '')
        return await func(request, *args, **kwargs)

def main():
    import argparse
    import os.path
    import sys

    parser = argparse.ArgumentParser(prog='datta.s3_server', description='start the s3 compatible server')
    parser.add_argument('-d', default='fdb', dest='dsn', help='DSN for file manager')
    parser.add_argument('--debug', default=False, dest='debug', action='store_true')
    parser.add_argument('-r', dest='host', default='', help='Root domain')
    parser.add_argument('-c', dest='cert_path', help='Path to SSL certificates')
    parser.add_argument('-p', type=int, default=8484, help='port', dest='port')
    parser.add_argument('-a', default='127.0.0.1', help='addr', dest='addr')
    parser.add_argument('-w', type=int, help='# of workers', dest='workers', default=1)
    
    args = parser.parse_args()
    
    if args.debug:
        app.debug = True

    app.root_host = args.host
    if app.root_host:
        app.middleware('request')(handle_wildcard)
        
    if args.cert_path:
        import ssl
        ssl_context = ssl.SSLContext()
        ssl_context.load_cert_chain(os.path.join(args.cert_path, 'cert.pem'), keyfile=os.path.join(args.cert_path, 'key.pem'))
    else:
        ssl_context = None

    # if 'PyPy' in sys.version:
    #     import asyncio
    #     asyncio.set_event_loop_policy(asyncio.DefaultEventLoopPolicy())

    app.config.FS_DSN = args.dsn
    app.config.REQUEST_TIMEOUT = 120
    app.config.KEEP_ALIVE = 600
    app.config.REQUEST_MAX_SIZE = 200000000

    try:
        app.run(
            host=args.addr,
            port=args.port,
            debug=args.debug,
            workers=args.workers,
            ssl=ssl_context,
            access_log=args.debug)
    except KeyboardInterrupt:
        app.stop()
        return 0
