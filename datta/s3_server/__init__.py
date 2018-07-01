from quart import Quart, request, Request
from quart.ctx import RequestContext
from . import api, admin, vhost, auth
from ..fs import get_manager
import atexit




class VhostQuart(Quart):
    def request_context(self, _request: Request) -> RequestContext:
        if self.config['SERVER_NAME'] and not _request.host.startswith(self.config['SERVER_NAME']):
            # this is a wildcard request
            try:
                bucket, host = _request.host.split('.', 1)
                _request.original_path = _request.path
                url = '/%s%s' % (bucket, _request.path)
                _request.path = url
                app.logger.debug('request_context %s, %s', url, _request.host)
                _request.headers['host'] = host
            except:
                app.logger.exception('bad vhost')
        return super().request_context(_request)
        
app = VhostQuart('s3-server', host_matching=True, static_host='')



@app.before_serving
async def setup_routes_and_db():
    app.fs = get_manager(app.config['FS_DSN'], debug=app.debug, event_model='asyncio')
    atexit.register(app.fs.close)

    if app.config['SERVER_NAME']:
        vhost.init_app(app)

    app.register_blueprint(admin.bp)
    app.register_blueprint(api.bp)



@app.before_request
async def get_user():
    request.user = auth.user_from_request(app.fs, request)
    if request.user:
        request.username = request.user['username']
    else:
        request.username = None



def main():
    import argparse
    import os.path
    import sys
    from hypercorn import config, run
    from quart.logging import create_serving_logger

    parser = argparse.ArgumentParser(prog='datta.s3_server', description='start the s3 compatible server')
    parser.add_argument('-d', default='fdb', dest='dsn', help='DSN for file manager')
    parser.add_argument('--debug', default=False, dest='debug', action='store_true')
    parser.add_argument('-r', dest='host', default='localhost:8484', help='Root domain')
    parser.add_argument('-c', dest='cert_path', help='Path to SSL certificates')
    parser.add_argument('-p', type=int, default=8484, help='port', dest='port')
    parser.add_argument('-a', default='127.0.0.1', help='addr', dest='addr')
    parser.add_argument('-w', type=int, help='# of workers', dest='workers', default=1)
    
    args = parser.parse_args()
    
    if args.debug:
        app.debug = True

    app.config['SERVER_NAME'] = args.host

    if args.cert_path:
        import ssl
        ssl_context = ssl.SSLContext()
        ssl_context.load_cert_chain(os.path.join(args.cert_path, 'cert.pem'), keyfile=os.path.join(args.cert_path, 'key.pem'))
    else:
        ssl_context = None

    # if 'PyPy' in sys.version:
    #     import asyncio
    #     asyncio.set_event_loop_policy(asyncio.DefaultEventLoopPolicy())

    app.config['FS_DSN'] = args.dsn
    app.config['MAX_CONTENT_LENGTH'] = 80 * 1024 * 1024

    hc = config.Config()
    hc.uvloop = True
    hc.ssl = ssl_context
    hc.port = args.port
    hc.debug = hc.use_reloader = args.debug
    hc.keep_alive_timeout = 600
    
    if hc.debug:
        hc.access_log_format = "%(h)s %(m)s %(U)s?%(q)s %(s)s %(b)s %(D)s"
        hc.access_logger = create_serving_logger()
        # hc.access_log_target = '-'
        hc.error_logger = hc.access_logger

    if args.workers > 1:
        run.run_multiple(app, hc, workers=args.workers)
    else:
        run.run_single(app, hc)
