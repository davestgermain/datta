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
                _request.headers['__path'] = _request.path
                _request.headers['__host'] = _request.host
                _request.headers['host'] = host
                url = '/%s%s' % (bucket, _request.path)
                _request.path = url
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




def main():
    import argparse
    import os.path
    import sys
    import asyncio
    from hypercorn import config
    from hypercorn.asyncio import serve
    from quart.logging import create_serving_logger

    parser = argparse.ArgumentParser(prog='datta.s3_server', description='start the s3 compatible server')
    parser.add_argument('-d', default='fdb', dest='dsn', help='DSN for file manager')
    parser.add_argument('--debug', default=False, dest='debug', action='store_true')
    parser.add_argument('-r', dest='host', default='localhost:8484', help='Root domain')
    parser.add_argument('-c', dest='cert_path', help='Path to SSL certificates')
    parser.add_argument('-p', type=int, default=8484, help='port', dest='port')
    parser.add_argument('-a', default='127.0.0.1', help='addr', dest='addr')
    parser.add_argument('-w', type=int, help='# of workers', dest='workers', default=1)
    parser.add_argument('-b', dest='block_server', help='Also run block server at host:port')

    args = parser.parse_args()
    
    if args.debug:
        app.debug = True

    app.config['SERVER_NAME'] = args.host

    if args.cert_path:
        import ssl
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.set_ciphers('ECDHE+AESGCM')
        ssl_context.load_cert_chain(os.path.join(args.cert_path, 'cert.pem'), keyfile=os.path.join(args.cert_path, 'key.pem'))
    else:
        ssl_context = None

    if 'PyPy' not in sys.version:            
        try:
            import uvloop
            asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        except ImportError:
            pass

    app.config['FS_DSN'] = args.dsn
    app.config['MAX_CONTENT_LENGTH'] = 85 * 1024 * 1024
    app.config['MAX_CONTENT_LENGTH'] = None

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
    loop = asyncio.get_event_loop()

    if args.block_server:
        from datta.fs.cas.server import AsyncioBlockServer
        host, port = args.block_server.split(':')
        bs = AsyncioBlockServer(args.dsn, host=host, port=port, debug=args.debug)
        block_server = bs.start(loop=loop, run_loop=False)
    else:
        block_server = None

    if args.workers > 1:
        import signal
        def _shutdown(num, frame):
            raise KeyboardInterrupt()
        signal.signal(signal.SIGTERM, _shutdown)
        if block_server:
            from concurrent.futures.thread import ThreadPoolExecutor
            loop.run_in_executor(ThreadPoolExecutor(), loop.run_forever)
        run.run_multiple(app, hc, workers=args.workers)
    else:
        try:
            loop.run_until_complete(serve(app, hc))
        except KeyboardInterrupt:
            if block_server:
                block_server.close()
                loop.run_until_complete(block_server.wait_closed())
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.close()
