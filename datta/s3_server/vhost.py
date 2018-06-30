import os.path
from datetime import datetime
from urllib.parse import unquote_to_bytes
from quart import exceptions
from .util import good_response

CONFIG_BUCKET = '/.config/vhost/'

def register(app, hosts, save=True):
    try:
        app.add_url_rule('/<path:key>', view_vhost_page, methods=['GET', 'HEAD'], host=hosts)
        app.add_url_rule('/', view_vhost_page, methods=['GET', 'HEAD'], host=hosts)
    except AssertionError:
        return False
    if save:
        for host in hosts:
            path = os.path.join(CONFIG_BUCKET, host)
            hostconfig = {'bucket': host}
            with app.fs.open(path, owner='root', mode='w') as fp:
                fp.write(repr(hostconfig))

def unregister(app, host, save=True):
    try:
        app.router.remove('/<key:path>', host=host)
        app.router.remove('/', host=host)
        app.router.hosts.remove(host)
        if save:
            path = os.path.join(CONFIG_BUCKET, host)
            app.fs.delete(path, owner='root')
    except (router.RouteDoesNotExist, KeyError):
        return False

def get_hosts(app):
    return list(app.router.hosts)

def get_config_hosts(app):
    hosts = [i.path.split('/')[-1] for i in app.fs.listdir(CONFIG_BUCKET)]
    return hosts


def init_app(app):
    hosts = get_config_hosts(app)
    register(app, hosts, save=False)
    app.logger.info('Configured vhosts for %s', hosts)


async def view_vhost_page(key='index.html'):
    fs = request.app.fs
    bucket = request.host
    path = os.path.join('/', bucket, key)
    try:
        fp = fs.open(path)
    except FileNotFoundError:
        if path.endswith('/'):
            try:
                path += '/index.html'
                fp = fs.open(path)
            except FileNotFoundError:
                raise exceptions.NotFound()
        else:
            raise exceptions.NotFound()

    headers = {}
    return good_response(fp,
                         headers=headers)
