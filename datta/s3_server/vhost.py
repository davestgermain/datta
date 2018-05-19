from datetime import datetime
from urllib.parse import unquote_to_bytes
from sanic import response, exceptions, router
from .util import get_etag, good_response

CONFIG_BUCKET = b'.s4-config'

def register(app, hosts, save=True):
    try:
        app.add_route(view_vhost_page, '/<key:path>', methods=['GET', 'HEAD'], strict_slashes=True, host=hosts)
        app.add_route(view_vhost_page, '/', methods=['GET', 'HEAD'], strict_slashes=True, host=hosts)
        if save:
            for host in hosts:
                hostconfig = {'bucket': host}
                app.shelf.put_in_bucket(CONFIG_BUCKET, b'vhost/%s' % host.encode('utf8'), hostconfig)
    except router.RouteExists:
        return False

def unregister(app, host, save=True):
    try:
        app.router.remove('/<key:path>', host=host)
        app.router.remove('/', host=host)
        app.router.hosts.remove(host)
        if save:
            app.shelf.delete_from_bucket(CONFIG_BUCKET, b'vhost/%s' % host)
    except (router.RouteDoesNotExist, KeyError):
        return False

def get_hosts(app):
    return list(app.router.hosts)

def get_config_hosts(app):
    # TODO: implement this
    # try:
    #     hosts = [key.split('/')[1] for key, _ in app.fs.get_range_from_bucket(CONFIG_BUCKET, 'vhost/')]
    # except KeyError:
    #     hosts = []
    # return hosts
    return []


def init_app(app):
    hosts = get_config_hosts(app)
    register(app, hosts, save=False)
    print('Configured vhosts for', hosts)


async def view_vhost_page(request, key='index.html'):
    shelf = request.app.shelf
    bucket = request.host.encode('utf8')
    key = unquote_to_bytes(key)

    try:
        value = shelf.get_from_bucket(bucket, key)
    except KeyError:
        if key.endswith(b'/'):
            try:
                key = key + b'index.html'
                value = shelf.get_from_bucket(bucket, key)
            except KeyError:
                raise exceptions.NotFound(key.decode('utf8'))
        else:
            raise exceptions.NotFound(key.decode('utf8'))

    headers = {}
    if hasattr(value, 'data'):
        body = value.data
        content_type = value.content_type

        if hasattr(value, 'created'):
            creation_date = datetime.utcfromtimestamp(value.created)
    else:
        body = response.json_dumps(value)
        content_type = 'application/json'
        creation_date = None
    return good_response(request,
                         body,
                         content_type=value.content_type,
                         headers=headers,
                         creation_date=creation_date)
