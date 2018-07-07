from urllib.parse import unquote
from quart import Blueprint, request, Response, current_app, exceptions
from quart.json import JSONEncoder
from .util import good_response
from . import aws, auth


bp = Blueprint(__name__, 'datta.s3_server.api')


@bp.route('/<bucket>/', methods=['GET', 'POST', 'PUT', 'HEAD', 'DELETE'])
async def bucket_view(bucket):
    prot = aws.S3Protocol(current_app.fs, request, logger=current_app.logger)
    prot.authenticate()
    resp = await prot.handle_bucket(bucket)
    return Response(resp.data, status=resp.status, headers=resp.headers)

@bp.route('/<bucket>/<path:key>', methods=['GET', 'POST', 'PUT', 'HEAD', 'DELETE'])
async def object_view(bucket, key):
    prot = aws.S3Protocol(current_app.fs, request, logger=current_app.logger)
    prot.authenticate()
    resp = await prot.handle_object(bucket, key)
    if resp.is_object:
        return good_response(resp.data, headers=resp.headers)
    else:
        return Response(resp.data, status=resp.status, headers=resp.headers)

@bp.route('/')
async def index():
    prot = aws.S3Protocol(current_app.fs, request, logger=current_app.logger)
    prot.authenticate()
    resp = await prot.handle_index()
    return Response(resp.data, status=resp.status, headers=resp.headers)


# the defaults are required to trick the url mapper into sorting this method earlier
@bp.route('/.simple/v1/<path:path>', methods=['GET', 'PUT', 'DELETE'], defaults={'path': ''})
async def simple_api(path):
    path = unquote('/' + path)
    fs = current_app.fs
    user = auth.user_from_request(fs, request)
    username = user['username'] if user else '*'

    if request.method == 'GET':
        if path.endswith('/'):
            enc = JSONEncoder()
            listiter = fs.listdir(path, owner=username)
            async def iterator():
                for p in listiter:
                    p1 = p.to_dict()
                    del p1['data']
                    del p1['history_key']
                    r = (enc.encode(p1) + '\n').encode('utf8')
                    yield r
            return Response(iterator(), status=200, content_type='application/json')

        try:
            rev = request.args.get('rev', None)
            if rev:
                rev = int(rev)
            fp = fs.open(path, owner=username, rev=rev)
        except (FileNotFoundError, ValueError):
            raise exceptions.NotFound()
        except PermissionError:
            raise exceptions.Forbidden()
        headers = {}

        return good_response(fp,
                            headers=headers)

    elif request.method == 'PUT':
        ctype = request.headers.get('content-type', '')
        print('UPLOADING', path, request.headers, ctype)
        try:
            with fs.open(path, mode='w', owner=username) as fp:
                fp.do_hash('md5')
                fp.content_type = ctype
                for metakey in request.headers:
                    if metakey.startswith('x-amz-meta-'):
                        metavalue = request.headers[metakey]
                        metakey = metakey[11:]
                        fp.meta[metakey] = metavalue
                expiration = request.headers.get('Expires', None)
                if expiration:
                    fp.meta['expiration'] = float(expiration)
                await aws.read_request(request, fp)
        except FileNotFoundError:
            raise exceptions.NotFound()
        except PermissionError:
            raise exceptions.Forbidden()
        return Response(fp.meta['md5'])

    elif request.method == 'DELETE':
        try:
            if fs.delete(path, owner=username):
                return Response('')
            else:
                raise exceptions.NotFound()
        except PermissionError:
            raise exceptions.Forbidden()
        return Response('')
