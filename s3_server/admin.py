from sanic import Blueprint, response, exceptions
from . import auth
# from .util import msg_response

bp = Blueprint('admin')

@bp.post('/.sys/register')
async def register(request):
    username = None
    auth_user = request['user']
    if auth_user and auth_user.get('role') == 'admin':
        username = request.form.get('username', '')
        if username:
            username = username[0]
    user, password = auth.register(request.app.fs, user=username)
    return response.json({'name': user['username'], 'password': password, 'secret_key': user['secret_key']})

@bp.post('/.sys/change_password')
async def change_password(request):
    password = request.form['password']
    
    if request['user']:
        auth.change_password(request.app.fs, request['user'], password)
        status = 200
        resp = 'OK'
    else:
        status = 401
        resp = 'ERROR'
    return msg_response(resp, status)

@bp.route('/.sys/acl/<bucket>')
async def change_acl(request, bucket):
    if request['user']:
        fs = request.app.fs
        operation = 'w' if method == 'PUT' else 'r'
        acl = auth.can_access_acl(fs, request['user']['username'], bucket, operation)
        if acl:
            if request.method == 'PUT':
                new_acl = request.json()
                # new_acl = json.loads(env['wsgi.input'].read())
                auth.set_acl(fs, bucket, new_acl)
                acl = new_acl
                status = 201
            else:
                status = 200
        return response.json(acl, status=status)
    else:
        raise exceptions.ServerError('Unauthorized', status=401)

@bp.post('/.sys/add_bucket')
async def add_bucket(request):
    bucket = request.form['bucket']
    status = 404
    if request['user']:
        bucket_name = auth.add_bucket(request.app.fs, request['user'], bucket)
        if bucket_name:
            status = 200
            resp = bucket_name
    else:
        status = 403
        resp = 'ERROR'
    return msg_response(resp, status)


@bp.route('/.sys/vhosts', methods=['GET', 'POST'])
async def vhost_config(request):
    from . import vhost
    if request.method == 'POST':
        host = request.form['host']
        action = request.form.get('action')
        if host:
            if action == 'register':
                vhost.register(request.app, host)
            elif action == 'unregister':
                vhost.unregister(request.app, host[0])
    return response.json(vhost.get_hosts(request.app))
