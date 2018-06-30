from quart import Blueprint, request, jsonify, current_app
from . import auth

bp = Blueprint('admin', 'datta.s3_server.admin')

@bp.route('/.sys/register', methods=['POST'])
async def register():
    username = None
    auth_user = request.user
    if auth_user and auth_user.get('role') == 'admin':
        username = request.form.get('username', '')
    user, password = auth.register(request.app.fs, user=username)
    return jsonify({'name': user['username'], 'password': password, 'secret_key': user['secret_key']})

@bp.route('/.sys/change_password', methods=['POST'])
async def change_password():
    password = request.form['password']
    
    if request.user:
        auth.change_password(request.app.fs, request.user, password)
        status = 200
        resp = 'OK'
    else:
        status = 401
        resp = 'ERROR'
    return msg_response(resp, status)

# @bp.route('/.sys/acl/<bucket>')
# async def change_acl(request, bucket):
#     if request.user:
#         fs = request.app.fs
#         operation = 'w' if method == 'PUT' else 'r'
#         acl = auth.can_access_acl(fs, request.user['username'], bucket, operation)
#         if acl:
#             if request.method == 'PUT':
#                 new_acl = request.json()
#                 # new_acl = json.loads(env['wsgi.input'].read())
#                 auth.set_acl(fs, bucket, new_acl)
#                 acl = new_acl
#                 status = 201
#             else:
#                 status = 200
#         return response.json(acl, status=status)
#     else:
#         raise exceptions.ServerError('Unauthorized', status=401)




@bp.route('/.sys/vhosts', methods=['GET', 'POST'])
async def vhost_config(request):
    from . import vhost
    if request.method == 'POST':
        host = request.form['host']
        action = request.form.get('action')
        if host:
            if action == 'register':
                vhost.register(current_app, host)
            elif action == 'unregister':
                vhost.unregister(current_app, host[0])
    return jsonify(vhost.get_hosts(request.app))
