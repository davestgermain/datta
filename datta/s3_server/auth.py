import hashlib
import hmac
import uuid
import codecs
import re
from datetime import datetime

try:
    import secrets
except ImportError:
    # only available >3.6
    from datta.ext import secrets



AWS_PASS = 1

def get_http_auth(auth_string):
    """
    return HTTP Basic Auth user, password tuple
    """
    try:
        auth = auth_string.split()[1]
        if not auth_string.startswith('AWS4-HMAC-SHA256'):
            auth_user, auth_pass = codecs.decode(auth.encode('utf8'), 'base64').decode('utf8').split(':', 1)
        else:
            # get the aws access_key
            auth_user = auth.split('=')[1].split('/')[0]
            auth_pass = AWS_PASS
    except Exception:
        auth_user = auth_pass = None
    return auth_user, auth_pass

def encode_password(password, salt=None, iterations=1000):
    if salt is None:
        salt = uuid.uuid4().hex
    encoded = hashlib.pbkdf2_hmac('sha256', password.encode('utf8'), salt.encode('utf8'), iterations).hex()
    return encoded, salt, iterations

def check_password(user_obj, password):
    """
    check user object password
    """
    encoded, salt, iterations = user_obj['password']
    return encode_password(password, salt=salt, iterations=iterations)[0] == encoded

#
# def change_password(shelf, user_obj, password):
#     """
#     change user object password
#     """
#     user_obj['password'] = encode_password(password)
#     shelf[AUTH_BUCKET, user_obj['username']] = user_obj

def register(fs, user=None, password=None):
    """
    register a new account
    returns username, password
    """
    user = user or uuid.uuid4().hex[:8]
    # password = password or codecs.encode(uuid.uuid4().bytes, 'base64').decode('utf8')
    password = password or secrets.token_urlsafe(16)
    encoded, salt, iterations = encode_password(password)
    user_obj = {
        'username': user,
        'password': (encoded, salt, iterations),
        'secret_key': secrets.token_urlsafe(30)
    }
    user_path = '/.auth/%s' % user
    if not fs[user_path]:
        fs[user_path] = user_obj
        fs.set_perm('/' + user + '/', user, ['r', 'w', 'd'])
    else:
        raise KeyError(user)
    return user_obj, password


def get_user(fs, username):
    return fs['/.auth/%s' % username]


def user_from_request(fs, request):
    auth_header = request.headers.get('Authorization', '')
    if auth_header:
        auth_user, auth_pass = get_http_auth(auth_header)
        if auth_user and auth_pass:
            headers = request.headers
            user = get_user(fs, auth_user)
            if user:
                if auth_pass != AWS_PASS and check_password(user, auth_pass):
                    return user
    return None



