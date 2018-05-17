import hashlib
import hmac
import uuid
import codecs
import re
import secrets
from datetime import datetime
from urllib.parse import urlsplit
from minio import signer


AUTH_BUCKET = '.auth'
ACL_BUCKET = '.acl'
DEFAULT_ACL = {'*': ['r', 'w', 'd']}
DEFAULT_ACL_OWNER = ['r', 'w', 'd', 's']

"""
ACL example:
buckets['secret-bucket'] = {
    'user1': ['r', 'w', 'd', 's'],
    '*': ['r']
}

"""

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

def can_do(acl, user, operation='r'):
    """
    checks whether the given user can perform given operation in the ACL
    """
    try:
        return operation in acl[user]
    except KeyError:
        return False

def change_password(shelf, user_obj, password):
    """
    change user object password
    """
    user_obj['password'] = encode_password(password)
    shelf[AUTH_BUCKET, user_obj['username']] = user_obj

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
        'secret_key': secrets.token_urlsafe(32)
    }
    user_path = '/.auth/%s' % user
    if not fs[user_path]:
        fs[user_path] = user_obj
        fs.set_perm('/' + user + '/', user, ['r', 'w', 'd'])
    else:
        raise KeyError(user)
    return user_obj, password

def add_bucket(fs, user, bucket, extra_acl=None):
    # username = user['username']
    # if bucket starts with username, add it
    # if not, check for role
    if not isinstance(bucket, str):
        bucket = bucket.decode('utf8')
    bucket_name = bucket
    # if bucket.startswith(username + '-'):
    #     if shelf.has_key((ACL_BUCKET, bucket)):
    #         # bail
    #         return
    #     else:
    #         bucket_name = bucket
    # else:
    #     # can I put it on the top level?
    #     if user.get('role') == 'admin':
    #         bucket_name = bucket
    #         if shelf.has_key((ACL_BUCKET, bucket_name)):
    #             return
    #     else:
    #         bucket_name = '%s-%s' % (username, bucket)
    #         if shelf.has_key((ACL_BUCKET, bucket_name)):
    #             return
    # acl = {}
    # acl.update(extra_acl or {})
    # acl[username] = DEFAULT_ACL_OWNER
    # set_acl(shelf, bucket_name, acl)
    # shelf.create_bucket(bucket)
    return bucket_name

# def get_acl(shelf, bucket, default=DEFAULT_ACL):
#     return shelf.get((ACL_BUCKET, bucket), default)
#
# def set_acl(shelf, bucket, acl):
#     shelf[ACL_BUCKET, bucket] = acl

def can_access_acl(shelf, username, bucket, operation='r'):
    acl = get_acl(shelf, bucket, {})
    if not acl:
        return acl
    # to read acls, must have 's' perm
    # or the 'r' perm on the .acl acl
    if can_do(acl, username, 's') or can_do(get_acl(shelf, ACL_BUCKET), username, operation):
        return acl
    return None

def get_user(fs, username):
    return fs['/.auth/%s' % username]

SIG_RE = re.compile('Signature=(.*)$')
HEAD_RE = re.compile('SignedHeaders=(.*),')

def user_from_headers(fs, headers, method='GET', url=''):
    auth_header = headers.get('Authorization', '')
    auth_user, auth_pass = get_http_auth(auth_header)

    if auth_user and auth_pass:
        user = get_user(fs, auth_user)
        if user:
            if auth_pass == AWS_PASS:
                # 20180517T030056Z
                date = datetime.strptime(headers['x-amz-date'], "%Y%m%dT%H%M%SZ")
                assert (datetime.utcnow() - date).seconds <= 120
                try:
                    to_sign = {h.title(): headers[h] for h in HEAD_RE.search(auth_header).group(1).split(';')}
                except (KeyError, IndexError) as e:
                    print('header problem!', headers, e)
                    to_sign = {}

                secret_key = user['secret_key']
    
                sha256 = headers.get('x-amz-content-sha256', '')
                region = 'us-east-1'
                parsed_url = urlsplit(url)
                signed_headers = signer.get_signed_headers(to_sign)
                canonical_req = signer.generate_canonical_request(method,
                                                           parsed_url,
                                                           to_sign,
                                                           signed_headers,
                                                           sha256)

                string_to_sign = signer.generate_string_to_sign(date, region,
                                                         canonical_req)
                signing_key = signer.generate_signing_key(date, region, secret_key)
                gen_sig = hmac.new(signing_key, string_to_sign.encode('utf-8'),
                                     hashlib.sha256).hexdigest()

                signature = SIG_RE.search(auth_header).group(1)

                if gen_sig == signature:
                    # print('USER ID', user)
                    return user
                # else:
                #     print(signed_headers, auth_header, gen_headers['Authorization'])
            elif check_password(user, auth_pass):
                return user
    return None

def can_access_bucket(fs, bucket, user=None, headers=None, method='GET', url='', operation='r'):
    rt = (True, 0)
    if not bucket: return rt
    # bucket_acl = get_acl(shelf, bucket)
    user = user or user_from_headers(fs, headers or {}, method=method, url=url)
    username = user['username'] if user else '*'
    # if not fs.check_perm(bucket, perm=operation, owner=username):
    #     rt = False, 401
    return rt

def available_buckets(fs, user=None):
    for i, count in fs.common_prefixes('/', '/'):
        if not i.startswith('.'):
            yield i
    # for path in fs.listdir('/', owner=user):
    #     yield path
