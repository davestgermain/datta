import os.path
import hashlib
import hmac
import uuid
import codecs
import re
from datetime import datetime
from urllib.parse import urlsplit, quote, unquote
from xml.etree.ElementTree import fromstring

from html import escape
import itertools

counter = itertools.count()

ERROR_XML = '''<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>{code}</Code>
  <Message>{message}</Message>
  <Resource>/{bucket}/{key}</Resource> 
  <RequestId>{request_id}</RequestId>
</Error>
'''


async def asynread(fp, size=-1):
    return fp.read(size)

class S3Response:
    def __init__(self, data_iter=None, status=200, content_type='text/xml', headers=None):
        self.data = data_iter or ''
        self.status = status
        self.headers = headers or {}
        self.is_object = False
        if content_type:
            self.headers['Content-Type'] = content_type

def sign(key, msg):
    return hmac.new(key, msg.encode('utf8'), hashlib.sha256).digest()

def get_aws_signature(path, query_string, method, signed_headers, secret_key, date, service='s3', region='us-east-1', sha256='', recv_sig=None, logger=None):
    datestamp = date.strftime('%Y%m%d')
    amzdate = date.strftime('%Y%m%dT%H%M%SZ')

    canonical_q = []
    for q in query_string.strip().split('&'):
        if q and '=' not in q:
            q += '='
        canonical_q.append(q)
    canonical_q.sort()
    canonical_q = '&'.join(canonical_q)
    path = quote(path)
    if path == '//':
        path = '/'

    canonical_req = [method, path, canonical_q]
    for header, value in signed_headers:
        value = ' '.join(value.strip().split())
        canonical_req.append('%s:%s' % (header.strip(), value))
    canonical_req.append('')
    canonical_req.append(';'.join([s[0] for s in signed_headers]))
    canonical_req.append(sha256)
    canonical_req = '\n'.join(canonical_req)

    scope = '%s/%s/%s/aws4_request' % (datestamp, region, service)
    string_to_sign = '\n'.join(['AWS4-HMAC-SHA256', amzdate, scope, hashlib.sha256(canonical_req.encode('utf8')).hexdigest()])

    kd = sign(('AWS4' + secret_key).encode('utf8'), datestamp)
    kr = sign(kd, region)
    ks = sign(kr, service)
    signing_key = sign(ks, 'aws4_request')

    signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
    if recv_sig is not None and signature != recv_sig:
        if logger:
            logger.error('BAD SIGNATURE gen:%s rec:%s headers:%r', signature, recv_sig, signed_headers)
            logger.error('\n' + canonical_req)
            logger.error(string_to_sign)
        return False
    return signature

SIG_RE = re.compile('Signature=(.*)$')
HEAD_RE = re.compile('SignedHeaders=(.*),')


class S3Protocol:
    INDEX_CACHE = {}
    def __init__(self, fs, request, logger=None):
        self.fs = fs
        self.req = request
        self.method = request.method
        self.username = None
        self.user = None
        self.logger = logger

    async def get_xml(self):
        return fromstring((await self.req.get_data()).decode('utf8'))

    def authenticate(self):
        auth_string = self.req.headers.get('Authorization', '')
        if auth_string.startswith('AWS4-HMAC-SHA256'):
            auth_user = auth_string.split()[1].split('=')[1].split('/')[0]
            user = self.load_user(auth_user)
            if user:
                headers = self.req.headers
                # 20180517T030056Z
                date = datetime.strptime(headers['x-amz-date'], "%Y%m%dT%H%M%SZ")
                # assert (datetime.utcnow() - date).seconds <= 300

                # the subdomain bucket handling code in __init__.py rewrites the path and host.
                # but signatures are computed based on the original path 
                path = headers.get('__path', self.req.path)
                host = headers.get('__host')
                if host:
                    headers['host'] = host
                try:
                    if 'expect;' in auth_string:
                        # nginx strips expect headers, so we have to add it
                        headers['expect'] = '100-continue'
                    to_sign = sorted([(h.lower(), headers[h]) for h in HEAD_RE.search(auth_string).group(1).split(';')])
                except (KeyError, IndexError) as e:
                    if self.logger:
                        self.logger.exception('header problem %s' % headers)
                    return

                secret_key = user['secret_key']
                signature = SIG_RE.search(auth_string).group(1)

                valid = get_aws_signature(path,
                                          self.req.query_string,
                                          self.method,
                                          to_sign,
                                          secret_key,
                                          date,
                                          sha256=headers.get('x-amz-content-sha256', ''),
                                          recv_sig=signature)

                if valid:
                    # print('USER ID', user['username'])
                    self.user = user
                    self.username = user['username']
                    return user
                elif self.logger:
                    self.logger.error('AUTH PROBLEM %s %s', valid, auth_header)

    def load_user(self, auth_user):
        return self.fs['/.auth/%s' % auth_user]

    def error_xml(self, status, code, message, bucket='', key=''):
        request_id = next(counter)
        message = ERROR_XML.format(**locals()).encode('utf8')
        return S3Response(message, status=status)

    async def read_from_buf(self, from_buf, to_buf):
        while 1:
            chunk = await asynread(from_buf, 8192)
            if not chunk:
                break
            to_buf.write(chunk)

    async def handle_bucket(self, bucket):
        request = self.req
        fs = self.fs
        if self.method == 'GET':
            qs = request.query_string
            prefix = request.args.get('prefix', '')

            config = fs.get_path_config('/' + bucket)
            if qs in (b'location=', b'location'):
                return S3Response('<?xml version="1.0" encoding="UTF-8"?><LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>')
            elif qs == b'policy=':
                raise NotImplementedError()
            elif b'uploads' in qs:
                path = bucket
                if prefix:
                    path += '/' + prefix
                return S3Response(list_partials(fs, path))
            elif qs in (b'versioning', b'versioning='):
                status = 'Enabled' if config.get('versioning', True) else 'Suspended'
                vxml = '''<?xml version="1.0" encoding="UTF-8"?><VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>{status}</Status></VersioningConfiguration>
                '''.format(status=status)
                return S3Response(vxml)
            elif qs in (b'logging', b'logging='):
                return S3Response()
            elif qs in (b'acl=', b'acl'):
                return S3Response(get_acl_response(fs, '/' + bucket, request.username))

            delimiter = request.args.get('delimiter', '')
            end_key = request.args.get('end')
            marker = request.args.get('marker')
            if marker:
                marker = os.path.join(bucket, marker)
            max_keys = min(int(request.args.get('max-keys') or 1000), 1000)

            s3_req = request.headers.get('authorization') or request.headers.get('x-amz-content-sha256') or delimiter or prefix or marker

            if s3_req:
                s3iter = list_bucket(fs,
                                        bucket,
                                        prefix=prefix,
                                        delimiter=delimiter,
                                        owner=self.username,
                                        marker=marker,
                                        maxkeys=max_keys,
                                        versions=b'versions' in request.query_string)
                async def iterator():
                    try:
                        for chunk in s3iter:
                            yield chunk.encode('utf8')
                    except KeyError:
                        yield self.error_xml(404, 'BucketNotFound', bucket, bucket=bucket).data
                    except Exception as e:
                        if self.logger:
                            self.logger.exception('listdir')
                        yield self.error_xml(500, repr(e), bucket, bucket=bucket).data
                return S3Response(iterator())
            else:
                resp = S3Response(get_website_index(fs, '/%s/' % bucket), content_type='text/html')
                resp.is_object = True
                return resp
        elif self.method == 'POST':
            if request.query_string == b'delete=':
                tree = await self.get_xml()
                keys = [key.text for key in tree.findall('Object/Key')]
                resp = '<?xml version="1.0" encoding="UTF-8"?>\n<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                user = self.username
                for key in keys:
                    keyelt = '<Key>%s</Key>' % key
                    if fs.delete(os.path.join(bucket, key), owner=user):
                        resp += '<Deleted>%s</Deleted>' % keyelt
                    else:
                        resp += '<Error>%s</Error>' % keyelt
                resp += '</DeleteResult>'            
            else:
                resp = ''
            return S3Response(resp)
        elif self.method == 'PUT':
            user = self.username

            headers = {}
            if user:
                path = '/' + bucket
                config = fs.get_path_config(path)
                if request.query_string in (b'acl=', b'acl'):
                    raise NotImplementedError('setting acls')
            
                if not config:
                    config = {'bucket': True, 'owner': user}
                    fs.set_path_config(path, config)
                    #add a bucket
                    acl = {user: ['r', 'w', 'd'], '*': []}
                    amz_acl = request.headers.get('x-amz-acl')
                    if amz_acl == 'public-read':
                        acl['*'].append('r')
                    elif amz_acl == 'public-read-write':
                        acl['*'].append('w')
                    fs.set_acl(path, acl)
                    headers['Location'] = path
                    try:
                        del self.INDEX_CACHE[user]
                    except KeyError:
                        pass
                    if self.logger:
                        self.logger.info('Created bucket %s for %s', bucket, user)
            return S3Response(headers=headers)
        elif self.method == 'DELETE':
            if self.username:
                path = '/' + bucket
                if current_app.fs.check_perm(path, self.username, 'd'):
                    current_app.fs.rmtree(path)
                try:
                    del self.INDEX_CACHE[self.username]
                except KeyError:
                    pass
            return S3Response()
        elif self.method == 'HEAD':
            return S3Response()
        else:
            raise NotImplementedError(self.method)

    async def handle_object(self, bucket, key):
        path = unquote('/{}/{}'.format(bucket, key))
        request = self.req
        fs = self.fs

        if self.method in ('GET', 'HEAD'):
            if 'uploadId' in request.args:
                return await self.multipart_upload(path)

            if request.query_string in (b'acl=', b'acl'):
                return S3Response(get_acl_response(fs, path, self.username))
            headers = {}

            owner = self.username
            try:
                fp = fs.open(path, owner=owner)
            except FileNotFoundError:
                # if this bucket is a "website", try serving an index.html
                if path.endswith('/'):
                    fp = get_website_index(fs, path, owner)
                else:
                    return self.error_xml(404, 'NoSuchKey', key, bucket=bucket, key=key)
            except PermissionError:
                if self.logger:
                    self.logger.error('DENIED %s user=%s auth=%s', path, owner, request.headers.get('authorization'))
                return self.error_xml(403, 'AccessDenied', key, bucket=bucket, key=key)
            resp = S3Response(fp, headers=headers, content_type=fp.content_type)
            resp.is_object = True
            return resp
        elif self.method == 'PUT':
            if 'uploadId' in request.args:
                return await self.multipart_upload(path)
            if request.query_string in (b'acl=', b'acl'):
                raise NotImplementedError('setting acls')

            # data = request.body or b''
            value = None
            copy = False
            owner = self.username or 'anon'

            copy_file = None
            if 'x-amz-copy-source' in request.headers:
                # copy an object from the given bucket
                copy_path = os.path.join('/', request.headers['x-amz-copy-source'])
                try:
                    copy_file = fs.open(copy_path, owner=owner)
                except PermissionError:
                    return self.error_xml(403, 'no permission', copy_key, bucket=copy_bucket, key=copy_bucket)
                except FileNotFoundError:
                    return self.error_xml(404, 'NoSuchKey', key, bucket=bucket, key=key)

            if path.endswith('/'):
                path = path[:-1]
            ctype = request.headers.get('content-type', '')
            # print('UPLOADING', path, request.headers, ctype)
            try:
                with fs.open(path, mode='w', owner=owner) as fp:
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
                    if copy_file:
                        await self.read_from_buf(copy_file, fp)
                    else:
                        await read_request(request, fp)
                    # print('OWNER IS', fp.owner)
            except PermissionError:
                return self.error_xml(403, 'AccessDenied', key, bucket=bucket, key=key)
            headers = {'Etag': fp.meta['md5']}
            if fp.rev is not None:
                headers['x-amz-version-id'] = str(fp.rev)
            if copy:
                headers['Content-Type'] = 'text/xml'
                resp = '''
    <CopyObjectResult>
       <LastModified>%s</LastModified>
       <ETag>"%s"</ETag>
    </CopyObjectResult>
                    ''' % (getattr(fp, 'created', time.time()), headers['Etag'])
            else:
                resp = ''
            return S3Response(resp, headers=headers)
        elif self.method == 'DELETE':
            config = fs.get_path_config(path)
            include_history = not config.get('versioning', True)
            try:
                if fs.delete(path, owner=self.username, include_history=include_history):
                    return S3Response()
                else:
                    return self.error_xml(404, 'NoSuchKey', key, bucket=bucket, key=key)
            except PermissionError:
                return self.error_xml(403, 'AccessDenied', key, bucket=bucket, key=key)
        elif self.method == 'POST':
            return await self.multipart_upload(path)

    async def multipart_upload(self, path):
        fs = self.fs
        request = self.req
        upload_id = request.args.get('uploadId', '')
        partnum = request.args.get('partNumber', '')
        data = ''
        headers = {}
        # path = self.path(bucket, key)
        owner = self.username
        if self.logger:
            self.logger.info('doing multipart upload %s %s %s %s %s', path, self.method, upload_id, partnum, owner)
        bucket, key = path.split('/', 1)

        if not upload_id:
            #start
            try:
                partial = fs.partial(path, content_type=request.headers.get('content-type', 'application/octet-stream'), owner=owner)
            except PermissionError:
                return self.error_xml(403, 'AccessDenied', key, bucket=bucket, key=key)
            data = '''<?xml version="1.0" encoding="UTF-8"?>
            <InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
              <Bucket>{bucket}</Bucket>
              <Key>{key}</Key>
              <UploadId>{uploadid}</UploadId>
            </InitiateMultipartUploadResult>'''.format(bucket=bucket, key=key, uploadid=partial.id)
        elif self.method == 'POST':
            # complete request
            tree = await self.get_xml()
            try:
                partial = fs.partial(path, id=upload_id)
            except PermissionError:
                return self.error_xml(403, 'AccessDenied', key, bucket=bucket, key=key)
            url = request.path
            async def iterator():
                partnums = []
                for part in tree.findall('{http://s3.amazonaws.com/doc/2006-03-01/}Part/{http://s3.amazonaws.com/doc/2006-03-01/}PartNumber'):
                    partnums.append(part.text)
                print(partnums)
                try:
                    value = partial.combine(partnums, owner=owner)
                except FileNotFoundError:
                    yield self.error_xml(404, 'NoSuchUpload', key, bucket=bucket, key=key).data
                else:
                    etag = value.meta['sha256']
                    # etag = get_etag(value.data)
                    body = '''<?xml version="1.0" encoding="UTF-8"?>
                <CompleteMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                  <Location>{url}</Location>
                  <Bucket>{bucket}</Bucket>
                  <Key>{key}</Key>
                  <ETag>{etag}</ETag>
                </CompleteMultipartUploadResult>'''.format(url=url, bucket=bucket, key=key, etag=etag)
                    print(body)
                    yield body.encode('utf8')
            data = iterator()
        elif self.method == 'PUT':
            partial = fs.partial(path, id=upload_id)
            content_type = request.headers.get('Content-Type', 'application/octet-stream')
            body_md5 = request.headers.get('Content-MD5')
            buf = partial.open_part(partnum)
            await read_request(request, buf)
            buf.close()
            headers['Etag'] = buf.meta['md5']
        elif self.method == 'GET':
            start_xml = '''<?xml version="1.0" encoding="UTF-8"?>
            <ListPartsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
              <Bucket>{bucket}</Bucket>
              <Key>{key}</Key>
              <UploadId>{upload_id}</UploadId>
              <Initiator>
                  <ID>{user}</ID>
                  <DisplayName>{user}</DisplayName>
              </Initiator>
              <Owner>
                <ID>{user}</ID>
                <DisplayName>{user}</DisplayName>
              </Owner>
              <StorageClass>STANDARD</StorageClass>'''.format(bucket=bucket,
                                                              key=key,
                                                              upload_id=upload_id,
                                                              user=owner)
            partial = fs.partial(path, id=upload_id)
            async def iterator():
                yield start_xml.encode('utf8')
                firstnum = None
                try:
                    maxparts = 0
                    partnum = 0
                    for partnum, meta in partial.list():
                        if firstnum is None:
                            yield '''<PartNumberMarker>{partnum}</PartNumberMarker>'''.format(partnum).encode('utf8')
                            firstnum = partnum
                        yield '''
                        <Part>
                          <PartNumber>{partnum}</PartNumber>
                          <ETag>&quot;{etag}&quot;</ETag>
                          <Size>{size}</Size>
                        </Part>
                        '''.format(partnum=partnum, etag=meta.get('md5'), size=meta['length']).encode('utf8')
                        maxparts = partnum
                except KeyError:
                    # no parts?
                    partnum = 0
                    maxparts = 1
                yield '''
                <NextPartNumberMarker>{lastpartnum}</NextPartNumberMarker>
                <IsTruncated>false</IsTruncated>
                <MaxParts>{maxparts}</MaxParts>
                </ListPartsResult>
                '''.format(maxparts=maxparts, lastpartnum=partnum + 1).encode('utf8')
            data = iterator()
        return S3Response(data, headers=headers)

    async def handle_index(self):
        fs = self.fs
        request = self.req
        user = self.username or ''
        uid = hashlib.md5(user.encode('utf8')).hexdigest()
        async def stream(user):
            if user not in self.INDEX_CACHE:
                buckets = []
                list_buckets = '''<?xml version="1.0" encoding="UTF-8"?>
        <ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
        <Owner>
            <ID>%s</ID>
            <DisplayName>%s</DisplayName>
        </Owner>
        <Buckets>'''
                buckets.append((list_buckets % (uid, user)).encode('utf8'))
                try:
                    for obj in self.fs.listdir('/', owner=user):
                        if obj.content_type == 'application/x-directory' and not obj.path.startswith('/.'):
                            bucket = obj.path.replace('/', '')
                            buckets.append(('<Bucket><Name>%s</Name><CreationDate>%sZ</CreationDate></Bucket>' % (bucket, obj.created.isoformat())).encode('utf8'))
                except Exception:
                    if self.logger:
                        self.logger.exception('index')
                buckets.append(b'</Buckets></ListAllMyBucketsResult>')
                self.INDEX_CACHE[user] = buckets
            else:
                buckets = self.INDEX_CACHE[user]
            for bucket in buckets:
                yield bucket
        return S3Response(stream(user))


async def write_async(write_buf, chunk):
    write_buf.write(chunk)

async def read_request(request, write_buf):
    """
    Reads a chunked AWS request, and writes into write_buf
    """
    if request.headers.get('x-amz-content-sha256') == 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD':
        rbuf = b''
        looking_for_chunk = True
        try:
            async for chunk in request.body:
                if looking_for_chunk:
                    cline, body = chunk.split(b'\r\n', 1)
                    size, sig = cline.split(b';')
                    size = int(size, 16)
                    rbuf += body
                    if size == 0:
                        break
                    looking_for_chunk = False
                else:
                    rbuf += chunk
                if len(rbuf) >= size:
                    write_buf.write(rbuf[:size])
                    # await write_async(write_buf, body[:size])
                    # chunk ends with \r\n
                    rbuf = rbuf[size + 2:]
                    looking_for_chunk = True
            if rbuf:
                write_buf.write(rbuf)
        except:
            from quart import current_app
            current_app.logger.exception('read_request')
            return
    else:
        await write_async(write_buf, await request.get_data())

def get_website_index(fs, path, user=None):
    if fs.get_path_config(path).get('website'):
        index_path = os.path.join(path, 'index.html')
        try:
            return fs.open(index_path, owner=user or '*')
        except FileNotFoundError:
            path = index_path
    from quart import exceptions
    raise exceptions.NotFound()

def make_contents(fs, iterator, bucket_prefix, maxkeys=1000, versions=False, delimiter='/', marker=None):
    is_truncated = 'false'
    contents = []
    last_key = None
    subdirs = set()
    key_count = 0
    last_marker = ''
    for row in iterator:
        key = row.path.replace(bucket_prefix, '', 1)
        if key == bucket_prefix[:-1]:
            continue

        key = escape(key)
        # if delimiter:
        #     skey = key[prefix_len:].split(delimiter)
        #     if len(skey) > 1:
        #         common_prefixes.add(prefix + skey[0] + delimiter)
        #         continue
        if marker and key <= marker:
            continue
        last_marker = key

        if versions:
            rows = fs.get_meta_history(row.path)
            latest_rev = row.rev
        else:
            rows = [row]
        for row in rows:
            if row.get('content_type') == 'application/x-directory':
                # subdirs.add(row.path.split('/')[-1])
                continue
            modified = row.get('modified', row.created).isoformat() + 'Z'
            created = row.get('created').isoformat() + 'Z'
            meta = row.meta or {}
            etag = meta.get('md5') or meta.get('sha256') or 'default'
            owner = row.get('owner', '') or ''
            if not isinstance(owner, str):
                owner = owner.decode('utf8')
            if owner == '*':
                owner = 'anon'
            if versions:
                contents.append('<Version>')
                # list all versions
            else:
                contents.append('<Contents>')
            doc = '''
    <Key>{key}</Key>
    <LastModified>{modified}</LastModified>
    <ETag>&quot;{etag}&quot;</ETag>
    <Size>{size}</Size>
    <StorageClass>STANDARD</StorageClass>
    <Owner><DisplayName>{owner}</DisplayName></Owner>
    '''.format(key=key, size=row.get('length') or 0, created=created, modified=modified, etag=etag, owner=owner)
            contents.append(doc)
            if versions:
                contents.append('<VersionId>{rev}/{etag}</VersionId>'.format(rev=row.rev, etag=etag))
                if row.rev == latest_rev:
                    contents.append('<IsLatest>true</IsLatest>')
                contents.append('</Version>')
            else:
                contents.append('</Contents>')
        key_count += 1

        last_key = key
        if key_count == maxkeys:
            is_truncated = 'true'
            break

    return contents, key_count, last_key, is_truncated, subdirs, last_marker


def md5hex(msg):
    return hashlib.md5(msg.encode('utf8')).hexdigest()

def get_acl_response(fs, path, user):
    acl = fs.get_acl(path)
    if not path.endswith('/'):
        meta_info = fs.get_file_metadata(path, None)
        owner = meta_info.get('owner')
        oid = md5hex(owner)
    else:
        config = fs.get_path_config(path)
        owner = config.get('owner', 'unknown')
        oid = md5hex(owner)
    grants = ''
    for username in [owner, user]:
        if username in acl:
            uid = md5hex(username)
            grants += '''
<Grant>
  <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Canonical User">
    <ID>{uid}</ID>
    <DisplayName>{name}</DisplayName>
  </Grantee>
  <Permission>FULL_CONTROL</Permission>
</Grant>
'''.format(uid=uid, name=username)

    xml = '''<?xml version="1.0" encoding="UTF-8"?>
<AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
<Owner>
<ID>{owner_id}</ID>
<DisplayName>{ownername}</DisplayName>
</Owner>
<AccessControlList>
{grants}
</AccessControlList>
</AccessControlPolicy>'''.format(owner_id=oid, ownername=owner, grants=grants)
    return xml


def list_bucket(fs, bucket, prefix='', maxkeys=1000, delimiter='/', marker=None, versions=False, owner=None):
    """
    Returns XML for S3 list_bucket API
    """
    path = '/'.join(['', bucket, prefix])

    # if not prefix:
    #     path += '/'

    element = 'ListBucketResult'
    if versions:
        element = 'ListVersionsResult'


    iterator = fs.listdir(path, owner=owner or '*', delimiter=delimiter, start_file=marker, walk=not delimiter)
    preamble = '''<?xml version="1.0" encoding="UTF-8"?>'''\
'''<%s xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
        <Name>%s</Name>
        <Prefix>%s</Prefix>
        <MaxKeys>%s</MaxKeys>
        <Delimiter>%s</Delimiter>
        <Marker>%s</Marker>
''' % (element, bucket, prefix, maxkeys, delimiter, escape(marker or ''))

    if versions:
        preamble += '<VersionIdMarker></VersionIdMarker>'

    bucket_prefix = '/%s/' % bucket

    contents, count, last_key, is_truncated, subdirs, last_marker = make_contents(fs, iterator, bucket_prefix, maxkeys=maxkeys, versions=versions, marker=marker)
    yield preamble
    yield from contents
    if last_key:
        yield '<NextContinuationToken>%s</NextContinuationToken>' % escape(last_key)
    yield '<KeyCount>%d</KeyCount><IsTruncated>%s</IsTruncated>' % (count, is_truncated)

    if delimiter:
        prefixes = set(d[0] for d in fs.common_prefixes(path, delimiter)) | subdirs
        if count == 0 and not path.endswith('/'):
            prefixes.add(path)
        if prefixes:
            next_token = None
            for cp in sorted(prefixes):
                cp = os.path.join(prefix, cp)
                if next_token is None:
                    next_token = cp
                # cp = cp.replace(bucket_prefix, '', 1)
                if cp:
                    if not cp.endswith('/'):
                        cp += '/'
                    yield '<CommonPrefixes><Prefix>%s</Prefix></CommonPrefixes>' % cp
                    last_marker = cp
            yield '<NextContinuationToken>%s</NextContinuationToken>' % next_token
    yield '<NextMarker>%s</NextMarker>' % escape(last_marker)
    yield '</%s>' % element

def list_partials(fs, bucket):
    yield '''<?xml version="1.0" encoding="UTF-8"?>
    <ListMultipartUploadsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
      <Bucket>{bucket}</Bucket>
      <KeyMarker></KeyMarker>
      <UploadIdMarker></UploadIdMarker><IsTruncated>false</IsTruncated>'''.format(bucket=bucket).encode('utf8')

    for p in fs.list_partials('/' + bucket):
        key = p['path'].replace(bucket, '', 1)
        created = p['created'].isoformat() + 'Z'
        upload = '''<Upload>
        <Key>{key}</Key>
        <UploadID>{id}</UploadId>
        <Owner>
            <DisplayName>{owner}</DisplayName>
        </Owner>
        <StorageClass>STANDARD</StorageClass>
        <Initiated>{created}</Initiated>
</Upload>
        '''.format(key=key, owner=p['owner'], created=created, id=p['id'])
        yield upload.encode('utf8')
    yield b'</ListMultipartUploadsResult>'


if __name__ == '__main__':
    from datta.fs import get_manager
    man = get_manager('fdb')
    result = list(list_bucket(man, 'foo', prefix=''))
    print(result)
