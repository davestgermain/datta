import time
import os.path
from datetime import datetime
import hashlib
from urllib.parse import unquote, quote
from quart import Blueprint, request, Response, current_app, exceptions
from quart.views import MethodView
from .util import aws_error_response, \
        xml_response, get_etag, get_xml, \
        good_response, asynread
from . import aws, auth

bp = Blueprint(__name__, 'datta.s3_server.api')


def get_website_index(fs, path, user=None):
    if fs.get_path_config(path).get('website'):
        index_path = os.path.join(path, 'index.html')
        try:
            return fs.open(index_path, owner=user or '*')
        except FileNotFoundError:
            path = index_path
    raise exceptions.NotFound()


    
class BucketView(MethodView):
    async def get(self, bucket):
        fs = current_app.fs
        qs = request.query_string
        prefix = request.args.get('prefix', '')

        config = fs.get_path_config('/' + bucket)
        if qs in ('location=', 'location'):
            return xml_response('<?xml version="1.0" encoding="UTF-8"?><LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>')
        elif qs == 'policy=':
            return jsonify(auth.get_acl(shelf, bucket))
        elif 'uploads' in qs:
            path = bucket
            if prefix:
                path += '/' + prefix
            return xml_response(aws.list_partials(fs, path))
        elif qs in ('versioning', 'versioning='):
            status = 'Enabled' if config.get('versioning', True) else 'Disabled'
            vxml = '''<?xml version="1.0" encoding="UTF-8"?><VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>{status}</Status></VersioningConfiguration>
            '''.format(status=status)
            return xml_response(vxml)
        elif qs in ('logging', 'logging='):
            return xml_response('')
        elif qs in ('acl=', 'acl'):
            return xml_response(aws.get_acl_response(fs, '/' + bucket, request.username))

        delimiter = request.args.get('delimiter', '')
        end_key = request.args.get('end')
        marker = request.args.get('marker')
        max_keys = min(int(request.args.get('max-keys') or 1000), 1000)

        s3_req = delimiter or prefix or marker or request.headers.get('authorization') or request.headers.get('x-amz-content-sha256')

        if s3_req:
            s3iter = aws.list_bucket(fs,
                                    bucket,
                                    prefix=prefix,
                                    delimiter=delimiter,
                                    owner=request.username,
                                    marker=marker,
                                    maxkeys=max_keys,
                                    versions='versions' in request.query_string)
            async def iterator():
                try:
                    for chunk in s3iter:
                        yield chunk.encode('utf8')
                except KeyError:
                    yield await aws_error_response(404, 'BucketNotFound', bucket, bucket=bucket).get_data()
            return xml_response(iterator=iterator)
        else:
            fp = get_website_index(fs, '/%s/' % bucket)
            return good_response(fp)


    async def put(self, bucket):
        user = request.username

        headers = {}
        if user:
            path = '/' + bucket
            fs = current_app.fs
            config = fs.get_path_config(path)
            if request.query_string in ('acl=', 'acl'):
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
                current_app.logger.info('Created bucket %s', bucket)
        return Response('', headers=headers)

    async def post(self, bucket):
        fs = current_app.fs
        if request.query_string == 'delete=':
            tree = await get_xml()
            keys = [key.text for key in tree.findall('Object/Key')]
            resp = '<?xml version="1.0" encoding="UTF-8"?>\n<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
            user = request.username
            for key in keys:
                keyelt = '<Key>%s</Key>' % key
                if fs.delete(os.path.join(bucket, key), owner=user):
                    resp += '<Deleted>%s</Deleted>' % keyelt
                else:
                    resp += '<Error>%s</Error>' % keyelt
            resp += '</DeleteResult>'            
        else:
            resp = ''
        return xml_response(resp)

    async def delete(self, bucket):
        if request.username:
            path = '/' + bucket
            if current_app.fs.check_perm(path, request.username, 'd'):
                current_app.fs.rmtree(path)
        return xml_response('')

    async def head(self, bucket):
        return Response('')


class ObjectView(MethodView):
    def path(self, bucket, key):
        return unquote('/{}/{}'.format(bucket, key))

    async def get(self, bucket, key):
        if 'uploadId' in request.args:
            return await self.multipart_upload(bucket, key)
        path = self.path(bucket, key)
        fs = current_app.fs
        if request.query_string in ('acl=', 'acl'):
            return xml_response(aws.get_acl_response(fs, path, request.username))
        headers = {}

        owner = request.username
        try:
            fp = fs.open(path, owner=owner)
        except FileNotFoundError:
            # if this bucket is a "website", try serving an index.html
            if path.endswith('/'):
                fp = get_website_index(fs, path, owner)
            else:
                return aws_error_response(404, 'NoSuchKey', key, bucket=bucket, key=key)
        except PermissionError:
            current_app.logger.error('DENIED %s user=%s auth=%s', path, owner, request.headers.get('authorization'))
            return aws_error_response(403, 'AccessDenied', key, bucket=bucket, key=key)
        return good_response(fp,
                            headers=headers)

    async def head(self, bucket, key):
        return await self.get(bucket, key)

    async def read_from_buf(self, from_buf, to_buf):
        while 1:
            chunk = await asynread(from_buf, 8192)
            if not chunk:
                break
            to_buf.write(chunk)

    async def put(self, bucket, key):
        if 'uploadId' in request.args:
            return await self.multipart_upload(bucket, key)
        if request.query_string in ('acl=', 'acl'):
            raise NotImplementedError('setting acls')

        fs = current_app.fs
        # data = request.body or b''
        value = None
        copy = False
        owner = request.username or 'anon'

        copy_file = None
        if 'x-amz-copy-source' in request.headers:
            # copy an object from the given bucket
            copy_path = os.path.join('/', request.headers['x-amz-copy-source'])
            try:
                copy_file = fs.open(copy_path, owner=owner)
            except PermissionError:
                return aws_error_response(error_code, 'no permission', copy_key, bucket=copy_bucket, key=copy_bucket)
            except FileNotFoundError:
                return aws_error_response(404, 'NoSuchKey', key, bucket=bucket, key=key)

        path = self.path(bucket, key)
        if path.endswith('/'):
            # directories are a no-op
            # return response.text('')
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
                    await aws.read_request(request, fp)
                # print('OWNER IS', fp.owner)
        except PermissionError:
            return aws_error_response(403, 'AccessDenied', key, bucket=bucket, key=key)
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
        return Response(resp, headers=headers)

    async def delete(self, bucket, key):
        path = self.path(bucket, key)
        config = current_app.fs.get_path_config(path)
        include_history = not config.get('versioning', True)
        try:
            if current_app.fs.delete(path, owner=request.username, include_history=include_history):
                return Response('')
            else:
                return aws_error_response(404, 'NoSuchKey', key, bucket=bucket, key=key)
        except PermissionError:
            return aws_error_response(403, 'AccessDenied', key, bucket=bucket, key=key)

    async def post(self, bucket, key):
        return await self.multipart_upload(bucket, key)

    async def multipart_upload(self, bucket, key):
        fs = current_app.fs
        upload_id = request.args.get('uploadId', '')
        partnum = request.args.get('partNumber', '')
        iterator = None
        headers = {}
        body = ''
        path = self.path(bucket, key)
        owner = request.username
        print('doing multipart upload', path, request.method, upload_id, partnum, owner)

        if not upload_id:
            #start
            try:
                partial = fs.partial(path, content_type=request.headers.get('content-type', 'application/octet-stream'), owner=owner)
            except PermissionError:
                return aws_error_response(403, 'AccessDenied', key, bucket=bucket, key=key)
            body = '''<?xml version="1.0" encoding="UTF-8"?>
            <InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
              <Bucket>{bucket}</Bucket>
              <Key>{key}</Key>
              <UploadId>{uploadid}</UploadId>
            </InitiateMultipartUploadResult>'''.format(bucket=bucket, key=key, uploadid=partial.id)
        elif request.method == 'POST':
            # complete request
            tree = await get_xml()
            try:
                partial = fs.partial(path, id=upload_id)
            except PermissionError:
                return aws_error_response(403, 'AccessDenied', key, bucket=bucket, key=key)
            url = request.path
            async def iterator():
                partnums = []
                for part in tree.findall('{http://s3.amazonaws.com/doc/2006-03-01/}Part/{http://s3.amazonaws.com/doc/2006-03-01/}PartNumber'):
                    partnums.append(part.text)
                print(partnums)
                try:
                    value = partial.combine(partnums, owner=owner)
                except FileNotFoundError:
                    yield aws_error_response(404, 'NoSuchUpload', key, bucket=bucket, key=key).get_data()
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

        elif request.method == 'PUT':
            partial = fs.partial(path, id=upload_id)
            content_type = request.headers.get('Content-Type', 'application/octet-stream')
            body_md5 = request.headers.get('Content-MD5')
            buf = partial.open_part(partnum)
            await aws.read_request(request, buf)
            buf.close()
            headers['Etag'] = buf.meta['md5']
        elif request.method == 'GET':
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
        return xml_response(body, iterator=iterator, headers=headers)



class SimpleAPI(MethodView):
    async def list(self, path):
        listiter = current_app.fs.listdir(path, owner=request.username)
        async def iterator():
            for p in listiter:
                yield (jsonify(p) + '\n').encode('utf8')
        return Response(iterator(), status=200, content_type='application/json')

    async def get(self, path):
        path = unquote('/' + path)
        if path.endswith('/'):
            return await self.list(path)

        fs = current_app.fs
        rev = request.args.get('rev', None)
        if rev:
            rev = int(rev)
        try:
            fp = fs.open(path, owner=request.username, rev=rev)
        except FileNotFoundError:
            raise exceptions.NotFound()
        except PermissionError:
            raise exceptions.Forbidden(path)
        headers = {}
        for key, value in fp.meta.items():
            headers['x-meta-%s' % key] = value if isinstance(value, str) else value.decode('utf8')
        headers['x-rev'] = str(fp.rev)

        return good_response(fp,
                            headers=headers)
            

    async def put(self, path):
        path = unquote('/' + path)
        fs = current_app.fs
        ctype = request.headers.get('content-type', '')
        print('UPLOADING', path, request.headers, ctype)
        try:
            with fs.open(path, mode='w', owner=request.username) as fp:
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

    async def delete(self, path):
        path = unquote('/' + path)
        fs = current_app.fs
        try:
            if current_app.fs.delete(path, owner=request.username):
                return Response('')
            else:
                raise exceptions.NotFound()
        except PermissionError:
            raise exceptions.Forbidden(path)
        return Response('')


bp.add_url_rule('/.simple/v1/<path:path>', view_func=SimpleAPI.as_view('simple'))
bp.add_url_rule('/<bucket>/<path:key>', view_func=ObjectView.as_view('object'))
bp.add_url_rule('/<bucket>/', view_func=BucketView.as_view('bucket'))

@bp.route('/')
async def index():
    fs = current_app.fs
    user = request.username or ''
    uid = hashlib.md5(user.encode('utf8')).hexdigest()
    iterator = auth.available_buckets(fs, user=user)
    async def stream():
        list_buckets = '''<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
<Owner>
    <ID>%s</ID>
    <DisplayName>%s</DisplayName>
</Owner>
<Buckets>
        '''
        yield (list_buckets % (uid, user)).encode('utf8')
        for info in iterator:
            yield ('<Bucket><Name>%s</Name><CreationDate>%sZ</CreationDate></Bucket>' % (info, datetime.utcnow().isoformat())).encode('utf8')
        yield b'</Buckets></ListAllMyBucketsResult>'
    return xml_response(iterator=stream)
