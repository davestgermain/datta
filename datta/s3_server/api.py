import time
import os.path
from datetime import datetime
from urllib.parse import unquote, quote
from sanic import Blueprint, response, exceptions
from sanic.views import HTTPMethodView
from sanic.views import stream as stream_decorator
from .util import aws_error_response, \
        xml_response, get_etag, get_xml, \
        good_response
from .aws import list_bucket, read_request, list_partials
from . import auth

bp = Blueprint('api')


def get_website_index(shelf, bucket, key):
    if shelf.bucket_contains(bucket, b'website'):
        index_key = key + b'index.html'
        try:
            return shelf.get_from_bucket(bucket, index_key)
        except KeyError:
            key = index_key
    raise exceptions.NotFound(key)


class BucketView(HTTPMethodView):
    async def get(self, request, bucket):
        fs = request.app.fs
        qs = request.query_string
        prefix = request.args.get('prefix', '')
        
        config = fs.get_path_config('/' + bucket)
        if qs in ('location=', 'location'):
            return xml_response('<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>')
        elif qs == 'policy=':
            return response.json(auth.get_acl(shelf, bucket))
        elif 'uploads' in qs:
            path = bucket
            if prefix:
                path += '/' + prefix
            return xml_response(list_partials(fs, path))
        elif qs in ('versioning', 'versioning='):
            status = 'Enabled' if config.get('versioning', True) else 'Disabled'
            vxml = '''
            <VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>{status}</Status></VersioningConfiguration>
            '''.format(status=status)
            return xml_response(vxml)
        elif qs in ('logging', 'logging='):
            return xml_response('')

        it = request.args.get('iter')
        delimiter = request.args.get('delimiter', '')
        end_key = request.args.get('end')
        marker = request.args.get('marker')
        # print(request.args)
        s3iter = list_bucket(fs, bucket, prefix=prefix, delimiter=delimiter, marker=marker, versions='versions' in request.query_string)
        async def iterator(resp):
            try:
                for chunk in s3iter:
                    resp.write(chunk)
            except KeyError:
                resp.write(aws_error_response(404, 'BucketNotFound', bucket, bucket=bucket).body)
        # else:
        #     try:
        #         index_value = get_website_index(shelf, bucket, b'')
        #     except exceptions.NotFound:
        #         index_value = None
        #     if index_value:
        #         return response.raw(index_value.data, index_value.content_type)
        #     else:
        #         return msg_response(shelf.bucket_size(bucket))
        return xml_response(iterator=iterator)

    async def put(self, request, bucket):
        # bucket_name = auth.add_bucket(request.app.fs, request['user'], bucket)
        return response.text(bucket_name)

    async def post(self, request, bucket):
        fs = request.app.fs
        if request.query_string == 'delete=':
            tree = get_xml(request)
            keys = [key.text for key in tree.findall('Object/Key')]
            resp = '<?xml version="1.0" encoding="UTF-8"?>\n<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
            user = request['username']
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

    async def delete(self, request, bucket):
        request.app.fs.rmtree('/' + bucket, owner=request['username'])
        return xml_response('')

    async def head(self, request, bucket):
        return response.text('')


class ObjectView(HTTPMethodView):
    def path(self, bucket, key):
        return unquote('/{}/{}'.format(bucket, key))

    async def get(self, request, bucket, key):
        if 'uploadId' in request.args:
            return await self.multipart_upload(request, bucket, key)
        fs = request.app.fs
        headers = {}
        status = 200
        path = self.path(bucket, key)
        # print('GETTING', path)
        owner = request['username']
        try:
            fp = fs.open(path, owner=owner)
        except FileNotFoundError:
            path
            return aws_error_response(404, 'NoSuchKey', key, bucket=bucket, key=key)
        except PermissionError:
            return aws_error_response(403, 'AccessDenied', key, bucket=bucket, key=key)
        # except KeyError:
        #     # if this bucket is a "website", try serving an index.html
        #     if key.endswith(b'/'):
        #         value = get_website_index(shelf, bucket, key)
        #     else:
        #         return aws_error_response(404, 'NoSuchKey', key, bucket=bucket, key=key)
        for key, value in fp.meta.items():
            headers['x-amz-meta-%s' % key] = value if isinstance(value, str) else value.decode('utf8')
        headers['x-amz-rev'] = str(fp.rev)

        return good_response(request,
                            fp,
                            headers=headers)

    async def head(self, request, bucket, key):
        resp = await self.get(request, bucket, key)
        resp.body = b''
        return resp

    @stream_decorator
    async def put(self, request, bucket, key):
        if 'uploadId' in request.args:
            return await self.multipart_upload(request, bucket, key)

        fs = request.app.fs
        # data = request.body or b''
        value = None
        copy = False
        owner = request['username'] or 'anon'

        # if 'x-amz-copy-source' in request.headers:
        #     # copy an object from the given bucket
        #     copy_bucket, copy_key = request.headers['x-amz-copy-source'][1:].encode('utf8').split(b'/', 1)
        #     can, error_code = auth.can_access_bucket(shelf,
        #                             copy_bucket,
        #                             user=request['user'],
        #                             headers=request.headers,
        #                             url=request.url,
        #                             operation='r')
        #     if not can:
        #         return aws_error_response(error_code, 'no permission', copy_key, bucket=copy_bucket, key=copy_bucket)
        #     else:
        #         value = shelf.get_from_bucket(copy_bucket, copy_key)
        #         copy = True
        path = self.path(bucket, key)
        if path.endswith('/'):
            # directories are a no-op
            # return response.text('')
            path = path[:-1]
        ctype = request.headers.get('content-type', '')
        print('UPLOADING', path, request.headers, ctype)
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
                await read_request(request, fp)
                print('OWNER IS', fp.owner)
        except PermissionError:
            return aws_error_response(403, 'AccessDenied', key, bucket=bucket, key=key)
        headers = {'Etag': fp.meta['md5']}
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
        return response.text(resp, headers=headers)

    async def delete(self, request, bucket, key):
        path = self.path(bucket, key)
        try:
            if request.app.fs.delete(path, owner=request['username']):
                return response.text('')
            else:
                return aws_error_response(404, 'NoSuchKey', key, bucket=bucket, key=key)
        except PermissionError:
            return aws_error_response(403, 'AccessDenied', key, bucket=bucket, key=key)

    async def post(self, request, bucket, key):
        return await self.multipart_upload(request, bucket, key)

    async def multipart_upload(self, request, bucket, key):
        fs = request.app.fs
        upload_id = request.args.get('uploadId', '')
        partnum = request.args.get('partNumber', '')
        iterator = None
        headers = {}
        body = ''
        path = self.path(bucket, key)
        owner = request['username']
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
            tree = get_xml(request)
            try:
                partial = fs.partial(path, id=upload_id)
            except PermissionError:
                return aws_error_response(403, 'AccessDenied', key, bucket=bucket, key=key)
            async def iterator(response):
                partnums = []
                for part in tree.findall('{http://s3.amazonaws.com/doc/2006-03-01/}Part/{http://s3.amazonaws.com/doc/2006-03-01/}PartNumber'):
                    partnums.append(part.text)
                print(partnums)
                try:
                    value = partial.combine(partnums, owner=owner)
                except FileNotFoundError:
                    return aws_error_response(404, 'NoSuchUpload', key, bucket=bucket, key=key)
                etag = value.meta['sha256']
                # etag = get_etag(value.data)
                url = request.path
                body = '''<?xml version="1.0" encoding="UTF-8"?>
            <CompleteMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
              <Location>{url}</Location>
              <Bucket>{bucket}</Bucket>
              <Key>{key}</Key>
              <ETag>{etag}</ETag>
            </CompleteMultipartUploadResult>'''.format(url=url, bucket=bucket, key=key, etag=etag)
                print(body)
                response.write(body)
        elif request.method == 'PUT':
            partial = fs.partial(path, id=upload_id)
            content_type = request.headers.get('Content-Type', 'application/octet-stream')
            body_md5 = request.headers.get('Content-MD5')
            buf = partial.open_part(partnum)
            await read_request(request, buf)
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
            async def iterator(response):
                response.write(start_xml)
                firstnum = None
                try:
                    maxparts = 0
                    partnum = 0
                    for partnum, meta in partial.list():
                        if firstnum is None:
                            response.write('''<PartNumberMarker>{partnum}</PartNumberMarker>'''.format(partnum))
                            firstnum = partnum
                        response.write('''
                        <Part>
                          <PartNumber>{partnum}</PartNumber>
                          <ETag>&quot;{etag}&quot;</ETag>
                          <Size>{size}</Size>
                        </Part>
                        '''.format(partnum=partnum, etag=meta.get('md5'), size=meta['length']))
                        maxparts = partnum
                except KeyError:
                    # no parts?
                    partnum = 0
                    maxparts = 1
                response.write('''
                <NextPartNumberMarker>{lastpartnum}</NextPartNumberMarker>
                <IsTruncated>false</IsTruncated>
                <MaxParts>{maxparts}</MaxParts>
                </ListPartsResult>
                '''.format(maxparts=maxparts, lastpartnum=partnum + 1))
        return xml_response(body, iterator=iterator, headers=headers)


@bp.route('/')
async def index(request):
    fs = request.app.fs
    user = request['username']
    iterator = auth.available_buckets(fs, user=user)
    async def stream(response):
        list_buckets = '''<?xml version="1.0" encoding="UTF-8"?>
        <ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
            <Owner>
                <ID>%s</ID>
                <DisplayName>%s</DisplayName>
            </Owner>
            <Buckets>
        '''
        response.write(list_buckets % (user, user))
        for info in iterator:
            data = '<Bucket><CreationDate>%sZ</CreationDate><Name>%s</Name></Bucket>' % (datetime.utcnow().isoformat(), info)
            response.write(data)
        response.write('</Buckets></ListAllMyBucketsResult>')
    return xml_response(iterator=stream)


class SimpleAPI(HTTPMethodView):
    async def list(self, request, path):
        listiter = request.app.fs.listdir(path, owner=request['username'])
        async def iterator(resp):
            for p in listiter:
                resp.write(response.json_dumps(p) + '\n')
        return response.StreamingHTTPResponse(iterator, status=200, content_type='application/json')

    async def get(self, request, path):
        path = unquote('/' + path)
        if path.endswith('/'):
            return await self.list(request, path)

        fs = request.app.fs
        rev = request.args.get('rev', None)
        if rev:
            rev = int(rev)
        try:
            fp = fs.open(path, owner=request['username'], rev=rev)
        except FileNotFoundError:
            raise exceptions.NotFound(path)
        except PermissionError:
            raise exceptions.Forbidden(path)
        headers = {}
        for key, value in fp.meta.items():
            headers['x-meta-%s' % key] = value if isinstance(value, str) else value.decode('utf8')
        headers['x-rev'] = str(fp.rev)

        return good_response(request,
                            fp,
                            headers=headers)
            

    async def put(self, path):
        path = unquote('/' + path)
        fs = request.app.fs
        ctype = request.headers.get('content-type', '')
        print('UPLOADING', path, request.headers, ctype)
        try:
            with fs.open(path, mode='w', owner=request['username']) as fp:
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
                await read_request(request, fp)
        except FileNotFoundError:
            raise exceptions.NotFound(path)
        except PermissionError:
            raise exceptions.Forbidden(path)
        return response.text(fp.meta['md5'])

    async def delete(self, path):
        path = unquote('/' + path)
        fs = request.app.fs
        try:
            if request.app.fs.delete(path, owner=request['username']):
                return response.text('')
            else:
                raise exceptions.NotFound(path)
        except PermissionError:
            raise exceptions.Forbidden(path)
        return response.text('')


bp.add_route(SimpleAPI.as_view(), '/.simple/v1/<path:path>')
bp.add_route(ObjectView.as_view(), '/<bucket>/<key:path>')
bp.add_route(BucketView.as_view(), '/<bucket>')