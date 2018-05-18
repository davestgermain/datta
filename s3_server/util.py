from datetime import datetime
import time
from hashlib import md5
from xml.etree.ElementTree import fromstring
from sanic import response, exceptions
from sanic.handlers import ContentRangeHandler
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

def get_etag(data):
    return '"%s"' % md5(data or b'').hexdigest()

def get_xml(request):
    return fromstring(request.body.decode('utf8'))

def good_response(request, fileobj, headers=None):
    headers = headers or {}
    content_type = fileobj.content_type or 'application/octet-stream'
    if not isinstance(content_type, str):
        content_type = content_type.decode('utf8')

    headers['Content-Type'] = content_type
    headers['Last-Modified'] = fileobj.modified.strftime("%a, %d %b %Y %H:%M:%S GMT")
    
    status = 200
    headers['Accept-Ranges'] = 'bytes'
    brange = request.headers.get('range')

    body = b''
    to_read = -1
    ranger = None
    if brange:
        fileobj.st_size = fileobj.length
        ranger = ContentRangeHandler(request, fileobj)
        headers.update(ranger.headers)
        fileobj.seek(ranger.start)
        
        to_read = ranger.size
        status = 206
    else:
        etag = fileobj.meta.get('md5') or fileobj.meta.get('sha256') or ''
        if etag:
            headers['Etag'] = etag
        if etag and request.headers.get('if-none-match') == etag:
            status = 304
            body = b''
            to_read = 0
        else:
            if_date = request.headers.get('If-Modified-Since', '')
            if if_date:
                ts = datetime.strptime(if_date, "%a, %d %b %Y %H:%M:%S %Z")
                if ts >= fileobj.modified:
                    status = 304
                    body = b''
                    to_read = 0
    if request.method == 'HEAD':
        body = b''
        to_read = 0

    if status >= 200 and (fileobj.length >= 65535 and (to_read == -1 or to_read >= 65535)):
        if to_read == -1:
            to_read = fileobj.length
        async def iterator(response):
            nonlocal to_read, fileobj
            while to_read > 0:
                chunk = await fileobj.aread(min(to_read, 4096))
                if chunk:
                    response.write(chunk)
                    to_read -= len(chunk)
                else:
                    break
            fileobj.close()
        return response.StreamingHTTPResponse(iterator, status=status, headers=headers, content_type=content_type)
    else:
        if to_read:
            # print('reading', to_read, body)
            body = fileobj.read(to_read)
            # print(body)
        headers['Content-Length'] = len(body)
        fileobj.close()
        return response.HTTPResponse(body_bytes=body, headers=headers, status=status, content_type=content_type)


def xml_response(body=None, status=200, iterator=None, **kwargs):
    if iterator is not None:
        return response.stream(iterator, content_type='text/xml', status=status, **kwargs)
    else:
        return response.text(body, content_type='text/xml', status=status, **kwargs)

def aws_error_response(status, code, message, bucket='', key=''):
    request_id = next(counter)
    message = ERROR_XML.format(**locals())
    resp = xml_response(message, status=status)
    # if status in (401, 403):
    #     resp.headers['WWW-Authenticate'] = 'Basic realm="Auth Required"'
    return resp

