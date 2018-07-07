from datetime import datetime
import time
from hashlib import md5
from xml.etree.ElementTree import fromstring
from quart import Response, request
from quart.datastructures import Range, ContentRange

async def asynread(fp, size=-1):
    return fp.read(size)


def get_etag(data):
    return '"%s"' % md5(data or b'').hexdigest()


def good_response(fileobj, headers=None):
    headers = headers or {}
    content_type = fileobj.content_type or 'application/octet-stream'
    if not isinstance(content_type, str):
        content_type = content_type.decode('utf8')

    headers['Content-Type'] = content_type
    headers['Last-Modified'] = fileobj.modified.strftime("%a, %d %b %Y %H:%M:%S GMT")
    headers['x-amz-version-id'] = str(fileobj.rev)
    for key, value in fileobj.meta.items():
        if isinstance(value, bytes):
            value = value.decode('utf8')
        else:
            value = str(value)
        headers['x-amz-meta-%s' % key] = value

    status = 200
    headers['Accept-Ranges'] = 'bytes'
    brange = request.headers.get('range')

    body = b''
    to_read = -1
    ranger = None
    if not brange:
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
    else:
        try:
            ranger = Range.from_header(brange)
        except ValueError:
            print('BAD RANGE HEADER', brange)
        else:
            fr = ranger.ranges[0]

            headers['Content-Range'] = ContentRange(ranger.units, fr.begin, fr.end, fileobj.length).to_header()
            fileobj.seek(fr.begin)
        
            to_read = (fr.end - fr.begin) + 1
            status = 206

    if request.method == 'HEAD':
        resp = Response('', headers=headers)
        resp.content_length = fileobj.length
        return resp

    if status >= 200 and (fileobj.length >= 65535 and (to_read == -1 or to_read >= 65535)):
        if to_read == -1:
            to_read = fileobj.length
        async def iterator(to_read):
            blocksize = getattr(fileobj, 'bs', 8192)
            # blocksize = 16384
            with fileobj:
                while to_read > 0:
                    chunk = await asynread(fileobj, min(to_read, blocksize))
                    if chunk:
                        yield chunk
                        to_read -= len(chunk)
                    else:
                        break
        return Response(iterator(to_read), status=status, headers=headers, content_type=content_type)
    else:
        if to_read:
            with fileobj:
                body = fileobj.read(to_read)
            # print(repr(body))
        return Response(body, headers=headers, status=status, content_type=content_type)



