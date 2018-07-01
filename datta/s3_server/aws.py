import os.path
import hashlib
from html import escape


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

def list_available_buckets(fs, username):
    pass

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


    iterator = fs.listdir(path, owner=owner or '*', delimiter=delimiter, walk=not delimiter)
    preamble = '''<?xml version="1.0" encoding="UTF-8"?>'''\
'''<%s xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
        <Name>%s</Name>
        <Prefix>%s</Prefix>
        <MaxKeys>%s</MaxKeys>
        <Delimiter>%s</Delimiter>
        <Marker>%s</Marker>
''' % (element, bucket, prefix, maxkeys, delimiter, marker or '')

    if versions:
        preamble += '<VersionIdMarker></VersionIdMarker>'

    bucket_prefix = '/%s/' % bucket

    contents, count, last_key, is_truncated, subdirs, last_marker = make_contents(fs, iterator, bucket_prefix, maxkeys=maxkeys, versions=versions, marker=marker)
    yield preamble
    yield from contents
    if last_key:
        yield '<NextContinuationToken>%s</NextContinuationToken>' % last_key
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
    yield '<NextMarker>%s</NextMarker>' % last_marker
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
