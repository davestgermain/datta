import os.path


async def write_async(write_buf, chunk):
    write_buf.write(chunk)

async def read_request(request, write_buf):
    """
    Reads a chunked AWS request, and writes into write_buf
    """
    if request.headers.get('x-amz-content-sha256') == 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD':
        # if request.stream:
        #     while True:
        #         chunk = await request.stream.get()
        #         if chunk is None:
        #             break
        #         fp.write(chunk)
        
        body = request.body
        data = b''
        while body:
            cline, body = body.split(b'\r\n', 1)
            size, sig = cline.split(b';')
            size = int(size, 16)
            if size == 0:
                break
            await write_async(write_buf, body[:size])
            # chunk ends with \r\n
            body = body[size + 2:]
    else:
        await write_async(write_buf, request.body)


def make_contents(fs, iterator, bucket_prefix, maxkeys=1000, versions=False):
    is_truncated = 'false'
    contents = []
    last_key = None
    for row in iterator:
        key = row.path.replace(bucket_prefix, '', 1)
        if key == bucket_prefix[:-1]:
            continue
        # if delimiter:
        #     skey = key[prefix_len:].split(delimiter)
        #     if len(skey) > 1:
        #         common_prefixes.add(prefix + skey[0] + delimiter)
        #         continue
        # if marker and key <= marker:
        #     continue
        if versions:
            rows = fs.get_meta_history(row.path)
            latest_rev = row.rev
        else:
            rows = [row]
        for row in rows:
            if row.get('content_type') == 'application/x-directory':
                continue
            modified = row.get('modified', row.created).isoformat() + 'Z'
            created = row.get('created').isoformat() + 'Z'
            etag = row.meta.get('md5') or row.meta.get('sha256') or 'default'
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
    '''.format(key=key, size=row.get('length', 0), created=created, modified=modified, etag=etag, owner=owner)
            contents.append(doc)
            if versions:
                contents.append('<VersionID>{rev}</VersionID>'.format(rev=row.rev))
                if row.rev == latest_rev:
                    contents.append('<IsLatest>true</IsLatest>')
                contents.append('</Version>')
            else:
                contents.append('</Contents>')
        
        last_key = key
        if len(contents) == maxkeys:
            is_truncated = 'true'
            break

    return contents, last_key, is_truncated

def list_available_buckets(fs, username):
    pass

def list_bucket(fs, bucket, prefix='', maxkeys=1000, delimiter='/', marker=None, versions=False):
    """
    Returns XML for S3 list_bucket API
    """
    path = '/'.join(['', bucket, prefix])
    # if not prefix:
    #     path += '/'

    element = 'ListBucketResult'
    if versions:
        element = 'ListVersionsResult'

    iterator = fs.listdir(path, delimiter=delimiter, limit=maxkeys, walk=not delimiter)
    preamble = '''<?xml version="1.0" encoding="UTF-8"?>'''\
'''<%s xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
        <Name>%s</Name>
        <Prefix>%s</Prefix>
        <MaxKeys>%s</MaxKeys>
        <Delimiter>%s</Delimiter>
''' % (element, bucket, prefix, maxkeys, delimiter)


    bucket_prefix = '/%s/' % bucket
    contents, last_key, is_truncated = make_contents(fs, iterator, bucket_prefix, maxkeys=maxkeys, versions=versions)
    count = len(contents)
    yield preamble
    yield from contents
    if last_key:
        yield '<NextContinuationToken>%s</NextContinuationToken>' % last_key
    yield '<KeyCount>%d</KeyCount><IsTruncated>%s</IsTruncated>' % (count, is_truncated)

    if delimiter:
        subdirs = fs.common_prefixes(path, delimiter)
        if subdirs:
            next_token = None
            for cp, count in sorted(subdirs):
                if next_token is None:
                    next_token = cp
                cp = cp.replace(bucket_prefix, '', 1)
                if cp:
                    yield '<CommonPrefixes><Prefix>%s%s</Prefix></CommonPrefixes>' % (cp, delimiter)
            yield '<NextContinuationToken>%s</NextContinuationToken>' % next_token
    yield '</%s>' % element

def list_partials(fs, bucket):
    resp = ['''<?xml version="1.0" encoding="UTF-8"?>
    <ListMultipartUploadsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
      <Bucket>{bucket}</Bucket>
      <KeyMarker></KeyMarker>
      <UploadIdMarker></UploadIdMarker><IsTruncated>false</IsTruncated>'''.format(bucket=bucket)]

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
        resp.append(upload)
    resp.append('</ListMultipartUploadsResult>')
    return resp
    
if __name__ == '__main__':
    from datta.fs import get_manager
    man = get_manager('fdb')
    result = list(list_bucket(man, 'foo', prefix=''))
    print(result)
