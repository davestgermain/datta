"""
functions and classes for Content Addressable Storage
"""
import abc
import datetime
import struct
import hashlib
from datta.pack import make_record_class
from datta.fs.base import Perm, Owner, VersionedFile
try:
    import snappy
except ImportError:
    snappy = None


now = datetime.datetime.utcnow


CasHistoryInfo = make_record_class('CasHistoryInfo', [
        ('path', str),
        ('owner', str),
        ('content_type', str),
        ('rev', int),
        ('length', int),
        ('created', datetime.datetime),
        ('bs', int),        # block size for data blocks
        ('ps', int),        # block size for pointer blocks (multiple of the key size)
        ('root', bytes),    # key for current version of data block
        ('prev', bytes),    # key for previous version of data block
        ('parent', bytes),  # key that links to previous record of this object
        ('meta', dict),
    ])

CasDir = make_record_class('CasDir', [
        ('files', dict),
        ('parent', bytes),
])

@classmethod
def dir_from_key(cls, key, fs):
    block = fs.cas_readblock(key)
    info = CasHistoryInfo.from_bytes(block)
    obj = cls.from_bytes(b''.join(fs.cas_walk_blocks(info.root)))
    return obj
CasDir.from_key = dir_from_key


class BaseCASManager(abc.ABC):
    CAS_COMPRESSED = 1
    CAS_UNCOMPRESSED = 0
    CAS_KEY_SIZE = 21
    CAS_POINTER_SIZE = 21504
    CAS_BLOCKSIZE = 65536

    @abc.abstractmethod
    def readblock(self, key, **kwargs):
        pass

    @abc.abstractmethod
    def writeblock(self, level, block, **kwargs):
        pass

    def walkblocks(self, start_key, verify=False, return_keys=False, **kwargs):
        """
        Walk the block tree, starting from a pointer or data block
        """
        keys = [start_key]
        if return_keys:
            yield start_key
        while keys:
            key = keys.pop(0)
            block = self.readblock(key, verify=verify, **kwargs)
            depth = key[0]
            if depth:
                # this is a pointer block
                while block:
                    key, block = block[:self.CAS_KEY_SIZE], block[self.CAS_KEY_SIZE:]
                    keys.append(key)
            else:
                if return_keys:
                    yield bytes(key)
                else:
                    yield block

    def writepointers(self, pointer_size, pointer, level, **kwargs):
        refs = bytearray()
        while pointer:
            cur_pointer, pointer = pointer[:pointer_size], pointer[pointer_size:]
            refs += self.writeblock(level, bytes(cur_pointer), **kwargs)
        if len(refs) > self.CAS_KEY_SIZE:
            return self.writepointers(pointer_size, refs, level + 1, **kwargs)
        else:
            return bytes(refs), level

    def writefile(self, meta, buf, hasher=None, **kwargs):
        prev = meta.pop('root', None)
        meta['created'] = now()
        hist = CasHistoryInfo.from_dict(meta)
        if not hist.ps:
            hist.ps = self.CAS_POINTER_SIZE
        if not hist.bs:
            hist.bs = self.CAS_BLOCKSIZE
        hist.prev = prev

        depth = 0
        pointers = bytearray()

        while 1:
            chunk = buf.read(hist.bs)
            if not chunk:
                break
            if hasher:
                hasher.update(chunk)
            key = self.writeblock(depth, chunk, **kwargs)
            pointers += key
        if not pointers:
            # still should write the zero block
            pointers = self.writeblock(0, b'', **kwargs)
        if len(pointers) > self.CAS_KEY_SIZE:
            root_hash, level = self.writepointers(hist.ps, pointers, 1, **kwargs)
        else:
            root_hash = bytes(pointers)
            level = 0
        hist.root = root_hash
        return hist, level + 1

    def info_from_block(self, key, **kwargs):
        block = self.readblock(key, **kwargs)
        if block:
            return CasHistoryInfo.from_bytes(block)

    def opendir(self, dirname, rev=None):
        assert dirname.endswith('/')
        d = Directory(self, dirname[:-1])
        d.load(rev)
        return d

    def get_file_chunks(self, file_info, cipher=None):
        if cipher:
            decrypt = cipher['decrypt']
        else:
            decrypt = None
        # this is a CAS file
        for block in self.walkblocks(file_info.root):
            if decrypt:
                block = decrypt(block)
            yield block

    def get_file_chunk(self, file_info, chunk, cipher=None, **kwargs):
        # this is a CAS file
        # must figure out how to find the offset within the pointers
        # files ~< 64MB will have only 1 level of pointers
        keysize = self.CAS_KEY_SIZE
        readblock = self.readblock

        depth, chksum = struct.unpack('>B20s', file_info.root)
        block = readblock(bytes(file_info.root), **kwargs)
        ptr_per_block = int(file_info.ps / keysize)
        ptr_num, offset = divmod(chunk, ptr_per_block)
        while depth > 1:
            depth -= 1
            boffset = (depth * ptr_num) * keysize
            key = bytes(block[boffset:boffset + keysize])
            block = readblock(key, **kwargs)
        offset *= keysize
        key = bytes(block[offset:offset + keysize])
        data = readblock(key, **kwargs)

        if cipher:
            data = cipher['decrypt'](data)
        return data


class KVCASManager(BaseCASManager):
    def __init__(self, kv):
        self.kv = kv
        self._basekey = kv._cas
        self.open = kv.open
        self.close = kv.close

    def writeblock(self, level, block, tr=None):
        """
        Write a block to the Content Addressed Storage area of the keyspace
        """
        # sha512 is faster than sha256, but we don't need so many bits
        csum = hashlib.sha512(block).digest()[:20]
        hkey = struct.pack('>B20s', level, csum)
        key = self._basekey[hkey]

        tr = tr or self.kv._begin(write=True, buffers=True)
        with tr:
            if not tr.get(key):
                blen = len(block)
                prefix = self.CAS_UNCOMPRESSED
                if snappy:
                    compressed = snappy.compress(block)
                    if len(compressed) < (blen * .8):
                        prefix = self.CAS_COMPRESSED
                        block = compressed
                tr[key] = struct.pack('b', prefix) + block
        return hkey

    def readblock(self, key, verify=False, tr=None):
        """
        Read a block from the Content Addressed Storage area
        """
        key = bytes(key)
        tr = tr or self.kv._begin(buffers=True)
        with tr:
            block = tr.get(self._basekey[key])
            if block:
                # print('READBLOCK', key.hex(), len(block))
                prefix, block = block[0], block[1:]
                if prefix == self.CAS_COMPRESSED:
                    block = snappy.decompress(bytes(block))
                if verify:
                    level, csum = struct.unpack('>B20s', key)
                    calc = hashlib.sha512(block).digest()[:20]
                    if calc != csum:
                        mess = 'Hash mismatch %s != %s' % (calc, csum)
                        raise IOError(mess)
        return block

    def writefile(self, meta, buf, hasher=None, **kwargs):
        with self.kv._begin(buffers=True, write=True) as tr:
            kwargs['tr'] = tr
            return BaseCASManager.writefile(self, meta, buf, hasher=hasher, **kwargs)

    def walkblocks(self, start_key, verify=False, return_keys=False, **kwargs):
        with self.kv._begin(buffers=True) as tr:
            kwargs['tr'] = tr
            for block in BaseCASManager.walkblocks(self, start_key, verify=verify, return_keys=return_keys, **kwargs):
                yield block

    def _blockkey(self, key):
        # converts kv key to CAS key
        if hasattr(key, 'key'):
            return self.kv._cas.unpack(key.key())[0]
        else:
            return key

    def missing(self, keys):
        with self._begin(buffers=True) as tr:
            for key in keys:
                if tr.get(self._basekey[key], None) is None:
                    yield key


class SyncRemoteManager(BaseCASManager):
    def __init__(self, addr=('127.0.0.1', 10811)):
        self.addr = addr
        self.sock = None
        self.rfile = self.wfile = None

    def connect(self, do_ssl=False):
        import socket
        self.sock = socket.create_connection(self.addr)
        if do_ssl:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            self.sock = ctx.wrap_socket(self.sock)
        self.rfile = self.sock.makefile('rb')
        self.wfile = self.sock.makefile('wb')
        print('connected to %s:%s' % self.addr, self.rfile.readline().strip().decode('utf8'))

    def readblock(self, key, verify=False):
        message = b'R %s\n' % key
        self._send(message)
        resp =  self.rfile.read(4)
        if resp != b'ERRR':
            length = struct.unpack('>I', resp)[0]
            block = self.rfile.read(length)
            if verify:
                if hashlib.sha512(block).digest()[:20] != key[1:]:
                    raise Exception('Bad block!')
        else:
            block = None
        return block

    def writeblock(self, level, block):
        message = b'W %s\n' % struct.pack('>BI', level, len(block))
        message += block
        self._send(message)
        length = struct.unpack('>I', self.rfile.read(4))[0]
        key = self.rfile.read(length)
        assert len(key) == 21, key
        return key

    def walkblocks(self, key):
        message = b'T %s\n' % key
        self._send(message)
        while 1:
            resp = self.rfile.read(4)
            if resp == b'':
                break
            if resp != b'ERRR':
                length = struct.unpack('>I', resp)[0]
                block = self.rfile.read(length)
                yield block
            else:
                yield None

    def missing(self, keys):
        missing = []
        while keys:
            to_check, keys = keys[:10000], keys[10000:]
            message = b'H ' + b''.join(to_check)
            self._send(message)
            while 1:
                resp = self.rfile.read(21)
                if resp != b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00':
                    missing.append(resp)
                else:
                    break
        return missing

    def get_stats(self):
        import json
        message = b'S\n'
        self._send(message)
        return json.loads(self.rfile.readline().decode('utf8'))

    def _send(self, message):
        if not self.sock:
            self.connect()
        lm = len(message)
        mess = struct.pack('>I', lm) + message
        self.wfile.write(mess)
        self.wfile.flush()
        
    def close(self):
        self._send(b'Q\n')
        self.wfile.close()
        self.rfile.close()
        self.sock.close()
        self.sock = None

    def __enter__(self):
        if not self.sock:
            self.connect()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        if exc:
            import six
            six.reraise(exc_type, exc, tb)


class Directory:
    """
    Access methods for Content Addressable Storage
    use Manager.cas_opendir() to open a directory,
    then normal file operations from this object
    """
    def __init__(self, manager, root, current_dir=None, parent=None):
        self.root = root
        self.current_dir = current_dir or root
        self.parent = parent
        self.man = manager
        self.record = None
        self.my_info_block = None
        self.my_data_block = None
        self.rev = -1
        self.get_file_chunks = manager.get_file_chunks
        self.get_file_chunk = manager.get_file_chunk

    def __repr__(self):
        return 'Directory(%s:%s) -> %s' % (self.current_dir, self.rev, self.root)

    def load(self, rev=None):
        my_block = None
        try:
            if self.parent:
                fp = self.parent.open(self.current_dir, mode=Perm.read, rev=rev)
            else:
                fp = self.man.open(self.root, mode=Perm.read, rev=rev)
            with fp:
                record = CasDir.from_bytes(fp.read())
                rev = fp.rev
                my_block = fp._file_info.history_key
                my_data_block = fp._file_info.root
                if not self.parent:
                    # hmm...
                    my_block = self.man._blockkey(my_block)
        except FileNotFoundError:
            record = CasDir.from_dict({})
            rev = -1
            my_data_block = None
        self.record = record
        self.rev = rev
        self.my_info_block = my_block
        self.my_data_block = my_data_block

    def save(self, extra_info=None):
        if self.parent:
            fp = self.parent.open(self.current_dir, mode=Perm.write)
        else:
            fp = self.man.open(self.root, mode=Perm.write)
        with fp:
            fp.content_type = u'application/x-cas-directory'
            self.record.parent = self.my_info_block
            fp.write(self.record.to_bytes())
            if not self.parent:
                # root file should be a CAS file
                fp.meta[u'CAS'] = True
            # clear old meta info
            for k in ('comment', 'op', 't'):
                fp.meta.pop(k, None)
            if extra_info:
                fp.meta.update(extra_info)
        self.load()

    def delete(self, path, owner=u'*', include_history=False, force_timestamp=None):
        path = self._get_fname(path)
        try:
            del self.record.files[path]
        except KeyError:
            return False
        self.save({'op': 'rm', 't': os.path.join(self.root, path)})

    def rename(self, frompath, topath, owner=Owner.ALL, record_move=True):
        assert topath.startswith(self.root)
        fname = self._get_fname(frompath)
        path, filename = os.path.split(topath)
        assert filename
        hist = self.record.files.pop(fname, None)
        if not hist:
            raise FileNotFoundError(fname)
        hist = CasHistoryInfo.from_bytes(hist)
        
        if path:
            d = self.chdir(path)
        else:
            d = self
        hist.path = filename
        d.record.files[filename] = hist.to_bytes()
        d.save({'op': 'mv', 't': [frompath, topath]})

    def listdir(self, walk=False, owner=None, limit=0, open_files=False):
        count = 0
        for name, h in sorted(self.record.files.items()):
            if open_files:
                yield self.open(name, owner=owner)
            else:
                yield CasHistoryInfo.from_bytes(h)
            count += 1
            if limit and limit == count:
                break
            if walk and name.endswith('/'):
                subdir = name
                for info in self.chdir(subdir).listdir(walk=True, open_files=open_files, owner=owner):
                    info.path = os.path.join(subdir, info.path)
                    yield info
                    count += 1
                    if limit and limit == count:
                        break

    def _get_fname(self, path):
        if path.endswith('/'):
            fname = path.split('/')[-2] + '/'
        else:
            fname = os.path.basename(path)
        return fname

    def save_file_data(self, path, meta, buf, cipher=None):
        fname = self._get_fname(path)
        old_info = meta.pop(u'file_info', None)
        meta['root'] = old_info.get('root')
        meta['path'] = fname
        meta['rev'] = old_info.get('rev', -1) + 1 if old_info else 0
        meta['parent'] = self.my_info_block
        hist, level = self.man.writefile(meta, buf, None)
        self.record.files[fname] = hist.to_bytes()
        # print('SAVED', fname, hist.rev)
        # to propagate comments up the tree, save them in the file's metadata
        info = {}
        for key in ('op', 't', 'comment'):
            if hist.meta.get(key):
                info[key] = hist.meta[key]
        self.save(info)

    def get_file_metadata(self, path, rev):
        fname = self._get_fname(path)
        hist = self.record.files.get(fname)
        if not hist:
            return {}
        hist = CasHistoryInfo.from_bytes(hist)
        if rev is not None and rev != hist.rev:
            startkey = self.my_info_block
            while hist.rev != rev and startkey:
                try:
                    record = CasDir.from_key(startkey, self.man)
                    hist = CasHistoryInfo.from_bytes(record.files[fname])
                    startkey = record.parent
                except KeyError:
                    return {}
        hist.history_key = self.my_info_block
        return hist

    def get_metadata_and_check_perm(self, filename, rev, mode=Perm.read, owner=Owner.ALL):
        self.man.check_perm(os.path.join(self.current_dir, filename), owner=owner, perm=mode)    
        return self.get_file_metadata(filename, rev)

    def get_meta_history(self, path):
        if path is None:
            # history for entire tree
            start = self.my_info_block
            while start:
                block = self.man.readblock(start)
                info = CasHistoryInfo.from_bytes(block)
                yield info
                start = info.parent
        else:
            fname = self._get_fname(path)
            hist = self.record.files.get(fname)
            if hist:
                hist = CasHistoryInfo.from_bytes(hist)
                yield hist
            if self.record.parent:
                start = self.record.parent
                while hist.rev > -1:
                    try:
                        record = CasDir.from_key(start, self.man)
                        yield CasHistoryInfo.from_bytes(record.files[fname])
                        start = record.parent
                    except KeyError:
                        break

    def open(self, filename, mode=Perm.read, owner=Owner.ALL, rev=None):
        if filename.startswith('/'):
            filename = self._get_fname(filename)
        elif filename.count('/') > 0 and not filename.endswith('/'):
            # need to open a directory to this path
            path, filename = os.path.split(filename)
            if not filename:
                # means we're trying to open a subdirectory somewhere
                path, filename = path.rsplit('/', 1)
                filename += '/'
            return self.chdir(path).open(filename, mode=mode, owner=owner, rev=rev)
        return VersionedFile(self, os.path.join(self.current_dir, filename), mode=mode, rev=rev, requestor=owner)

    def chdir(self, dirname, rev=None):
        if not dirname.endswith('/'):
            dirname += '/'
        if dirname.startswith('/'):
            dirname = dirname[1:]
        if dirname.count('/') > 1:
            # need to open/create subdirectories
            d = None
            for subdir in dirname.split('/')[:-1]:
                d = (d or self).chdir(subdir, rev=rev)
        else:
            d = Directory(self.man, self.root, os.path.join(self.current_dir, dirname), parent=self)

            d.load(rev=rev)
        return d

    def blockkeys(self):
        """
        Returns CAS block keys for all associated files
        """
        seen = set()
        yield self.my_info_block
        yield self.my_data_block
        for info in self.listdir(walk=True):
            for k in (info.root, info.parent):
                if k and k not in seen:
                    yield k
                    seen.add(k)
