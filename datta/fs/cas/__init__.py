"""
functions and classes for Content Addressable Storage
"""
import abc
import datetime
import struct
import hashlib
import os.path
import traceback
from datta.pack import make_record_class
from datta.cache import Cache
from datta.fs.base import Perm, Owner, VersionedFile
try:
    import snappy
except ImportError:
    snappy = None


CAS_COMPRESSED = 1
CAS_UNCOMPRESSED = 0
CAS_KEY_SIZE = 21
CAS_POINTER_SIZE = 21504
CAS_BLOCKSIZE = 65536
CAS_EMPTY_BLOCK = b'\x00\xcf\x83\xe15~\xef\xb8\xbd\xf1T(P\xd6m\x80\x07\xd6 \xe4\x05'


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
    if key:
        block = fs.readblock(key)
        info = CasHistoryInfo.from_bytes(block)
        obj = cls.from_bytes(b''.join(fs.walkblocks(info.root)))
        return obj
CasDir.from_key = dir_from_key

@classmethod
def dir_from_root(cls, root_key, fs):
    return cls.from_bytes(b''.join(fs.walkblocks(root_key)))
CasDir.from_root = dir_from_root

def get_file(self, filename):
    return CasHistoryInfo.from_bytes(self.files[filename])
CasDir.get_file = get_file


def get_cas_secret(*args):
    """
    return the shared secret for client and server authorization
    can be any byte string
    """
    secret = b'datta'
    for a in args:
        if a:
            if not isinstance(a, bytes):
                a = a.encode('utf8')
            secret += a
    return secret


class BaseCASManager(abc.ABC):
    @abc.abstractmethod
    def readblock(self, key, **kwargs):
        pass

    @abc.abstractmethod
    def writeblock(self, level, block, **kwargs):
        pass

    def _hash_block(self, block):
        return hashlib.sha512(block).digest()[:20]

    def _blockkey(self, key):
        return key

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
            if block is None:
                break
            depth = key[0]
            if depth:
                # this is a pointer block
                keys.extend((block[i:i+CAS_KEY_SIZE] for i in range(0, len(block), CAS_KEY_SIZE)))
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
        if len(refs) > CAS_KEY_SIZE:
            return self.writepointers(pointer_size, refs, level + 1, **kwargs)
        else:
            return bytes(refs), level

    def writefile(self, buf, blocksize=CAS_BLOCKSIZE, pointersize=CAS_POINTER_SIZE, hasher=None, encrypt=None, **kwargs):
        depth = 0
        pointers = bytearray()

        while 1:
            chunk = buf.read(blocksize)
            if not chunk:
                break
            if hasher:
                hasher.update(chunk)
            if encrypt:
                chunk = encrypt(chunk)
            key = self.writeblock(depth, chunk, **kwargs)
            pointers += key
        if not pointers:
            # still should write the zero block
            pointers = self.writeblock(0, b'', **kwargs)
        if len(pointers) > CAS_KEY_SIZE:
            root_key, level = self.writepointers(pointersize, pointers, 1, **kwargs)
        else:
            root_key = bytes(pointers)
            level = 0
        return root_key, level + 1

    def save_file_data(self, path, meta, buf, cipher=None, hasher=None, **kwargs):
        old_info = meta.pop(u'file_info', None)
        if old_info:
            meta['bs'] = old_info.bs
            meta['ps'] = old_info.ps
            meta['prev'] = old_info.get('root')
            if meta.get('rev') is None:
                meta['rev'] = old_info.get('rev', -1) + 1
        else:
            if meta.get('rev') is None:
                meta['rev'] = 0
        meta['path'] = path
        if meta['modified']:
            meta['created'] = meta['modified']
        if not meta['created']:
            meta['created'] = now()
        hash_algo = meta.pop(u'hash', None)
        if hash_algo:
            hasher = getattr(hashlib, hash_algo)()
        else:
            hasher = None
        # print(meta)
        hist = CasHistoryInfo.from_dict(meta)
        if not hist.ps:
            hist.ps = CAS_POINTER_SIZE
        if not hist.bs:
            hist.bs = CAS_BLOCKSIZE
        encrypt = cipher['encrypt'] if cipher else None
        hist.root, level = self.writefile(buf, blocksize=hist.bs, pointersize=hist.ps, hasher=hasher, encrypt=encrypt, **kwargs)
        if hasher:
            hist.meta[hash_algo] = hasher.hexdigest()
        return hist

    def info_from_block(self, key, **kwargs):
        block = self.readblock(key, **kwargs)
        if block:
            return CasHistoryInfo.from_bytes(block)

    def file_from_key(self, key):
        try:
            info = self.info_from_block(key)
        except:
            traceback.print_exc()
            raise IOError('%s not a file' % key)
        if info:
            return VersionedFile(self, info.path, mode=Perm.read, file_info=info)

    def opendir(self, dirname, rev=None, encryption_key=None, auto_save=True, owner=None):
        assert dirname.endswith('/')
        d = Directory(self, dirname[:-1], encryption_key=encryption_key, auto_save=auto_save, root_owner=owner)
        d.load(rev)
        return d

    def get_file_chunks(self, file_info, cipher=None):
        if cipher:
            decrypt = cipher['decrypt']
        else:
            decrypt = None
        depth = file_info.root[0]
        if depth:
            for block in self.walkblocks(file_info.root):
                if decrypt:
                    block = decrypt(block)
                yield block
        else:
            block = self.readblock(file_info.root)
            if decrypt:
                block = decrypt(block)
            yield block

    def get_file_chunk(self, file_info, chunk, cipher=None, **kwargs):
        # this is a CAS file
        # must figure out how to find the offset within the pointers
        # files ~< 64MB will have only 1 level of pointers
        keysize = CAS_KEY_SIZE
        readblock = self.readblock
        depth, chksum = struct.unpack('>B20s', file_info.root)
        block = readblock(bytes(file_info.root), **kwargs)
        if depth == 0:
            # there's only one block
            data = block
        else:
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
        BaseCASManager.__init__(self)
        self.kv = kv
        self._basekey = kv._cas
        self.open = kv.open
        self.close = kv.close
        self.cache = Cache(maxsize=256)

    def __repr__(self):
        return 'KVCASManager(%r)' % self.kv

    def writeblock(self, level, block, tr=None, **kwargs):
        """
        Write a block to the Content Addressed Storage area of the keyspace
        """
        # sha512 is faster than sha256, but we don't need so many bits
        csum = self._hash_block(block)
        hkey = struct.pack('>B20s', level, csum)
        key = self._basekey[hkey]
        self.cache.set(hkey, block)

        tr = tr or self.kv._begin(write=True, buffers=True)
        with tr:
            if not tr.get(key):
                blen = len(block)
                prefix = CAS_UNCOMPRESSED
                if snappy:
                    compressed = snappy.compress(block)
                    if len(compressed) < (blen * .8):
                        prefix = CAS_COMPRESSED
                        block = compressed
                tr[key] = struct.pack('b', prefix) + block
        return hkey

    def readblock(self, key, verify=False, tr=None, **kwargs):
        """
        Read a block from the Content Addressed Storage area
        """
        key = bytes(key)
        block = self.cache.get(key)
        if block is None:
            tr = tr or self.kv._begin(buffers=True)
            with tr:
                block = tr.get(self._basekey[key])
                if block:
                    # print('READBLOCK', key.hex(), len(block))
                    prefix, block = block[0], block[1:]
                    if prefix == CAS_COMPRESSED:
                        block = snappy.decompress(bytes(block))
                    if verify:
                        level, csum = struct.unpack('>B20s', key)
                        calc = self._hash_block(block)
                        if calc != csum:
                            mess = 'Hash mismatch %s != %s' % (calc, csum)
                            raise IOError(mess)
                    self.cache.set(key, bytes(block))
        return block

    def writefile(self, buf, hasher=None, tr=None, **kwargs):
        tr = tr or self.kv._begin(buffers=True, write=True)
        with tr:
            kwargs['tr'] = tr
            return BaseCASManager.writefile(self, buf, hasher=hasher, **kwargs)

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




class Directory:
    """
    Access methods for Content Addressable Storage
    use Manager.cas.opendir() to open a directory,
    then normal file operations from this object
    """
    def __init__(self, manager, root, current_dir=None, parent=None, encryption_key=None, auto_save=True, root_owner=None):
        self.root = root
        self.current_dir = current_dir or root
        self.parent = parent
        self.man = manager
        self.auto_save = auto_save
        self.encryption_key = encryption_key
        self.record = None
        self.root_owner = root_owner
        self._recordbytes = None
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
                fp = self.man.open(self.root, mode=Perm.read, rev=rev, owner=self.root_owner)
            with fp:
                if self.encryption_key:
                    fp.set_encryption(self.encryption_key)
                elif fp.meta.get(u'_encryption'):
                    raise Exception('Directory is encrypted')
                data = fp.read()
                record = CasDir.from_bytes(data)
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
        self._recordbytes = record.to_bytes()
        self.rev = rev
        self.my_info_block = my_block
        self.my_data_block = my_data_block

    def save(self, meta=None, info=None):
        if self.record.to_bytes() == self._recordbytes:
            return
        if self.parent:
            fp = self.parent.open(self.current_dir, mode=Perm.write)
        else:
            fp = self.man.open(self.root, mode=Perm.write, owner=self.root_owner)
        with fp:
            if info:
                for k, v in info.items():
                    if v is not None:
                        setattr(fp, k, v)
            if self.encryption_key:
                fp.set_encryption(self.encryption_key)
            fp.content_type = u'application/x-cas-directory'
            self.record.parent = self.my_info_block
            fp.write(self.record.to_bytes())
            if not self.parent:
                # root file should be a CAS file
                fp.meta[u'CAS'] = True
            # clear old meta info
            for k in (u'comment', u'op', u't'):
                fp.meta.pop(k, None)
            if meta:
                fp.meta.update(meta)
        self.load()

    def delete(self, path, owner=u'*', include_history=False, force_timestamp=None):
        path = self._get_fname(path)
        hist = self.record.files.get(path)
        if not hist:
            return False
        try:
            self.man.check_perm(os.path.join(self.current_dir, path), owner=owner, perm=Perm.delete)
        except AttributeError as e:
            pass
        hist = CasHistoryInfo.from_bytes(hist)
        hist.rev += 1
        hist.length = 0
        hist.owner = owner
        if force_timestamp:
            hist.created = force_timestamp
        else:
            hist.created = now()
        meta = {'op': 'rm'}
        hist.meta.update(meta)
        hist.prev = hist.root
        hist.root = CAS_EMPTY_BLOCK
        hist.parent = self.my_info_block
        self.record.files[path] = hist.to_bytes()
        if self.auto_save:
            meta[u't'] = os.path.join(self.current_dir, path)
            self.save(meta=meta, info={'modified': force_timestamp, 'owner': owner})

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
        if d.auto_save:
            d.save(meta={'op': 'mv', 't': [frompath, topath]}, info={'owner': owner})

    def listdir(self, walk=False, owner=None, limit=0, open_files=False):
        count = 0
        for name, h in sorted(self.record.files.items()):
            if open_files:
                fp = self.open(name, owner=owner)
                yield fp
                last_info = fp.info
            else:
                last_info = CasHistoryInfo.from_bytes(h)
                yield last_info
            count += 1
            if limit and limit == count:
                break
            if walk and last_info.content_type == 'application/x-cas-directory':
                subdir = os.path.split(name)[1]
                for info in self.chdir(subdir).listdir(walk=True, open_files=open_files, owner=owner):
                    info.path = os.path.join(subdir, info.path)
                    yield info
                    count += 1
                    if limit and limit == count:
                        break

    def __contains__(self, path):
        fname = self._get_fname(path)
        return fname in self.record.files and self.record.get_file(fname).meta.get(u'op') != u'rm'

    def _get_fname(self, path):
        if path.endswith('/'):
            fname = path.split('/')[-2] + '/'
        else:
            fname = os.path.basename(path)
        return fname

    def save_file_data(self, path, meta, buf, cipher=None):
        meta['parent'] = self.my_info_block
        if meta.get('rev') is not None:
            # this means the file is forced at this revision.
            # we should save the fixed timestamp
            info = {'modified': meta.get('modified')}
        else:
            info = None
        path = self._get_fname(path)
        hist = self.man.save_file_data(path, meta, buf, cipher=cipher, subdir=True)
        self.record.files[hist.path] = hist.to_bytes()
        # print('SAVED', self, path, len(self.record.files))
        # to propagate comments up the tree, save them in the file's metadata
        if self.auto_save or hist.content_type == u'application/x-cas-directory':
            meta = {u't': os.path.join(self.current_dir, path)}
            for key in (u'op', u't', u'comment'):
                if hist.meta.get(key):
                    meta[key] = hist.meta[key]
            self.save(meta=meta, info=info)

    def get_file_metadata(self, path, rev):
        fname = self._get_fname(path)
        try:
            hist = self.record.get_file(fname)
        except KeyError:
            return {}
        if rev is not None and rev < hist.rev:
            startkey = self.my_info_block
            while hist.rev > rev and startkey:
                try:
                    hist = CasDir.from_key(startkey, self.man).get_file(fname)
                    startkey = hist.parent
                except KeyError:
                    return {}
        hist.history_key = self.my_info_block
        return hist

    def get_metadata_and_check_perm(self, filename, rev, mode=Perm.read, owner=Owner.ALL):
        try:
            self.man.check_perm(os.path.join(self.current_dir, filename), owner=owner, perm=mode)
        except AttributeError as e:
            pass
            # import warnings
            # message = '%r does not have a check_perm method' % self.man
            # warnings.warn(message)
        return self.get_file_metadata(filename, rev)

    def get_meta_history(self, path):
        if path is None:
            # history for entire tree
            start = self.my_info_block
            while start:
                block = self.man.readblock(start)
                info = CasHistoryInfo.from_bytes(block)
                changed_path = info.meta.get('t', '').replace(self.current_dir + '/', '', 1)
                if changed_path:
                    try:
                        finfo = CasDir.from_root(info.root, self.man).get_file(changed_path)
                    except KeyError:
                        finfo = None
                else:
                    finfo = None
                yield info, finfo
                start = info.parent
        else:
            fname = self._get_fname(path)
            hist = self.record.files.get(fname)
            if hist:
                hist = CasHistoryInfo.from_bytes(hist)
                yield hist
            if hist.parent:
                start = hist.parent
                while hist.rev > 0:
                    try:
                        hist = CasDir.from_key(start, self.man).get_file(fname)
                        start = hist.parent
                        yield hist
                    except KeyError:
                        break

    def changed_since(self, rev=0):
        seen = set()
        for info, finfo in self.get_meta_history(None):
            if info.rev > rev:
                path = finfo.path
                if path not in seen:
                    yield path
                    seen.add(path)
            else:
                break

    def open(self, filename, mode=Perm.read, owner=Owner.ALL, rev=None):
        if filename.startswith(('/', './')):
            filename = self._get_fname(filename)
        elif filename.count('/') > 0 and not filename.endswith('/'):
            # need to open a directory to this path
            path, filename = os.path.split(os.path.normpath(filename))
            if not filename:
                # means we're trying to open a subdirectory somewhere
                path, filename = path.rsplit('/', 1)
                filename += '/'
            return self.chdir(path, auto_save=self.auto_save).open(filename, mode=mode, owner=owner, rev=rev)
        path = os.path.normpath(os.path.join(self.current_dir, filename))
        return VersionedFile(self, path, mode=mode, rev=rev, requestor=owner)

    def chdir(self, dirname, rev=None, encryption_key=None, auto_save=None):
        auto_save = auto_save if auto_save is not None else self.auto_save
        if not dirname.endswith('/'):
            dirname += '/'
        if dirname.startswith('/'):
            dirname = dirname[1:]
        elif dirname.startswith('./'):
            dirname = dirname[2:]
        if dirname.count('/') > 1:
            # need to open/create subdirectories
            d = None
            for subdir in dirname.split('/')[:-1]:
                d = (d or self).chdir(subdir, rev=rev, auto_save=auto_save)
        else:
            d = Directory(self.man,
                        self.root,
                        os.path.join(self.current_dir, dirname)[:-1],
                        parent=self,
                        encryption_key=encryption_key,
                        auto_save=auto_save)
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
