import abc
import os, os.path
import io
import hashlib
import uuid
import mimetypes
from tempfile import SpooledTemporaryFile
import msgpack
import datetime, time
from collections import namedtuple
import six

try:
    PermissionError = PermissionError
except NameError:
    class PermissionError(IOError):
        pass
    class FileNotFoundError(IOError):
        pass
    class FileError(IOError):
        pass

try:
    abc.ABC
except AttributeError:
    class ABC(object):
        __metaclass__ = abc.ABCMeta
        """Helper class that provides a standard way to create an ABC using
        inheritance.
        """
        pass
    abc.ABC = ABC

Perm = namedtuple('Perm', ['read', 'write', 'delete'])(read=u'r', write=u'w', delete=u'd')

class Record(dict):
    def __getattr__(self, key):
        try:
            return self[key]
        except KeyError:
            raise AttributeError(key)

    def __setattr__(self, key, value):
        self[key] = value

    @classmethod
    def from_bytes(cls, data):
        unpacked = {}
        for k, v in msgpack.unpackb(data, encoding='utf8').items():
            if not isinstance(k, six.text_type):
                k = k.decode('utf8')
            unpacked[k] = v
        obj = cls(unpacked)
        for k in ('created', 'modified'):
            v = obj.get(k, None)
            if v:
                obj[k] = datetime.datetime.utcfromtimestamp(v)
        return obj

    def __bytes__(self):
        return msgpack.packb(self, encoding='utf8', use_bin_type=True)
    
    to_bytes = as_foundationdb_value = __bytes__


class BaseManager(abc.ABC):
    def __init__(self, dsn='', debug=False, **kwargs):
        self.debug = debug
        self.dsn = dsn
        self.options = kwargs
        self._setup()
    
    def __repr__(self):
        return '%s%s(%s)' % (self.__class__.__module__, self.__class__.__name__, self.dsn)

    @abc.abstractmethod
    def _setup(self):
        pass

    @abc.abstractmethod
    def get_meta_history(self, path):
        """
        return historical metadata for the path.
        if path is a directory, returns metadata for all items in the directory
        """
        pass
    
    @abc.abstractmethod
    def get_file_metadata(self, path, rev):
        """
        Return dict-like metadata for the path and rev (or None for latest rev)
        """
        pass

    @abc.abstractmethod
    def get_file_chunks(self, path, rev, chunk=None, cipher=None):
        """
        Return iterator of file chunks
        or the specified chunk
        """
        pass

    @abc.abstractmethod
    def save_file_data(self, path, meta, buffer, cipher=None):
        """
        Save the file metadata and data (in file-like buffer)
        """
        pass

    @abc.abstractmethod
    def __contains__(self, path):
        pass

    def subdirectories(self, dirname, delimiter='/'):
        """
        returns the subdirectories off of dirname
        """
        raise NotImplementedError()


    def common_prefixes(self, prefix, delimiter):
        raise NotImplementedError()

    @abc.abstractmethod
    def listdir(self, dirname, walk=False, owner=None, limit=0, open_files=False, order=None, cols=None, delimiter='/'):
        pass

    def copyfile(self, filename_or_fileobj, topath, content_type=None):
        if isinstance(filename_or_fileobj, six.string_types):
            filename_or_fileobj = open(filename_or_fileobj, 'rb')
        if not content_type and hasattr(filename_or_fileobj, 'name'):
            content_type = mimetypes.guess_type(filename_or_fileobj.name)[0]
            to_ctype = mimetypes.guess_type(topath)[0]
            if to_ctype != content_type:
                content_type = to_ctype
        with self.open(topath, mode=Perm.write) as tofile:
            tofile.content_type = content_type
            while 1:
                data = filename_or_fileobj.read(8192)
                if not data:
                    break
                tofile.write(data)
            filename_or_fileobj.close()
        return tofile

    def copydir(self, dirname, topath=None, walk=False):
        topath = topath or dirname
        for p in os.listdir(dirname):
            fn = os.path.join(dirname, p)
            if os.path.isfile(fn):
                ft = os.path.join(topath, p)
                self.copyfile(fn, ft)

    @abc.abstractmethod
    def delete(self, path, owner='*', include_history=False, force_timestamp=None):
        """
        delete a file
        """
        pass

    # @abc.abstractmethod
    def delete_old_versions(self, path, owner='*', maxrev=-1):
        raise NotImplementedError()

    @abc.abstractmethod
    def rename(self, frompath, topath, owner='*', record_move=True):
        pass

    @abc.abstractmethod
    def set_perm(self, path, owner, perm=Perm.read):
        pass
    
    @abc.abstractmethod
    def check_perm(self, path, owner, perm=Perm.read, raise_exception=True):
        pass

    @abc.abstractmethod
    def clear_perm(self, path, owner, perm):
        pass

    def rmtree(self, directory, include_history=False):
        """
        Removes every file under directory
        """
        for obj in self.listdir(directory, walk=True):
            self.delete(obj.path, include_history=include_history)

    def create_repository(self, directory):
        """
        Create a 'repository' at directory.
        The backend should use this call to create indexes for efficient
        version lookups.
        """
        pass

    @abc.abstractmethod
    def repo_rev(self, repository):
        """
        return maximum revision for fs, starting at prefix
        """
        pass

    @abc.abstractmethod
    def repo_changed_files(self, repository, since=0):
        pass

    @abc.abstractmethod
    def repo_history(self, repository, since=0):
        pass

    def __getitem__(self, path):
        """
        gets the stored data
        """
        raise NotImplementedError()

    def __setitem__(self, path, data):
        """
        sets the data
        """
        raise NotImplementedError()

    def __delitem__(self, path):
        """
        deletes the data
        """
        raise NotImplementedError()

    def open(self, path, mode=Perm.read, owner='*', rev=None, version=None):
        """
        Open the file at path
        """
        path = os.path.normpath(path)
        return VersionedFile(self, path, mode=mode, rev=rev, requestor=owner, version=version)

    def open_many(self, paths, mode=Perm.read, owner='*'):
        """
        Open files
        """
        for path in paths:
            path = os.path.normpath(path)
            meta = self.get_file_metadata(path, None)
            vf = VersionedFile(self, path, requestor=owner, mode=mode, **meta)
            yield vf

    def partial(self, path, id=None, **kwargs):
        part = Partial(self, path, id)
        if id is None:
            part.start(kwargs)
        return part

    def list_partials(self, path):
        for p in self.listdir('/.partial' + path, walk=True):
            if p.path.endswith('/-1'):
                path = p.path.replace('/.partial', '', 1)
                pid = path.split('/')[-2]
                path = '/'.join(path.split('/')[:-2])
                info = {
                    'id': pid,
                    'path': path,
                    'created': p.created,
                    'meta': p.meta,
                    'owner': p.owner,
                }
                yield info

class Partial:
    """
    Support object for resumable uploads
    """
    def __init__(self, manager, path, id):
        self.manager = manager
        if not id:
            id = uuid.uuid4().hex
        self.id = id
        self.dest = path
        path = ['', '.partial'] + [p for p in path.split('/') if p] + [self.id]
        self.path = '/'.join(path)

    def start(self, meta):
        six.print_('starting', self.path, self.dest)
        self.manager.check_perm(self.dest, meta.get('owner'), perm=Perm.write)
        path = os.path.join(self.path, '-1')
        with self.manager.open(path, mode=Perm.write, owner='sys') as fp:
            fp.content_type = meta.pop('content_type', None)
            fp.meta = meta

    def open_part(self, num):
        path = os.path.join(self.path, str(num))
        part = self.manager.open(path, mode=Perm.write, owner='sys')
        part.do_hash('md5')
        return part

    def add(self, chunk, num):
        with self.open_part(num) as fp:
            fp.write(chunk)
        return chunk

    def combine(self, partnums, owner=None):
        with self.manager.open(self.dest, mode=Perm.write, owner=owner) as fp:
            fp.do_hash()
            for part in partnums:
                with self.manager.open(os.path.join(self.path, str(part)), owner='sys') as p:
                    six.print_(p.path)
                    if p.path.endswith('/-1'):
                        fp.meta = p.meta
                        fp.content_type = p.content_type
                    else:
                        chunk = p.read()
                        fp.write(chunk)
                        six.print_('wrote %s to %s' % (len(chunk), self.dest))
        self.manager.rmtree(self.path)
        return fp

    def list(self):
        for p in self.manager.listdir(self.path, owner='sys'):
            partnum = int(p.path.split('/')[-1])
            if partnum > -1:
                yield partnum, p


class VersionedFile(io.BufferedIOBase):
    def __init__(self, manager, filename, mode=Perm.read, requestor='*', meta=None, rev=None, **kwargs):
        io.BufferedIOBase.__init__(self)
        self.path = self.name = filename
        manager.check_perm(self.path, owner=requestor, perm=mode)
        self.created = None
        self.modified = None
        self.data = None
        self.meta = meta or {}
        self.mode = mode
        self._seekable = True
        self.length = 0
        self.bs = 8192
        self._cipher = None
        self.manager = manager
        val = manager.get_file_metadata(filename, rev)
        if val:
            self.update(val)
        
        if mode == Perm.read and 'id' not in kwargs:
            if not val:
                raise FileNotFoundError(self.path)
        elif mode == Perm.write:
            self.owner = requestor 

        if kwargs:
            self.update(kwargs)
        self._pos = 0
        if mode == Perm.read:
            if self.data:
                self._curr_chunk = self.data
                self._curr_chunk_num = 0
            else:
                self._curr_chunk_num = None
                self._curr_chunk = None
        else:
            self._buf = SpooledTemporaryFile(max_size=getattr(self, 'buffer_threshold', 52428800))
            self.hash = None

    def do_hash(self, algo='sha256'):
        self.hash = algo

    def close(self):
        if self.closed:
            return
        if self.writable():
            self._buf.seek(0, 2)
            length = self.length = self._buf.tell()
            self._buf.seek(0)

            hist_data = {
                'meta': self.meta,
                'owner': getattr(self, 'owner', None),
                'length': length,
                'hash': self.hash
            }
            if not self.created:
                self.created = datetime.datetime.utcnow()
            hist_data['created'] = created = self.created
            content_type = getattr(self, 'content_type', None)
            if not content_type:
                content_type = mimetypes.guess_type(self.path)[0]
            hist_data['content_type'] = content_type

            if getattr(self, 'force_rev', None):
                hist_data['rev'] = rev = self.force_rev

            self.manager.save_file_data(self.path, hist_data, self._buf, cipher=self._cipher)

            self._buf.close()
            self._buf = None
        self.mode = None
        io.BufferedIOBase.close(self)

    # def __del__(self):
    #     self.close()

    def readable(self):
        return self.mode == Perm.read

    def writable(self):
        return self.mode == Perm.write

    def seekable(self):
        return self._seekable

    def tell(self):
        if self.readable():
            return self._pos
        else:
            return self._buf.tell()

    def seek(self, pos, whence=0):
        if self.mode == Perm.read:
            curpos = self._pos
            if whence == 0:
                abspos = pos
            elif whence == 1:
                abspos = curpos + pos
            elif whence == 2:
                abspos = self.length + pos
            self._pos = abspos
            return self._pos
        elif self.mode == Perm.write and self.seekable():
            return self._buf.seek(pos, whence)

    def read(self, size=-1):
        if self.mode != Perm.read:
            return
        if self._pos == 0 and size == -1:
            # optimization for reading the whole file
            buf = b''
            for chunk in self.manager.get_file_chunks(self.path, self.rev, cipher=self._cipher):
                buf += chunk
            self._pos = len(buf)
            return buf

        length = size if size > 0 else self.length
        buf = b''
        where, pos = divmod(self._pos, self.bs)

        if self._curr_chunk_num != where:
            self._curr_chunk = self.manager.get_file_chunks(self.path, self.rev, where, cipher=self._cipher)
            self._curr_chunk_num = where
        buf += self._curr_chunk[pos:]
        while len(buf) < length:
            where += 1
            self._curr_chunk = self.manager.get_file_chunks(self.path, self.rev, where, cipher=self._cipher)
            if self._curr_chunk is None:
                self._curr_chunk_num = None
                break
            buf += self._curr_chunk
            self._curr_chunk_num = where
        read = buf[:length]
        self._pos += len(read)
        return read

    async def aread(self, size=-1):
        return self.read(size)

    def readall(self):
        return self.read()

    def write(self, data):
        if not data:
            return
        if not self.writable():
            raise FileError()
        if isinstance(data, six.text_type):
            data = data.encode('utf8')
        
        wrote = len(data)
        
        self._buf.write(data)
        return wrote

    def update(self, kwargs):
        for k, v in kwargs.items():
            if k in ('created', 'modified') and isinstance(v, float):
                v = datetime.datetime.utcfromtimestamp(v)
            setattr(self, k, v)

    def set_encryption(self, password='', save_password=False):
        """
        Set the encryption password, optionally saving the password in the metadata
        """
        import blowfish
        password = hashlib.sha512(password.encode('utf8')).digest()[:56]
        if self.writable():
            assert self._cipher is None
            self.meta[u'_encryption'] = {
                u'method': u'cfb',
                u'iv': os.urandom(8),
            }
            if save_password:
                self.meta[u'_encryption'][u'key'] = password
        else:
            assert u'_encryption' in self.meta
            password = self.meta[u'_encryption'].get(u'key', None) or password
        c = blowfish.Cipher(password)
        iv = self.meta[u'_encryption'][u'iv']
        self._cipher = {
            'encrypt': lambda chunk: b''.join(c.encrypt_cfb(chunk, iv)),
            'decrypt': lambda chunk: b''.join(c.decrypt_cfb(chunk, iv)),
        }

