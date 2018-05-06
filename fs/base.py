import abc
import os, os.path
import io
import hashlib
import mimetypes
import msgpack
import datetime, time
from collections import defaultdict
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
    def __init__(self, dsn='', debug=False):
        self.debug = debug
        self.dsn = dsn
        self._setup()
    
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
    def get_file_chunks(self, path, rev):
        """
        Return iterator of file chunks
        """
        pass

    @abc.abstractmethod
    def save_file_data(self, path, meta, buffer):
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
        with self.open(topath, mode='w') as tofile:
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
    def set_perm(self, path, owner, perm='r'):
        pass
    
    @abc.abstractmethod
    def check_perm(self, path, owner, perm='r', raise_exception=True):
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

    def open(self, path, mode='r', owner='*', rev=None, version=None):
        """
        Open the file at path
        """
        path = os.path.normpath(path)
        return VersionedFile(self, path, mode=mode, rev=rev, requestor=owner, version=version)

    def open_many(self, paths, mode='r', owner='*'):
        """
        Open files
        """
        for path in paths:
            path = os.path.normpath(path)
            meta = self.get_file_metadata(path, None)
            vf = VersionedFile(self, path, requestor=owner, mode=mode, **meta)
            yield vf


class VersionedFile(io.BufferedIOBase):
    def __init__(self, manager, filename, mode='r', requestor='*', meta=None, rev=None, **kwargs):
        io.BufferedIOBase.__init__(self)
        self.path = self.name = filename
        manager.check_perm(self.path, owner=requestor, perm=mode)
        self.created = None
        self.modified = None
        self.data = None
        self.meta = meta or {}
        self.mode = mode
        self.length = 0
        self.bs = 8192
        self.manager = manager
        val = manager.get_file_metadata(filename, rev)
        if val:
            self.update(val)
        
        if mode == 'r' and 'id' not in kwargs:
            if not val:
                raise FileNotFoundError(self.path)
        elif mode == 'w':
            self.owner = requestor 

        if kwargs:
            self.update(kwargs)
        self._pos = 0
        if mode == 'r':
            if self.data:
                self._curr_chunk = self.data
                self._curr_chunk_num = 0
            else:
                self._curr_chunk_num = None
                self._curr_chunk = None
        else:
            self._buf = io.BytesIO()
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

            self.manager.save_file_data(self.path, hist_data, self._buf)

            self._buf = None
        self.mode = None
        io.BufferedIOBase.close(self)

    def readable(self):
        return self.mode == 'r'

    def writable(self):
        return self.mode == 'w'

    def seekable(self):
        return True

    def tell(self):
        if self.readable():
            return self._pos
        else:
            return self._buf.tell()

    def seek(self, pos, whence=0):
        if self.mode == 'r':
            curpos = self._pos
            if whence == 0:
                abspos = pos
            elif whence == 1:
                abspos = curpos + pos
            elif whence == 2:
                abspos = self.length + pos
            self._pos = abspos
            return self._pos
        elif self.mode == 'w':
            return self._buf.seek(pos, whence)

    def read(self, size=-1):
        if self.mode != 'r':
            return
        if self._pos == 0 and size == -1:
            # optimization for reading the whole file
            buf = b''
            for chunk in self.manager.get_file_chunks(self.path, self.rev):
                buf += chunk
            self._pos = len(buf)
            return buf

        length = size if size > 0 else self.length
        buf = b''
        where, pos = divmod(self._pos, self.bs)

        if self._curr_chunk_num != where:
            self._curr_chunk = self.manager.get_file_chunks(self.path, self.rev, where)
            self._curr_chunk_num = where
        buf += self._curr_chunk[pos:]
        while len(buf) < length:
            where += 1
            self._curr_chunk = self.manager.get_file_chunks(self.path, self.rev, where)
            if self._curr_chunk is None:
                self._curr_chunk_num = None
                break
            buf += self._curr_chunk
            self._curr_chunk_num = where
        read = buf[:length]
        self._pos += len(read)
        return read

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


