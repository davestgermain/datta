import abc
import os, os.path
import io
import hashlib
import mimetypes
import datetime, time
from collections import defaultdict
import six

try:
    PermissionError
except NameError:
    class PermissionError(IOError):
        pass
    class FileNotFoundError(IOError):
        pass
    class FileError(IOError):
        pass


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
        return self.engine.execute(perms.delete().where(perms.c.path == path).where(perms.c.owner == owner).where(perms.c.perm == perm))

    @abc.abstractmethod
    def maxrev(self, prefix='/'):
        """
        return maximum revision for fs, starting at prefix
        """
        pass

    @abc.abstractmethod
    def changes(self, prefix='/', since=0):
        pass

    def get_data(self, path, owner='*'):
        """
        gets the stored data
        """
        raise NotImplementedError()

    def set_data(self, path, data, owner='*'):
        """
        sets the data
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
        self.manager = manager
        val = manager.get_file_metadata(filename, rev)
        if val:
            self.update(val)
        
        if mode == 'r' and 'id' not in kwargs:
            if not val:
                raise FileNotFoundError(self.path)
        elif mode == 'w':
            self.owner = requestor 

        self._chunks = None
        if kwargs:
            self.update(kwargs)
        if mode == 'r':
            self._buf = io.BytesIO()
            self._consumed = 0
            self._chunks = self.get_chunks()
        else:
            self._buf = io.BytesIO()
            self._consumed = None
            self.hash = None

    def do_hash(self, algo='sha256'):
        self.hash = algo

    def close(self):
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
        else:
            self._buf.close()
        self.mode = None
        io.BufferedIOBase.close(self)

    def get_chunks(self):
        if self.data is not None:
            pos = self._buf.tell()
            self._buf.seek(0, 2)
            self._buf.write(self.data)
            yield len(self.data)
        else:
            for chunk in self.manager.get_file_chunks(self.path, self.rev):
                pos = self._buf.tell()
                self._buf.seek(0, 2)
                self._buf.write(chunk)
                cr = len(chunk)
                self._consumed += cr
                self._buf.seek(pos)
                yield cr

    def readable(self):
        return self.mode == 'r'

    def writable(self):
        return self.mode == 'w'

    def consume(self, size):
        if not self._chunks:
            return
        cr = 0
        while cr < size:
            try:
                cr += next(self._chunks)
            except StopIteration:
                self._chunks = None
                break

    def read(self, size=-1):
        if not self.readable():
            return
        data = self._buf.read(size)
        dr = len(data)
        length = size if size > 0 else self.length
        if self._chunks and dr < length:
            self.consume(length)
            self._buf.seek(-dr, 1)
            return self.read(size)
        else:
            return data

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

    def seekable(self):
        return True

    def tell(self):
        return self._buf.tell()

    def seek(self, pos, whence=0):
        if self.readable():
            curpos = self._buf.tell()
            if whence == 0:
                abspos = pos
            elif whence == 1:
                abspos = curpos + pos
            elif whence == 2:
                abspos = self.length + pos
            if abspos > self._consumed:
                self.consume(abspos - curpos)
                self._buf.seek(curpos)
        return self._buf.seek(pos, whence)

