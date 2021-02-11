import abc
import os, os.path
import io
import hashlib
import uuid
import mimetypes
from tempfile import SpooledTemporaryFile
import datetime, time
from collections import namedtuple
import six
from datta.pack import Record, make_record_class

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

Perm = namedtuple('Perm', ['read', 'write', 'delete', 'ALL'])(read=u'r', write=u'w', delete=u'd', ALL=u'rwd')

FileConfig = make_record_class('FileConfig', [('config', dict)])

class Owner:
    ALL = u'*'
    SYS = u'sys'
    ROOT = u'root'



class BaseManager(abc.ABC):
    def __init__(self, dsn='', debug=False, **kwargs):
        self.debug = debug
        self.dsn = dsn
        self.options = kwargs
        self._setup()
        self.set_perm(u'/', Owner.ROOT, Perm.ALL)

    def __repr__(self):
        return '%s.%s(%s)' % (self.__class__.__module__, self.__class__.__name__, self.dsn.geturl())

    @abc.abstractmethod
    def _setup(self):
        pass

    def close(self):
        pass

    @abc.abstractmethod
    def get_meta_history(self, path):
        """
        return historical metadata for the path.
        if path is a directory, returns metadata for all items in the directory
        """
        pass
    
    @abc.abstractmethod
    def get_file_metadata(self, path, rev, mode=None):
        """
        Return dict-like metadata for the path and rev (or None for latest rev)
        """
        pass

    @abc.abstractmethod
    def get_file_chunks(self, file_info, cipher=None):
        """
        Return iterator of file chunks
        or the specified chunk
        """
        pass

    @abc.abstractmethod
    def get_file_chunk(self, file_info, chunk, cipher=None):
        """
        Return single chunk
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

    def copyfile(self, filename_or_fileobj, topath, content_type=None, owner=None, meta=None):
        if isinstance(filename_or_fileobj, six.string_types):
            filename_or_fileobj = open(filename_or_fileobj, 'rb')
        if not content_type and hasattr(filename_or_fileobj, 'name'):
            content_type = mimetypes.guess_type(filename_or_fileobj.name)[0]
            to_ctype = mimetypes.guess_type(topath)[0]
            if to_ctype != content_type:
                content_type = to_ctype
        with self.open(topath, mode=Perm.write, owner=owner) as tofile:
            tofile.content_type = content_type
            if meta:
                tofile.meta.update(meta)
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

    def mkdir(self, dirname, owner=Owner.SYS, raise_exception=True, **meta):
        if dirname.endswith(u'/'):
            dirname = dirname[:-1]
        if dirname in self:
            if raise_exception:
                raise IOError('directory exists')
            else:
                return False
        with self.open(dirname, mode=Perm.write, owner=owner) as fp:
            fp.content_type = u'application/x-directory'
            fp.meta.update(meta)
        self.set_perm(dirname, owner, Perm.ALL)

    def _copyone(self, fromfile, to_file):
        to_file.owner = fromfile.owner
        to_file.meta = fromfile.meta
        to_file.content_type = getattr(fromfile, 'content_type', None)
        to_file.created = fromfile.created
        to_file.modified = fromfile.modified
        to_file.force_rev = fromfile.rev
        blocksize = getattr(fromfile, 'bs', 8192)
        while 1:
            chunk = fromfile.read(blocksize)
            if not chunk:
                break
            to_file.write(chunk)
        
    def copyinto(self, other_manager, shallow=True, dest=u'/'):
        for fp in other_manager.listdir(u'/', open_files=True, owner=Owner.ROOT, walk=True):
            all_files = [fp]
            if not shallow:
                all_files.extend([other_manager.open(p.path, owner=Owner.ROOT, rev=p.rev) for p in other_manager.get_meta_history(fp.path) if p.rev != fp.rev])
            for fp in all_files:
                to_path = os.path.join(dest, *fp.path.split(u'/'))
                with self.open(to_path, mode=Perm.write, owner=Owner.ROOT) as to_file:
                    self._copyone(fp, to_file)
                fp.close()
            six.print_(to_file.path)
                    
    @abc.abstractmethod
    def delete(self, path, owner=Owner.ALL, include_history=False, force_timestamp=None):
        """
        delete a file
        """
        pass

    # @abc.abstractmethod
    def delete_old_versions(self, path, owner=Owner.ALL, maxrev=-1):
        raise NotImplementedError()

    @abc.abstractmethod
    def rename(self, frompath, topath, owner=Owner.ALL, record_move=True):
        pass

    def check_perm(self, path, owner, perm=Perm.read, raise_exception=True, tr=None):
        if owner == Owner.ROOT:
            return True
        acl = self.get_acl(path, tr=tr)
        if acl:
            if perm in acl.get(owner, ()):
                return True
            elif perm in acl.get(Owner.ALL, ()):
                return True
        if raise_exception:
            raise PermissionError((path, owner, perm))
        else:
            return False

    def set_perm(self, path, owner, perm=Perm.read):
        acl = self.get_acl(path) or {}
        acl[owner] = list(perm)
        self.set_acl(path, acl)
        return True

    def clear_perm(self, path, owner, perm):
        acl = self.get_acl(path) or {}
        if owner in acl:
            for p in perm:
                try:
                    acl[owner] = [k for k in acl[owner] if k != perm]
                except ValueError:
                    continue
        self.set_acl(path, acl)
        return True

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

    def open(self, path, mode=Perm.read, owner=Owner.ALL, rev=None):
        """
        Open the file at path
        """
        path = os.path.normpath(path)
        vf = VersionedFile(self, path, mode=mode, rev=rev, requestor=owner)
        if mode == Perm.write:
            config = self.get_path_config(path)
            if not config.get('versioning', True):
                vf.force_rev = 0
        return vf

    def open_many(self, paths, mode=Perm.read, owner=Owner.ALL):
        """
        Open files
        """
        for path in paths:
            path = os.path.normpath(path)
            meta = self.get_file_metadata(path, None, mode=mode)
            vf = VersionedFile(self, path, requestor=owner, mode=mode, **meta)
            yield vf

    def get_path_config(self, path, create=False, **kwargs):
        """
        
        """
        sp = path.split('/')
        if len(sp) > 2:
            configpath = '/'.join(sp[:2])
            try:
                with self.open(configpath, owner=Owner.ROOT) as fp:
                    data = fp.read()
                    if data:
                        return FileConfig.from_bytes(data).config
            except FileNotFoundError:
                if create:
                    self.set_path_config(path, kwargs)
        return kwargs

    def set_path_config(self, path, config):
        """
        
        """
        configpath = u'/'.join(path.split(u'/')[:2])
        if not isinstance(config, FileConfig):
            config = FileConfig(config)
        with self.open(configpath, mode=Perm.write, owner=Owner.ROOT) as fp:
            fp.content_type = u'application/x-directory'
            fp.write(config.to_bytes())

    def partial(self, path, id=None, **kwargs):
        self.set_perm(u'/.partial/', Owner.SYS, Perm.ALL)
        part = Partial(self, path, id)
        if id is None:
            part.start(kwargs)
        return part

    def list_partials(self, path):
        for p in self.listdir(u'/.partial' + path, walk=True):
            if p.path.endswith(u'/-1'):
                path = p.path.replace(u'/.partial', '', 1)
                pid = path.split('/')[-2]
                path = u'/'.join(path.split('/')[:-2])
                info = {
                    'id': pid,
                    'path': path,
                    'created': p.created,
                    'meta': p.meta,
                    'owner': p.owner,
                }
                yield info

    def get_total_size(self, path):
        tot = 0
        for info in self.get_meta_history(path):
            tot += info.length or 0
        return tot

    def verify_integrity(self, dirname):
        last_path = None
        try:
            for p in self.listdir(dirname, walk=True):
                last_path = p.path
                revs = [i.rev for i in self.get_meta_history(p.path)]
                for rev in revs:
                    p = self.open(last_path, rev=rev, owner=Owner.ROOT)
                    hashval = hasher = None
                    for k in ('sha256', 'sha1', 'md5'):
                        if k in p.meta:
                            hashval = p.meta[k]
                            hasher = getattr(hashlib, k)()
                            break
                    failed = False
                    if hasher:
                        hasher.update(p.read())
                        found = hasher.hexdigest()
                        if found != hashval:
                            failed = (found, hashval)
                    else:
                        failed = len(p.read()) != (p.length or 0)
                    p.close()
                    if failed:
                        print('FAILED' if failed else 'OK', p.path, p.rev, failed)
        except Exception:
            import traceback; traceback.print_exc()
            print(last_path)

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
        path = [u'', u'.partial'] + [p for p in path.split(u'/') if p] + [self.id]
        self.path = u'/'.join(path)

    def start(self, meta):
        six.print_('starting', self.path, self.dest)
        self.manager.check_perm(self.dest, meta.get('owner'), perm=Perm.write)
        path = os.path.join(self.path, '-1')
        with self.manager.open(path, mode=Perm.write, owner=Owner.SYS) as fp:
            fp.content_type = meta.pop('content_type', None)
            fp.meta = meta

    def open_part(self, num):
        path = os.path.join(self.path, str(num))
        part = self.manager.open(path, mode=Perm.write, owner=Owner.SYS)
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
                with self.manager.open(os.path.join(self.path, str(part)), owner=Owner.SYS) as p:
                    six.print_(p.path)
                    if p.path.endswith(u'/-1'):
                        fp.meta = p.meta
                        fp.content_type = p.content_type
                    else:
                        chunk = p.read()
                        fp.write(chunk)
                        six.print_('wrote %s to %s' % (len(chunk), self.dest))
        self.manager.rmtree(self.path, include_history=True)
        return fp

    def list(self):
        for p in self.manager.listdir(self.path, owner=Owner.SYS):
            partnum = int(p.path.split('/')[-1])
            if partnum > -1:
                yield partnum, p


class VersionedFile(io.BufferedIOBase):
    def __init__(self, manager, filename, mode=Perm.read, requestor=Owner.ALL, meta=None, rev=None, file_info=None, **kwargs):
        io.BufferedIOBase.__init__(self)
        self.path = self.name = filename
        # manager.check_perm(self.path, owner=requestor, perm=mode)
        self.created = self.modified = None
        self.data = None
        self.meta = meta or {}
        self.mode = mode
        self._seekable = True
        self.length = 0
        self.bs = 8192
        self._cipher = None
        self.manager = manager
        self._file_info = file_info or manager.get_metadata_and_check_perm(filename, rev, mode=mode, owner=requestor)
        # self._file_info = manager.get_file_metadata(filename, rev, mode=mode)
        if self._file_info:
            self.update(self._file_info)

        if mode == Perm.read and not self._file_info:
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

    @property
    def is_dir(self):
        return getattr(self, 'content_type', '') == u'application/x-directory'

    def do_hash(self, algo='sha256'):
        self.hash = algo

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc:
            if self.readable():
                self.close()
            else:
                self._buf.close()
                self.mode = None
            import six
            six.reraise(exc_type, exc, tb)
        else:
            self.close()

    def close(self):
        if self.closed:
            return
        if self.writable():
            self._buf.seek(0, 2)
            length = self.length = self._buf.tell()
            self._buf.seek(0)

            hist_data = {
                u'meta': self.meta,
                u'owner': getattr(self, 'owner', None),
                u'length': length,
                u'hash': self.hash,
                u'created': self.created,
                u'modified': self.modified,
                u'file_info': self._file_info,
            }
            content_type = getattr(self, 'content_type', None)
            if not content_type:
                content_type = mimetypes.guess_type(self.path)[0]
            hist_data[u'content_type'] = content_type

            if getattr(self, 'force_rev', None) is not None:
                hist_data[u'rev'] = rev = self.force_rev
                hist_data[u'modified'] = self.created

            self.update(self.manager.save_file_data(self.path, hist_data, self._buf, cipher=self._cipher))

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
        elif self._pos == self.length:
            return b''
        buf = bytearray()
        if self._pos == 0 and size == -1:
            if self.data:
                self._pos = self.length
                return self.data
            else:
                # optimization for reading the whole file
                i = 0
                for chunk in self.manager.get_file_chunks(self._file_info, cipher=self._cipher):
                    i+= 1
                    buf.extend(chunk)
                self._pos = len(buf)
                return bytes(buf)

        length = size if size > 0 else self.length
        where, pos = divmod(self._pos, self.bs)

        if self._curr_chunk_num != where:
            self._curr_chunk = self.manager.get_file_chunk(self._file_info, where, cipher=self._cipher)
            self._curr_chunk_num = where
        buf += self._curr_chunk[pos:]
        while len(buf) < length:
            where += 1
            self._curr_chunk = self.manager.get_file_chunk(self._file_info, where, cipher=self._cipher)
            if self._curr_chunk is None:
                self._curr_chunk_num = None
                break
            buf.extend(self._curr_chunk)
            self._curr_chunk_num = where
        read = buf[:length]
        self._pos += len(read)
        return bytes(read)

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
        if kwargs:
            for k, v in kwargs.items():
                if k == 'modified' and self.mode == 'w':
                    continue
                if v is not None:
                    setattr(self, k, v)

    def set_encryption(self, password='', save_password=False):
        """
        Set the encryption password, optionally saving the password in the metadata
        """
        try:
            from nacl.secret import SecretBox
        except ImportError:
            SecretBox = None
        if SecretBox:
            password = hashlib.sha256(password.encode('utf8')).digest()
        else:
            password = hashlib.sha512(password.encode('utf8')).digest()[:56]
        if self.writable():
            assert self._cipher is None
            if SecretBox:
                method = u'nacl'
                self.meta[u'_encryption'] = {u'method': method}
            else:
                method = u'cfb'
                self.meta[u'_encryption'] = {
                    u'method': method,
                    u'iv': os.urandom(8),
                }
            if save_password:
                self.meta[u'_encryption'][u'key'] = password
        else:
            assert u'_encryption' in self.meta
            method = self.meta[u'_encryption'][u'method']
            password = self.meta[u'_encryption'].get(u'key', None) or password
        if method == u'nacl':
            c = SecretBox(password)
            self._cipher = {
                'encrypt': c.encrypt,
                'decrypt': c.decrypt
            }
        else:
            import blowfish
            c = blowfish.Cipher(password)
            iv = self.meta[u'_encryption'][u'iv']
            self._cipher = {
                'encrypt': lambda chunk: b''.join(c.encrypt_cfb(chunk, iv)),
                'decrypt': lambda chunk: b''.join(c.decrypt_cfb(chunk, iv)),
            }
        if self.data:
            self._curr_chunk = self._cipher['decrypt'](self.data)

