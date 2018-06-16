from .kv_fs import BaseKVFSManager, ACLRecord
from contextlib import contextmanager
import fdb
import six
import ctypes

fdb.api_version(510)

class CtxTransaction(fdb.Transaction):
    def __init__(self, ptr, db):
        fdb.Transaction.__init__(self, ptr, db)
        self.enter_count = 0

    def __enter__(self):
        self.enter_count += 1
        return self

    def __exit__(self, type, exc, tb):
        if not exc:
            self.enter_count -= 1
            if self.enter_count == 0:
                self.commit().wait()
        else:
            self.cancel()
            six.reraise(type, exc, tb)

    def get(self, key):
        item = fdb.Transaction.get(self, key)
        item.wait()
        return item
    


class FSManager(BaseKVFSManager):
    CHUNKSIZE = 64 * 1024
    TRANSIZE = 8 * 1024 * 1024

    def _setup(self):
        self.db = fdb.open()
        with self._begin(write=True) as tr:
            self._files = fdb.directory.create_or_open(tr, u'fs')
            self._history = fdb.directory.create_or_open(tr, u'hist')
            self._kv = fdb.directory.create_or_open(tr, u'kv')
            self._repos = fdb.directory.create_or_open(tr, u'repo')
            self._perms = fdb.directory.create_or_open(tr, u'perms')
            self._active_repos = {}
    
    def _begin(self, write=False, buffers=False):
        pointer = ctypes.c_void_p()
        self.db.capi.fdb_database_create_transaction(self.db.dpointer, ctypes.byref(pointer))
        return CtxTransaction(pointer.value, self.db)

    def get_acl(self, path, tr=None):
        # tr = tr or self._begin()
        ppath = self._perm_path(path)
        basekey = self._perms
        acl = None
        with self._begin() as tr:
            while ppath:
                key = basekey[ppath]
                acl = tr[key]
                if acl != None:
                    acl = ACLRecord.from_bytes(acl.value).acl
                    break
                ppath.pop(-1)
        return acl
