from .kv_fs import BaseKVFSManager
from contextlib import contextmanager
import fdb

fdb.api_version(510)



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
    
    @contextmanager
    def _begin(self, write=False):
        tr = self.db.create_transaction()
        try:
            yield tr
        except:
            tr.cancel()
            raise
        else:
            tr.commit().wait()    