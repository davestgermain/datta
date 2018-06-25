from .kv_fs import BaseKVFSManager
from ..ext import subspace
from ..lmdbutils import TransactionalEnvironment


class FSManager(BaseKVFSManager):
    TRANSIZE = 1024 * 1024 * 1024
    
    def _setup(self, **kwargs):
        self.db = TransactionalEnvironment(filename=self.dsn, env_args=kwargs)
        self._files = subspace.Subspace((u'fs', ))
        self._history = subspace.Subspace((u'hist', ))
        self._kv = subspace.Subspace((u'kv', ))
        self._repos = subspace.Subspace((u'repo', ))
        self._perms = subspace.Subspace((u'perms', ))
        self._active_repos = {}

    def close(self):
        self.db.close()

    def _begin(self, write=False, **kwargs):
        return self.db.create_transaction(write=write, **kwargs)

    def _get_chunksize(self, meta):
        # return 1080
        return 4096
