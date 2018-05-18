from .kv_fs import BaseKVFSManager
from .ext import subspace
import lmdb
import operator
from collections import namedtuple
from contextlib import contextmanager


KeyValue = namedtuple('KeyValue', ('key', 'value'))
    

class DBProxy(object):
    def __init__(self, env, txn=None):
        self.env = env
        self.txn = txn

    def create_transaction(self, write=False, buffers=False):
        txn = self.env.begin(write=write, buffers=buffers)
        return DBProxy(self.env, txn)

    def cancel(self):
        if self.txn:
            self.txn.abort()

    def get_range(self, start, end, reverse=False, limit=None):
        if hasattr(start, 'key'):
            start = start.key()
        if hasattr(end, 'key'):
            end = end.key()
        cursor = self.txn.cursor()
        if reverse:
            range_func = cursor.iterprev
            start, end = end, start
            comparator = operator.lt
        else:
            range_func = cursor.iternext
            comparator = operator.gt
        count = 0
        # print('get_range', start, end, reverse, limit)
        found = cursor.set_range(start)
        for key, value in range_func(keys=True, values=True):
            key = bytes(key)

            if reverse and key > start:
                # count += 1
                continue
            if comparator(key, end):
                break
            yield KeyValue(key, value)
            count += 1
            if limit and count > limit:
                break
        cursor.close()

    def commit(self):
        self.txn.commit()

    def abort(self):
        self.txn.abort()

        
    def __getitem__(self, key):
        if hasattr(key, 'key'):
            key = key.key()
        if isinstance(key, slice):
            val = []
            for i in self.get_range(key.start, key.stop):
                val.append(i)
        else:
            val = self.txn.get(key)
        return val

    def __delitem__(self, key):
        if isinstance(key, slice):
            # do range clear
            for i in self.get_range(key.start, key.stop):
                self.txn.delete(i.key)
            # raise NotImplementedError()
        else:
            if hasattr(key, 'key'):
                key = key.key()
            self.txn.delete(key)

    def __setitem__(self, key, value):
        if hasattr(key, 'key'):
            key = key.key()
        if hasattr(value, '__bytes__'):
            value = bytes(value)
        self.txn.put(key, value)


def transactional(func):
    def _wrapped(self, db, *args, **kwargs):
        if not db.txn:
            db = db.create_transaction(write=True)
            created = True
        else:
            created = False
        try:
            return func(self, db, *args, **kwargs)
        except:
            db.txn.abort()
            raise
        else:
            if created:
                db.txn.commit()
    return _wrapped


class FSManager(BaseKVFSManager):
    CHUNKSIZE = 1024 * 1024
    TRANSIZE = 1024 * 1024 * 1024
    
    def _setup(self, **kwargs):
        self.env = lmdb.Environment(self.dsn,
                                     map_size=kwargs.get('map_size', 10**10),
                                     max_dbs=200,
                                     sync=kwargs.get('sync', True))
        self.db = DBProxy(self.env)
        self._files = subspace.Subspace(('fs', ))
        self._history = subspace.Subspace(('hist', ))
        self._kv = subspace.Subspace(('kv', ))
        self._repos = subspace.Subspace(('repo', ))
        self._perms = subspace.Subspace(('perms', ))
        self._active_repos = {}

    @contextmanager
    def _begin(self, write=False):
        txn = self.env.begin(write=write)
        try:
            yield DBProxy(self.env, txn)
        except:
            txn.abort()
            raise
        else:
            txn.commit().wait()


