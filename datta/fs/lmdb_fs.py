from .kv_fs import BaseKVFSManager
from ..ext import subspace
import lmdb
import operator
import six
from collections import namedtuple
from contextlib import contextmanager


KeyValue = namedtuple('KeyValue', ('key', 'value'))


class DBProxy(object):
    def __init__(self, env, txn=None):
        self.env = env
        self.txn = txn
        self.enter_count = 0
        
    def __enter__(self):
        self.enter_count += 1
        return self

    def __exit__(self, type, exc, tb):
        if not exc:
            self.enter_count -= 1
            if self.enter_count == 0:
                self.txn.commit()
        else:
            self.txn.abort()
            six.reraise(type, exc, tb)

    def create_transaction(self, write=False, buffers=False):
        txn = self.env.begin(write=write, buffers=buffers)
        return DBProxy(self.env, txn)

    def cancel(self):
        self.txn.abort()

    def get_range(self, start, end, reverse=False, limit=None):
        if hasattr(start, 'key'):
            start = start.key()
        if hasattr(end, 'key'):
            end = end.key()
        count = 0
        with self.txn.cursor() as cursor:
            if reverse:
                range_func = cursor.iterprev
                start, end = end, start
                comparator = operator.lt
            else:
                range_func = cursor.iternext
                comparator = operator.gt
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

    get = __getitem__

    def __delitem__(self, key):
        if isinstance(key, slice):
            # do range clear
            for i in self.get_range(key.start, key.stop):
                self.txn.delete(i.key)
        else:
            if hasattr(key, 'key'):
                key = key.key()
            self.txn.delete(key)

    def __setitem__(self, key, value):
        if hasattr(key, 'key'):
            key = key.key()
        if hasattr(value, 'to_bytes'):
            value = value.to_bytes()
        self.txn.put(key, value)



class FSManager(BaseKVFSManager):
    CHUNKSIZE = 1024 * 1024
    TRANSIZE = 1024 * 1024 * 1024
    
    def _setup(self, **kwargs):
        self.env = lmdb.Environment(self.dsn,
                                     map_size=kwargs.get('map_size', 10**10),
                                     max_dbs=200,
                                     sync=kwargs.get('sync', True))
        self.db = DBProxy(self.env)
        self._files = subspace.Subspace((u'fs', ))
        self._history = subspace.Subspace((u'hist', ))
        self._kv = subspace.Subspace((u'kv', ))
        self._repos = subspace.Subspace((u'repo', ))
        self._perms = subspace.Subspace((u'perms', ))
        self._active_repos = {}
        self.CHUNKSIZE = 1080

    def close(self):
        self.env.close()

    def _begin(self, write=False, **kwargs):
        txn = self.env.begin(write=write, **kwargs)
        return DBProxy(self.env, txn)


