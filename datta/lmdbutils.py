from collections import namedtuple
import operator
import six
import lmdb


KeyValue = namedtuple('KeyValue', ('key', 'value'))


class TransactionalEnvironment(object):
    def __init__(self, env=None, txn=None, filename=None, env_args=None):
        if env is None:
            env_args = env_args or {}
            env = lmdb.Environment(filename,
                                 map_size=env_args.get('map_size', 10**10),
                                 max_dbs=env_args.get('max_dbs', 200),
                                 writemap=env_args.get('writemap', True),
                                 meminit=env_args.get('meminit', False),
                                 sync=env_args.get('sync', True))
            
        self.env = env
        self.txn = txn
        self.enter_count = 0

    def close(self):
        self.env.sync()
        self.env.close()

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
        return TransactionalEnvironment(env=self.env, txn=txn)

    def get_range(self, start, end, reverse=False, limit=None, keys=True, values=True, do_clear=False):
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
            for row in range_func(keys=True, values=values):
                if keys and values:
                    key, value = row
                    key = bytes(key)
                elif keys:
                    key = bytes(row)
                    value = None
                elif values:
                    value = row
                    key = None

                if reverse and key > start:
                    continue
                if comparator(key, end):
                    break                
                if do_clear:
                    if not cursor.delete():
                        break
                yield KeyValue(key, value)
                count += 1
                if limit and count == limit:
                    break

    def commit(self):
        self.txn.commit()

    def abort(self):
        self.txn.abort()
    cancel = abort

    def __getitem__(self, key):
        return self.get(key)

    def get(self, key, default=None):
        if not isinstance(key, slice):
            if hasattr(key, 'key'):
                key = key.key()
            val = self.txn.get(key, default=default)
        else:
            val = list(self.get_range(key.start, key.stop))
        return val

    def __delitem__(self, key):
        if not isinstance(key, slice):
            if hasattr(key, 'key'):
                key = key.key()
            self.txn.delete(key)
        else:
            # do range clear
            for i in self.get_range(key.start, key.stop, values=False, do_clear=True):
                pass
                # self.txn.delete(i.key)

    def __setitem__(self, key, value):
        if hasattr(key, 'key'):
            key = key.key()
        if hasattr(value, 'to_bytes'):
            value = value.to_bytes()
        elif hasattr(value, '__bytes__'):
            value = bytes(value)
        self.txn.put(key, value)

