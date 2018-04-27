from .base import BaseManager
import fdb
import os, os.path
import hashlib
import msgpack
import time, datetime

fdb.api_version(510)

CHUNKSIZE = 64 * 1024
TRANSIZE = 8 * 1024 * 1024


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
        obj = cls(**msgpack.unpackb(data, encoding='utf8'))
        for k in ('created', 'modified'):
            v = obj.get(k, None)
            if v:
                obj[k] = datetime.datetime.utcfromtimestamp(v)
        return obj

    def __bytes__(self):
        return msgpack.packb(self, use_bin_type=True)


class FSManager(BaseManager):
    def _setup(self):
        self.db = fdb.open()
        tr = self.db.create_transaction()
        try:
            self.files = fdb.directory.create_or_open(tr, 'fs')
            self.history = fdb.directory.create_or_open(tr, 'hist')
            self.kv = fdb.directory.create_or_open(tr, 'kv')
        except:
            tr.cancel()
            raise
        else:
            tr.commit().wait()

    def get_meta_history(self, path):
        """
        return historical metadata for the path.
        if path is a directory, returns metadata for all items in the directory
        """
        hk = self.make_history_key(path)
        start = hk[None]
        end = self.make_history_key(path, end=True)
        for k, v in self.db.get_range(start, end, reverse=True):
            key = hk.unpack(k)
            if len(key) > 1:
                continue
            row = Record.from_bytes(v)
            row.rev = key[0]
            yield row

    def get_file_metadata(self, path, rev, tr=None):
        if tr is None:
            tr = self.db
        active = tr[self.make_file_key(path)] or None
        if rev is None and not active:
            # there is no metadata
            return {}
        elif not active:
            active = {}
        else:
            active = Record.from_bytes(bytes(active))
            rev = active.rev if rev is None else rev

        key = self.make_history_key(path)

        start_key = key[rev]
        val = tr[start_key]
        if val:
            val = Record.from_bytes(bytes(val))
            val.update(active)
            val.rev = rev
            return val
        else:
            return None

    def save_file_data(self, path, meta, buf):
        meta['bs'] = CHUNKSIZE
        rev = meta.get('rev', None)
        meta['created'] = created = meta['created'].timestamp()
        meta['path'] = path
        tr = self.db.create_transaction()
        try:
            hist_key = self.make_history_key(path)
            if rev is not None:
                modified = meta['created']
            else:
                start = self.make_history_key(path)[None]
                end = self.make_history_key(path, end=True)
                result = list(tr.get_range(start, end, reverse=True, limit=1))
                if result:
                    rev = hist_key.unpack(result[0].key)[0] + 1
                else:
                    rev = 0
                meta['rev'] = rev
                modified = time.time()

            # now write the chunks
            hash_algo = meta.get('hash', None)
            if hash_algo:
                hasher = getattr(hashlib, hash_algo)()
            else:
                hasher = None
            cn = 0
            while 1:
                chunk = buf.read(CHUNKSIZE)
                if not chunk:
                    break
                tr[hist_key[rev][cn]] = chunk
                written += len(chunk)
                if hasher:
                    hasher.update(chunk)
                cn += 1
                # transactions can't be too big
                if written >= TRANSIZE:
                    tr.commit().wait()
                    print('starting new transaction')
                    tr = self.db.create_transaction()
                    written = 0
            if hasher:
                meta[hash_algo] = hasher.hexdigest()
            val = bytes(Record(**meta))
            print('writing', hist_key[rev], val)
            tr[hist_key[rev]] = val
            written = len(val)

            # set the active key
            tr[self.make_file_key(path)] = bytes(Record(created=created, modified=modified, rev=rev))
        except:
            tr.cancel()
            raise
        else:
            tr.commit().wait()

    def get_file_chunks(self, path, rev):
        key = self.make_history_key(path)
        tr = self.db
        for k, chunk in tr.get_range(key[rev][0], key[rev + 1]):
            yield chunk

    def make_file_key(self, path):
        if path:
            if path[0] == '/':
                path = path[1:]
            path = [p for p in path.split('/') if p]
        return self.files[path]
    
    def path_hash(self, path):
        return hashlib.sha1(path.encode('utf8')).digest()

    def make_history_key(self, path, end=False):
        r = [self.path_hash(path)]
        if end:
            r.append(None)
        return self.history[r]

    def __contains__(self, path):
        val = self.db[self.make_file_key(path)]
        return bool(val)

    def listdir(self, dirname, walk=False, owner=None, limit=0, open_files=False, order=None, where=None, cols=None, delimiter='/'):
        if delimiter:
            nd = os.path.normpath(dirname)
            if dirname.endswith(delimiter) and not nd.endswith(delimiter):
                nd += delimiter

            dirname = nd

        tr = self.db.create_transaction()
        try:
            start = self.make_file_key(dirname).key()[:-1]
            end = start + b'\xff'

            nc = dirname.count(delimiter)
            for k, v in tr.get_range(start, end, limit=limit):
                k = self.files.unpack(k)[0]
                path = '/' + '/'.join(k)
                if not walk and path.count(delimiter) > nc:
                    continue
                meta = Record.from_bytes(v)
                meta.update(self.get_file_metadata(path, rev=meta['rev'], tr=tr))
                if open_files:
                    yield VersionedFile(self, path, mode='r', requestor=owner, **meta)
                else:
                    if owner and not self.check_perm(path, owner=owner, raise_exception=False, tr=tr):
                        continue
                    yield path, meta
        finally:
            tr.commit().wait()

    def rename(self, frompath, topath, owner='*', record_move=True):
        raise NotImplementedError()

    def delete(self, path, owner='*', include_history=False, force_timestamp=None):
        """
        delete a file
        """
        path = os.path.normpath(path)
        return self._delete(self.db, path, owner=owner, include_history=include_history, force_timestamp=force_timestamp)

    @fdb.transactional
    def _delete(self, tr, path, owner='*', include_history=False, force_timestamp=None):
        self.check_perm(path, owner=owner, perm='d', tr=tr)
        fk = self.make_file_key(path)
        val = tr[fk]
        if val:
            rev = Record.from_bytes(val.value).rev
            del tr[fk]
        else:
            return
        if include_history:
            # delete everything
            del tr[self.make_history_key(path).range()]
        else:
            # record the history of deletion
            rev += 1
            if force_timestamp:
                created = force_timestamp.timestamp()
            else:
                created = time.time()
            meta = {'path': path, 
                    'owner': owner,
                    'meta': {'operation': 'del'},
                    'created': created,
                   }
            tr[self.make_history_key(path)[rev]] = bytes(Record(meta))
            return True

    def maxrev(self, prefix='/'):
        """
        return maximum revision for fs, starting at prefix
        """
        mr = -1
        if prefix.startswith('/'):
            prefix = prefix[1:]
        prefix = prefix.split('/')[1:] or None
        start = self.files[prefix].key()[:-1]
        end = start + b'\xff'
        for k, v in self.db.get_range(start, end):
            val = Record.from_bytes(v)
            if val.rev > mr:
                mr = val.rev
        return mr

    def changes(self, prefix='/', since=0):
        if prefix.startswith('/'):
            prefix = prefix[1:]
        prefix = prefix.split('/')[1:] or None
        start = self.files[prefix].key()[:-1]
        end = start + b'\xff'

        for k, v in self.db.get_range(start, end):
            if Record.from_bytes(v).rev > since:
                yield '/'.join(('',) + self.files.unpack(k)[0])

    def get_data(self, path, owner='*'):
        """
        gets the stored data
        """
        val = self.db[self.kv[path]]
        if val:
            rec = Record.from_bytes(val)
            if '__value' in rec:
                return rec['__value']
            else:
                return rec
        else:
            return None

    def set_data(self, path, data, owner='*'):
        """
        sets the data as a msgpack string
        """
        key = self.kv[path]
        if not isinstance(data, dict):
            data = {'__value': data}
        val = bytes(Record(data))
        tr = self.db.create_transaction()
        try:
            tr[key] = val
        except:
            tr.cancel()
            raise
        else:
            tr.commit().wait()

    def check_perm(self, path, owner, perm='r', raise_exception=True, tr=None):
        # raise NotImplementedError()
        return True

    def set_perm(self, path, owner, perm='r'):
        raise NotImplementedError()

    def clear_perm(self, path, owner, perm):
        raise NotImplementedError()
