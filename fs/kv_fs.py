from .base import BaseManager, Record, PermissionError, Perm, VersionedFile
import os, os.path
import hashlib
import msgpack
import time, datetime
import six
import operator
import collections


if six.PY2:
    def to_timestamp(dt):
        return time.mktime(dt.utctimetuple())
else:
    def to_timestamp(dt):
        return dt.timestamp()



class BaseKVFSManager(BaseManager):
    CHUNKSIZE = 64 * 1024
    TRANSIZE = 8 * 1024 * 1024
    

    def get_meta_history(self, path):
        """
        return historical metadata for the path.
        if path is a directory, returns metadata for all items in the directory
        """
        if not isinstance(path, six.text_type):
            path = path.decode('utf8')
        if path.endswith(u'/'):
            paths = [p['path'] for p in self.listdir(path, walk=True)]
        else:
            paths = [path]
        history = []
        with self._begin() as tr:
            for path in paths:
                hk = self.make_history_key(path)
                start = hk[None]
                end = self.make_history_key(path, end=True)
                for k, v in tr.get_range(start, end, reverse=True):
                    key = hk.unpack(k)
                    if len(key) > 1:
                        continue
                    row = Record.from_bytes(v)
                    row.rev = key[0]
                    history.append(row)

        history.sort(key=operator.itemgetter(u'created'), reverse=True)
        return history

    def get_file_metadata(self, path, rev, tr=None):
        with self._begin() as tr:
            active = tr[self._make_file_key(path)]
            exists = active != None
            if rev is None and not exists:
                # there is no metadata
                return {}
            elif not exists:
                active = {}
            else:
                active = Record.from_bytes(bytes(active))
                rev = active.rev if rev is None else rev
        
            # renamed files have a reference to the old path
            path = active.pop('path', path)
            if not isinstance(path, six.text_type):
                path = path.decode('utf8')
            key = self.make_history_key(path)

            start_key = key[rev]
            val = tr[start_key]
            if not val:
                # files in the repo have different revs
                if self._is_in_repo(tr, path):
                    lastkey = tr.get_key(fdb.KeySelector.last_less_or_equal(start_key))
                    if key.contains(lastkey):
                        rev = key.unpack(lastkey)[0]
                        val = tr[key[rev]]
        if val:
            val = Record.from_bytes(bytes(val))
            val.update(active)
            val.rev = rev
        return val

    def save_file_data(self, path, meta, buf, cipher=None):
        meta['bs'] = self.CHUNKSIZE
        rev = meta.get('rev', None)
        meta['created'] = created = to_timestamp(meta['created'])
        meta['path'] = path
        hist_key = self.make_history_key(path)
        hash_algo = meta.pop('hash', None)
        if hash_algo:
            hasher = getattr(hashlib, hash_algo)()
        else:
            hasher = None
        
        with self._begin(write=True) as tr:
            if rev is not None:
                modified = meta['created']
            else:
                meta['rev'] = rev = self._get_next_rev(tr, path)
                modified = time.time()

            # now write the chunks
            cn = 0
            written = 0
            while 1:
                chunk = buf.read(self.CHUNKSIZE)
                if not chunk:
                    break
                if hasher:
                    hasher.update(chunk)
                if cipher:
                    chunk = cipher['encrypt'](chunk)
                tr[hist_key[rev][cn]] = chunk
                written += len(chunk)
                cn += 1
                # transactions can't be too big
                if written >= self.TRANSIZE:
                    # tr.commit().wait()
                    tr.commit()
                    six.print_('starting new transaction')
                    tr = self._begin()
                    written = 0
            if hasher:
                meta['meta'][hash_algo] = hasher.hexdigest()
            hist = Record(meta)
            val = hist.to_bytes()

            tr[hist_key[rev]] = val
            self._record_repo_history(tr, hist, rev)
            
            written += len(val)

            # set the active key
            tr[self._make_file_key(path)] = Record(created=created, modified=modified, rev=rev)

    def get_file_chunks(self, path, rev, cipher=None):
        key = self.make_history_key(path)
        if cipher:
            decrypt = cipher['decrypt']
        else:
            decrypt = None
        with self._begin() as tr:
            for i in tr.get_range(key[rev][0], key[rev + 1]):
                data = i.value
                if decrypt:
                    data = decrypt(data)
                yield data

    def get_file_chunk(self, path, rev, chunk, cipher=None):
        key = self.make_history_key(path)
        if cipher:
            decrypt = cipher['decrypt']
        else:
            decrypt = None
        with self._begin() as tr:
            data = tr[key[rev][chunk]]
            if decrypt:
                data = decrypt(data)
            return data
        
    def _make_file_key(self, path):
        if not isinstance(path, six.text_type):
            path = path.decode('utf8')
        if path:
            if path[0] == '/':
                path = path[1:]
            path = [p for p in path.split('/') if p]
        return self._files[path]
    
    def _path_hash(self, path):
        return hashlib.sha1(path.encode('utf8')).digest()

    def make_history_key(self, path, end=False):
        r = [self._path_hash(path)]
        if end:
            r.append(None)
        return self._history[r]

    def __contains__(self, path):
        key = self._make_file_key(path)
        with self._begin() as tr:
            return bool(tr[key])

    def listdir(self, dirname, walk=False, owner=None, limit=0, open_files=False, order=None, where=None, cols=None, delimiter='/'):
        if delimiter:
            nd = os.path.normpath(dirname)
            if dirname.endswith(delimiter) and not nd.endswith(delimiter):
                nd += delimiter

            dirname = nd
        with self._begin() as tr:
            start = self._make_file_key(dirname).key()[:-1]
            end = start + b'\xff'

            nc = dirname.count(delimiter)
            for k, v in tr.get_range(start, end, limit=limit):
                k = self._files.unpack(k)[0]
                path = '/' + '/'.join(k)

                if not walk and path.count(delimiter) > nc:
                    continue
                meta = Record.from_bytes(v)

                meta.update(self.get_file_metadata(path, rev=meta['rev'], tr=tr))
                if open_files:
                    yield VersionedFile(self, path, mode=Perm.read, requestor=owner, **meta)
                else:
                    if owner and not self.check_perm(path, owner=owner, raise_exception=False, tr=tr):
                        continue
                    meta.path = path
                    yield meta

    def rmtree(self, directory, include_history=False):
        if not isinstance(directory, six.text_type):
            directory = directory.decode('utf8')

        start = self._make_file_key(directory).key()[:-1]
        end = start + b'\xff'
        with self._begin(write=True) as tr:
            if include_history:
                for i in tr[start:end]:
                    path = u'/' + u'/'.join(self._files.unpack(i.key)[0])
                    del tr[self.make_history_key(path).range()]
            del tr[start:end]

    def rename(self, frompath, topath, owner=u'*', record_move=True):
        frompath = os.path.normpath(frompath)
        topath = os.path.normpath(topath)
        if not isinstance(frompath, six.text_type):
            frompath = frompath.decode('utf8')
        if not isinstance(topath, six.text_type):
            topath = topath.decode('utf8')
        assert frompath in self
        with self._begin(write=True) as tr:
            self.check_perm(frompath, owner=owner, perm=Perm.write, tr=tr)
            self.check_perm(topath, owner=owner, perm=Perm.write, tr=tr)
            active = self.get_file_metadata(frompath, None)
            active['path'] = topath
            if record_move:
                hist = Record({'path': frompath,
                              'owner': owner,
                              'meta': {'operation': 'mv', 'dest': topath}})
                rev = active.rev + 1
                tr[self.make_history_key(frompath)[rev]] = hist.to_bytes()
                self._record_repo_history(tr, hist, rev)
            tr[self._make_file_key(topath)] = Record(created=to_timestamp(active.created), modified=time.time(), rev=active.rev, path=frompath).to_bytes()
            del tr[self._make_file_key(frompath)]

        return 3

    def delete(self, path, owner=u'*', include_history=False, force_timestamp=None):
        """
        delete a file
        """
        path = os.path.normpath(path)

        with self._begin(write=True) as tr:
            self.check_perm(path, owner=owner, perm=Perm.delete, tr=tr)
            fk = self._make_file_key(path)
            val = tr[fk]
            if val:
                rev = Record.from_bytes(val).rev
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
                    created = to_timestamp(force_timestamp)
                else:
                    created = time.time()
                meta = Record({'path': path, 
                        'owner': owner,
                        'meta': {'operation': 'del'},
                        'created': created,
                       })
                tr[self.make_history_key(path)[rev]] = meta
                self._record_repo_history(tr, meta, rev)
                return True

    def _get_next_rev(self, tr, path):
        found = self._is_in_repo(tr, path)
        if found:
            # file is in a repository
            # versions increase on the repository level
            rev = self._repo_rev(tr, found) + 1
        else:
            hist_key = self.make_history_key(path)
            start = hist_key[None]
            end = self.make_history_key(path, end=True)
            result = list(tr.get_range(start, end, reverse=True, limit=1))
            if result:
                rev = hist_key.unpack(result[0].key)[0]
                if rev is None:
                    rev = 0
                else:
                    rev += 1
            else:
                rev = 0
        return rev

    def _is_in_repo(self, tr, path):
        for repo in self._active_repos:
            if path.startswith(repo):
                return self._active_repos[repo]

    def _record_repo_history(self, tr, meta, rev):
        found = self._is_in_repo(tr, meta.path)
        if found:
            repokey = found['key']
            tr[repokey[rev]] = meta.to_bytes()
            return True

    def create_repository(self, directory):
        directory = six.text_type(directory)
        key = self._repos[directory]
        rev = -1
        with self._begin(write=True) as tr:
            val = tr[key[None]]
            if not val:
                tr[key[None]] = Record(latest=0, rev=-1).to_bytes()
            keyrange = slice(key.key(), self._repos[directory, None].key())
            self._active_repos[directory] = {'key': key, 'range': keyrange}

    def repo_rev(self, repository):
        """
        return maximum revision for repository within filesystem
        """
        repository = six.text_type(repository)
        try:
            found = self._active_repos[repository]
        except KeyError:
            raise Exception(repository)
        else:
            with self._begin() as tr:
                return self._repo_rev(tr, found)
    
    def _repo_rev(self, tr, found):
        latest = list(tr.get_range(found['range'].start, found['range'].stop, limit=1, reverse=True))[0]
        rev = found['key'].unpack(latest.key)[0]
        if rev is None:
            rev = -1
        return rev

    def repo_history(self, repository, since=-1):
        repository = six.text_type(repository)
        key = self._repos[repository]
        start = self._repos[repository][since + 1]
        end = self._repos[repository, None]
        with self._begin() as tr:
            for k, v in tr.get_range(start, end, reverse=True):
                rev = key.unpack(k)[0]
                rec = Record.from_bytes(v)
                rec.rev = rev
                yield rec

    def repo_changed_files(self, repository, since=-1):
        seen = set()
        for rec in self.repo_history(repository, since=since):
            path = rec['path']
            if path not in seen:
                yield path
                seen.add(path)

    def __getitem__(self, path):
        """
        gets the stored data
        """
        with self._begin() as tr:
            val = tr[self._kv[path]]

        if val != None:
            rec = Record.from_bytes(bytes(val))
            if '__value' in rec:
                return rec['__value']
            else:
                return rec
        else:
            return None

    def __setitem__(self, path, data):
        """
        sets the data as a msgpack string
        """
        key = self._kv[path]
        if not isinstance(data, dict):
            data = {'__value': data}
        val = Record(data).to_bytes()
        with self._begin(write=True) as tr:
            tr[key] = val

    def __delitem__(self, path):
        with self._begin(write=True) as tr:
            del tr[self._kv[path]]

    def common_prefixes(self, prefix, delimiter):
        start = self._make_file_key(prefix).key()[:-1]
        end = start + b'\xff'

        nc = prefix.count(delimiter)
        pref = collections.defaultdict(int)
        with self._begin() as tr:
            for k, v in tr.get_range(start, end):
                k = self._files.unpack(k)[0]
                path = '/' + '/'.join(k)
                path = path.replace(prefix, '', 1)
                if path.count(delimiter) > 0:
                    pref[path.split(delimiter)[0]] += 1
        return pref.items()

    def _perm_path(self, path):
        if path[0] == '/':
            path = path[1:]
        path = [p for p in path.split('/') if p]
        return path

    def check_perm(self, path, owner, perm=Perm.read, raise_exception=True, tr=None):
        pars = [owner, perm]
        upars = [u'*', perm]
        sp = self._perm_path(path)
        with self._begin() as tr:
            while sp:
                key = self._perms[pars + sp]
                if tr[key] == b'':
                    return True
                key = self._perms[upars + sp]
                if tr[key] == b'':
                    return True
                sp.pop(-1)
        if raise_exception:
            raise PermissionError((path, owner, perm))
        else:
            return False

    def set_perm(self, path, owner, perm=Perm.read):
        sp = self._perm_path(path)
        with self._begin(write=True) as tr:
            for p in perm:
                pars = [owner, p] + sp
                key = self._perms[pars]
                tr[key] = b''
        return True

    def clear_perm(self, path, owner, perm):
        sp = self._perm_path(path)
        with self._begin(write=True) as tr:        
            for p in perm:
                key = self._perms[[owner, p] + sp]
                del tr[key]
