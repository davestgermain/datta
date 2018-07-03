from .base import BaseManager, PermissionError, Perm, Owner, VersionedFile
import os, os.path
import hashlib
import time, datetime
import six
import uuid
import operator
import collections
from functools import lru_cache
from datta.pack import make_record_class, Record

now = datetime.datetime.utcnow

OP_DELETED = 1


HistoryInfo = make_record_class('HistoryInfo', [
        ('path', str),
        ('owner', str),
        ('content_type', str),
        ('rev', int),
        ('length', int),
        ('created', datetime.datetime),
        ('bs', int),
        ('meta', dict),
        ('data', bytes)
    ])


FileInfo = make_record_class('FileInfo', [
        ('rev', int),
        ('created', datetime.datetime),
        ('modified', datetime.datetime),
        ('path', str),
        ('history_key', 'key'),
        ('flag', int),
    ], version=1)

orig_from_tuple = FileInfo.from_tuple
@classmethod
def from_version_1(cls, data, version=1):
    if len(data) < 6:
        data = list(data) + [None, None]
    return orig_from_tuple(data, version=version)
FileInfo.from_tuple = from_version_1
FileInfo.from_bytes = lru_cache(maxsize=128)(FileInfo.from_bytes)


ListInfo = make_record_class('ListInfo', [
        ('path', str),
        ('owner', str),
        ('content_type', str),
        ('rev', int),
        ('length', int),
        ('created', datetime.datetime),
        ('bs', int),
        ('meta', dict),
        ('data', bytes),
        ('modified', datetime.datetime),
        ('history_key', 'key'),
        ('flag', int),
    ])


KVRecord = make_record_class('KVRecord', [
        ('value', None)
    ])


ACLRecord = make_record_class('ACLRecord', [
        ('acl', dict)
    ])


def convert_old_acl(cls, info, version=1):
    if version != 0:
        obj = Record.from_dict(cls, info, version=version)
    else:
        obj = cls(info)
    return obj
ACLRecord.from_dict = classmethod(convert_old_acl)
ACLRecord.from_bytes = lru_cache(maxsize=200)(ACLRecord.from_bytes)


RepoStatus = make_record_class('RepoStatus', [
        ('rev', int)
    ])


class BaseKVFSManager(BaseManager):
    TRANSIZE = 8 * 1024 * 1024
    
    def _get_chunksize(self, meta):
        return 65536

    def get_meta_history(self, path):
        """
        return historical metadata for the path.
        if path is a directory, returns metadata for all items in the directory
        """
        if not isinstance(path, six.text_type):
            path = path.decode('utf8')
        if path.endswith(u'/'):
            paths = [p.path for p in self.listdir(path, walk=True)]
        else:
            paths = [path]
        history = []
        with self._begin(buffers=True) as tr:
            for path in paths:
                info = FileInfo.from_bytes(tr[self._make_file_key(path)])
                hk = info.get('history_key') or self.make_history_key(path)
                hr = hk.range()
                start = hr.start
                end = hr.stop

                for k, v in tr.get_range(start, end, reverse=True):
                    key = hk.unpack(k)
                    if len(key) > 1:
                        continue
                    row = HistoryInfo.from_bytes(v)
                    row.rev = key[0]
                    history.append(row)

        history.sort(key=operator.attrgetter('rev'), reverse=True)
        return history

    def _get_history_for_rev(self, tr, path, history_key, rev):
        start_key = history_key.pack((rev,))
        val = tr[start_key]
        if val:
            hist = HistoryInfo.from_bytes(val)
            hist.rev = rev
            return hist
        else:
            # files in the repo have different revs
            if self._is_in_repo(tr, path):
                for lastkey, val in tr.get_range(history_key[0], start_key, reverse=True, values=False):
                    if history_key.contains(lastkey):
                        rev = history_key.unpack(lastkey)[0]
                        hist = HistoryInfo.from_bytes(tr[history_key[rev]])
                        hist.rev = rev
                        return hist

    def get_file_metadata(self, path, rev, tr=None, mode=None):
        if tr is None:
            tr = self._begin(buffers=True)
        with tr:
            active = tr[self._make_file_key(path)]
            exists = active != None
            if rev is None and not exists:
                # there is no metadata
                return {}
            elif exists:
                active = FileInfo.from_bytes(active)
                if mode != Perm.write and active.flag == OP_DELETED:
                    return {}
                rev = active.rev if rev is None else rev            
            else:
                active = FileInfo.from_dict({})

            if not active.history_key:
                active.history_key = self.make_history_key(path)

            hist = self._get_history_for_rev(tr, path, active.history_key, rev)
        combined = ListInfo.from_records(hist, active)
        combined.rev = hist.get('rev')
        return combined

    def get_metadata_and_check_perm(self, path, rev, mode=None, owner=None):
        with self._begin(buffers=True) as tr:
            self.check_perm(path, owner=owner, perm=mode, tr=tr)
            return self.get_file_metadata(path, rev, tr=tr, mode=mode)

    def save_file_data(self, path, meta, buf, cipher=None):
        rev = meta.get(u'rev', None)
        created = meta[u'created'] or now()
        modified = meta[u'modified'] or now()

        meta[u'path'] = path
        hist_key = None
        hash_algo = meta.pop(u'hash', None)
        if hash_algo:
            hasher = getattr(hashlib, hash_algo)()
        else:
            hasher = None
        meta[u'bs'] = self._get_chunksize(meta)

        active_info = FileInfo.from_dict({'created': created, 'modified': modified})
        # first, get the active info
        old_info = meta.pop(u'file_info', None)
        if old_info:
            hist_key = old_info.history_key
        if not hist_key:
            hist_key = self._history[uuid.uuid4().bytes]
        active_info.history_key = hist_key    
        with self._begin(write=True) as tr:
            found = self._is_in_repo(tr, path)
            if rev is None or found:
                if found:
                    # file is in a repository
                    # versions increase on the repository level
                    rev = self._repo_rev(tr, found) + 1
                else:
                    sk = hist_key.range()
                    start = sk.start
                    end = sk.stop
                    result = list(tr.get_range(start, end, reverse=True, limit=1))
                    if result:
                        rev = hist_key.unpack(result[0].key)[0]
                        if rev is None:
                            rev = 0
                        else:
                            rev += 1
                    else:
                        rev = 0
                meta[u'rev'] = rev

            active_info.rev = rev
            meta[u'created'] = modified
            hist = HistoryInfo.from_dict(meta)
            written = 0
            if hist.length <= 1000:
                data = buf.read()
                if hasher:
                    hasher.update(data)
                if cipher:
                    data = cipher['encrypt'](data)
                hist.data = data
            else:
                # now write the chunks
                cn = 0
                while 1:
                    chunk = buf.read(hist.bs)
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
                        tr = self._begin(write=True)
                        written = 0
            if hasher:
                hist.meta[hash_algo] = hasher.hexdigest()
            val = hist.to_bytes()

            tr[hist_key[rev]] = val
            self._record_repo_history(tr, hist)
            
            written += len(val)

            # set the active key
            tr[self._make_file_key(path)] = active_info
        return {'rev': rev}

    def get_file_chunks(self, file_info, cipher=None):
        key = file_info.history_key
        rev = file_info.rev
        if cipher:
            decrypt = cipher['decrypt']
        else:
            decrypt = None
        startkey = key.pack((rev, 0))
        endkey = key.pack((rev + 1, ))
        with self._begin(buffers=True) as tr:
            for i in tr.get_range(startkey, endkey):
                data = i.value
                if decrypt:
                    data = decrypt(data)
                yield data

    def get_file_chunk(self, file_info, chunk, cipher=None):
        key = file_info.history_key.pack((file_info.rev, chunk))
        if cipher:
            decrypt = cipher['decrypt']
        else:
            decrypt = None
        with self._begin(buffers=True) as tr:
            data = tr[key]
            if decrypt:
                data = decrypt(data)
            return data

    @lru_cache(maxsize=500)
    def _make_file_key(self, path):
        if not isinstance(path, six.text_type):
            path = path.decode('utf8')
        if path:
            if path[0] == u'/':
                path = path[1:]
            path = [p for p in path.split(u'/') if p]
        return self._files.pack((path, ))
    
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
            val = tr[key]
            if val:
                val = FileInfo.from_bytes(val)
                return val.get('flag') != OP_DELETED
        return False

    def listdir(self, dirname, walk=False, owner=None, limit=0, open_files=False, delimiter=u'/', rev=None, start_file=None, **kwargs):
        if delimiter:
            nd = os.path.normpath(dirname)
            if dirname.endswith(delimiter) and not nd.endswith(delimiter):
                nd += delimiter

            dirname = nd
        count = 0
        with self._begin(buffers=True) as tr:
            start = self._make_file_key(dirname)[:-1]
            end = start + b'\xff'
            if start_file:
                start = self._make_file_key(start_file)
            nc = dirname.count(delimiter)
            for k, v in tr.get_range(start, end):
                k = self._files.unpack(k)[0]
                path = u'/' + u'/'.join(k)

                if not walk and path.count(delimiter) > nc:
                    continue
                if open_files:
                    yield VersionedFile(self, path, mode=Perm.read, requestor=owner, rev=rev)
                else:
                    finfo = FileInfo.from_bytes(v)
                    if finfo.flag == OP_DELETED:
                        continue
                    elif owner and not self.check_perm(path, owner=owner, raise_exception=False, tr=tr):
                        continue

                    if not finfo.history_key:
                        finfo.history_key = self.make_history_key(path)

                    hist = self._get_history_for_rev(tr, path, finfo.history_key, rev or finfo.rev)
                    meta = ListInfo.from_records(hist, finfo)
                    meta.path = path
                    yield meta
                if limit:
                    count += 1
                    if count == limit:
                        break

    def rmtree(self, directory, include_history=False):
        if not isinstance(directory, six.text_type):
            directory = directory.decode('utf8')

        start = self._make_file_key(directory)[:-1]
        end = start + b'\xff'
        with self._begin(write=True) as tr:
            if include_history:
                for i in tr[start:end]:
                    path = u'/' + u'/'.join(self._files.unpack(i.key)[0])
                    del tr[i.key]
                    info = FileInfo.from_bytes(i.value)
                    hk = info.get('history_key') or self.make_history_key(path)
                    del tr[hk.range()]
            else:
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
            from_key = self._make_file_key(frompath)
            from_info = FileInfo.from_bytes(tr[from_key])

            to_key = self._make_file_key(topath)
            from_info.modified = now()

            if record_move:
                hist = HistoryInfo.from_dict({'path': frompath,
                                             'owner': owner,
                                             'meta': {u'operation': u'mv', u'dest': topath}})
                rev = from_info.rev + 1
                tr[from_info.history_key[rev]] = hist.to_bytes()
                self._record_repo_history(tr, hist)

            tr[to_key] = from_info.to_bytes()
            del tr[from_key]

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
                info = FileInfo.from_bytes(val)
                rev = info.rev
            else:
                return
            history_key = info.history_key or self.make_history_key(path)

            if include_history:
                # delete everything
                del tr[fk]
                del tr[history_key.range()]
            else:
                # record the history of deletion
                info.flag = OP_DELETED
                tr[fk] = info
                rev += 1
                if force_timestamp:
                    created = force_timestamp
                else:
                    created = now()
                meta = HistoryInfo.from_dict({'path': path, 
                                            'owner': owner,
                                            'meta': {u'operation': u'del'},
                                            'created': created,
                                        })
                tr[history_key[rev]] = meta
                self._record_repo_history(tr, meta)
                return True

    def delete_old_versions(self, path, owner=u'*', maxrev=-1):
        path = os.path.normpath(path)
        fk = self._make_file_key(path)
        basekey = self.make_history_key(path)

        with self._begin(write=True) as tr:
            self.check_perm(path, owner=owner, perm=Perm.delete, tr=tr)
            val = tr[fk]
            if val:
                if maxrev == -1:
                    rev = FileInfo.from_bytes(val).rev - 1
                else:
                    rev = maxrev
                kr = slice(basekey[0], basekey[rev])
                del tr[kr]

    def _is_in_repo(self, tr, path):
        for repo in self._active_repos:
            if path.startswith(repo):
                return self._active_repos[repo]

    def _record_repo_history(self, tr, meta):
        found = self._is_in_repo(tr, meta.path)
        if found:
            repokey = found['key']
            meta.data = None
            last = RepoStatus.from_bytes(tr[repokey[None]])
            last.rev += 1
            tr[repokey[last.rev]] = meta.to_bytes()
            tr[repokey[None]] = last
            return last.rev

    def create_repository(self, directory):
        directory = six.text_type(directory)
        config = self.get_path_config(directory)
        if not config.get(u'is_repo'):
            config.is_repo = {}
            key = self._repos[directory]
            with self._begin(write=True) as tr:
                val = tr[key[None]]
                if not val:
                    tr[key[None]] = RepoStatus(-1).to_bytes()
            keyrange = slice(key.key(), self._repos[directory][9223372036854775807].key())
            config.is_repo[u'key'] = key.key()
            config.is_repo[u'range'] = (keyrange.start, keyrange.stop)
            self.set_path_config(directory, config)
        else:
            repo = config.get(u'is_repo')
            key = self._repos.__class__(rawPrefix=repo[u'key'])
            keyrange = slice(repo[u'range'][0], repo[u'range'][1])
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
            with self._begin(buffers=True) as tr:
                return self._repo_rev(tr, found)
    
    def _repo_rev(self, tr, found):
        val = tr[found['key'][None]]
        if val is not None:
            latest = RepoStatus.from_bytes(val).rev
        else:
            latest = -1
        return latest

    def repo_history(self, repository, since=-1):
        repository = six.text_type(repository)
        key = self._repos[repository]
        start = key[since + 1]
        end = key[9223372036854775807]
        with self._begin(buffers=True) as tr:
            for k, v in tr.get_range(start, end, reverse=True):
                try:
                    rev = key.unpack(k)[0]
                except ValueError:
                    print('could not unpack', k, v)
                    break
                rec = HistoryInfo.from_bytes(v)
                rec.rev = rev
                yield rec

    def repo_changed_files(self, repository, since=-1):
        seen = set()
        for rec in self.repo_history(repository, since=since):
            path = rec.path
            if path not in seen:
                yield path
                seen.add(path)

    def repo_checkout(self, repository, rev=None, owner='*'):
        """
        return iterator of open files for every path in the repository,
        for the given version
        """
        for fp in self.listdir(repository, walk=True, open_files=True, owner=owner, rev=rev):
            yield fp

    def __getitem__(self, path):
        """
        gets the stored data
        """
        with self._begin(buffers=True) as tr:
            val = tr[self._kv.pack((path,))]

        if val != None:
            try:
                rec = KVRecord.from_bytes(bytes(val))
                return rec.value
            except AttributeError:
                print(repr(rec))
        else:
            return None

    def __setitem__(self, path, data):
        """
        sets the data as a msgpack string
        """
        key = self._kv.pack((path,))
        rec = KVRecord(data)
        val = rec.to_bytes()
        with self._begin(write=True) as tr:
            tr[key] = val

    def __delitem__(self, path):
        with self._begin(write=True) as tr:
            del tr[self._kv[path]]

    def common_prefixes(self, prefix, delimiter):
        start = self._make_file_key(prefix)[:-1]
        end = start + b'\xff'

        nc = prefix.count(delimiter)
        pref = collections.defaultdict(int)
        with self._begin() as tr:
            for k, v in tr.get_range(start, end):
                k = self._files.unpack(k)[0]
                path = u'/' + u'/'.join(k)
                path = path.replace(prefix, '', 1)
                if path != prefix and path.count(delimiter) == 1:
                    pref[path.split(delimiter)[0]] += 1
        return pref.items()

    def get_acl(self, path, tr=None):
        tr = tr or self._begin(buffers=True)
        ppath = self._perm_path(path)
        makekey = self._perms.pack
        acl = None
        with tr:
            while ppath:
                key = makekey((ppath,))
                acl = tr[key]
                if acl:
                    acl = ACLRecord.from_bytes(acl).acl
                    break
                ppath.pop(-1)
        return acl

    def set_acl(self, path, acl):
        ppath = self._perm_path(path)
        key = self._perms[ppath]
        rec = ACLRecord(acl)
        val = rec.to_bytes()
        with self._begin(write=True) as tr:
            if acl:
                tr[key] = val
            else:
                del tr[key]

    def _perm_path(self, path):
        if path[0] == u'/':
            path = path[1:]
        path = [p for p in path.split(u'/') if p]
        return path

    def _find_orphaned_history(self):
        hist = self._history
        files = self._files
        found = set()
        with self._begin() as tr:
            for k, v in tr[files.range()]:
                up = files.unpack(k)
                path = '/' + '/'.join(up[0])
                found.add(self._path_hash(path))
            for k, v in tr[hist.range()]:
                up = hist.unpack(k)
                phash = up[0][0]
                if phash not in found and len(up[1:]) == 1:
                    v = HistoryInfo.from_bytes(v)
                    if v.path:
                        print(v.path)
                    else:
                        print(phash)
    
    def _delete_history_for_paths(self, paths):
        with self._begin(write=True) as tr:
            for path in paths:
                del tr[self.make_history_key(path).range()]

    def _get_range(self, start, stop, tr=None, **kwargs):
        if tr is None:
            tr = self._begin()
        with tr:
            for i in tr.get_range(start, stop, **kwargs):
                yield i

    def _get_key(self, key, tr=None):
        if tr is None:
            tr = self._begin()
        with tr:
            return tr[key]

