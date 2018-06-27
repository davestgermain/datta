from .base import BaseManager, Record, PermissionError, Perm, Owner, VersionedFile
import os, os.path
import hashlib
import time, datetime
import six
import uuid
import operator
import collections

now = datetime.datetime.utcnow

OP_DELETED = 1


class HistoryInfo(Record):
    fields = [
        ('path', str),
        ('owner', str),
        ('content_type', str),
        ('rev', int),
        ('length', int),
        ('created', datetime.datetime),
        ('bs', int),
        ('meta', dict),
        ('data', bytes)
    ]


class FileInfo(Record):
    fields = [
        ('rev', int),
        ('created', datetime.datetime),
        ('modified', datetime.datetime),
        ('path', str),
        ('history_key', 'key'),
        ('flag', int),
    ]

class ListInfo(Record):
    fields = [
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
    ]

class KVRecord(Record):
    fields = [
        ('value', None)
    ]

class ACLRecord(Record):
    fields = [
        ('acl', dict)
    ]
    @classmethod
    def from_dict(cls, info, version=1):
        if version != 0:
            obj = Record.from_dict(cls, info, version=version)
        else:
            obj = cls()
            obj.acl = info
        return obj


class RepoStatus(Record):
    fields = [
        ('rev', int)
    ]


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
        start_key = history_key[rev]
        val = tr[start_key]
        if not val:
            # files in the repo have different revs
            if self._is_in_repo(tr, path):
                for lastkey, val in tr.get_range(history_key[0], start_key, reverse=True, values=False):
                    if history_key.contains(lastkey):
                        rev = history_key.unpack(lastkey)[0]
                        val = tr[history_key[rev]]
                        break
        if val:
            hist = HistoryInfo.from_bytes(val)
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
            elif not exists:
                active = FileInfo()
            else:
                active = FileInfo.from_bytes(bytes(active))
                if active.get('flag') == OP_DELETED and mode != Perm.write:
                    return {}
                rev = active.rev if rev is None else rev

            if not getattr(active, 'history_key'):
                active.history_key = self.make_history_key(path)

            hist = self._get_history_for_rev(tr, path, active.history_key, rev)
        combined = ListInfo()
        if hist:
            combined.update(hist)
            combined.update(active)
            combined.rev = hist.rev
        return combined

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

        active_info = FileInfo(created=created, modified=modified)
        with self._begin(write=True) as tr:
            # first, get the active info
            old_info = meta[u'file_info']
            if old_info:
                hist_key = old_info.history_key
            if not hist_key:
                hist_key = self._history[uuid.uuid4().bytes]

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

            active_info.history_key = hist_key
            active_info.rev = rev
            hist = HistoryInfo(**meta)
            hist.created = modified
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
        with self._begin(buffers=True) as tr:
            for i in tr.get_range(key[rev][0], key[rev + 1]):
                data = i.value
                if decrypt:
                    data = decrypt(data)
                yield data

    def get_file_chunk(self, file_info, chunk, cipher=None):
        key = file_info.history_key
        rev = file_info.rev
        if cipher:
            decrypt = cipher['decrypt']
        else:
            decrypt = None
        with self._begin(buffers=True) as tr:
            data = tr[key[rev][chunk]]
            if decrypt:
                data = decrypt(data)
            return data
        
    def _make_file_key(self, path):
        if not isinstance(path, six.text_type):
            path = path.decode('utf8')
        if path:
            if path[0] == u'/':
                path = path[1:]
            path = [p for p in path.split(u'/') if p]
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
            val = tr[key]
            if val:
                val = FileInfo.from_bytes(val)
                return val.get('flag') != OP_DELETED
        return False

    def listdir(self, dirname, walk=False, owner=None, limit=0, open_files=False, delimiter='/', rev=None, **kwargs):
        if delimiter:
            nd = os.path.normpath(dirname)
            if dirname.endswith(delimiter) and not nd.endswith(delimiter):
                nd += delimiter

            dirname = nd
        with self._begin(buffers=True) as tr:
            start = self._make_file_key(dirname).key()[:-1]
            end = start + b'\xff'

            nc = dirname.count(delimiter)
            for k, v in tr.get_range(start, end, limit=limit):
                k = self._files.unpack(k)[0]
                path = u'/' + u'/'.join(k)

                if not walk and path.count(delimiter) > nc:
                    continue
                if open_files:
                    yield VersionedFile(self, path, mode=Perm.read, requestor=owner, rev=rev)
                else:
                    finfo = FileInfo.from_bytes(v)
                    meta = ListInfo()
                    if finfo.get('flag') == OP_DELETED:
                        continue

                    if not finfo.history_key:
                        finfo.history_key = self.make_history_key(path)

                    hist = self._get_history_for_rev(tr, path, finfo.history_key, rev or finfo.rev)
                    if hist:
                        meta.update(hist)
                    meta.update(finfo)
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
                hist = HistoryInfo(path=frompath,
                                 owner=owner,
                                 meta={u'operation': u'mv', u'dest': topath})
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
                meta = HistoryInfo(path=path, 
                                    owner=owner,
                                    meta={u'operation': u'del'},
                                    created=created,
                       )
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
        # latest = list(tr.get_range(found['range'].start, found['range'].stop, limit=1, reverse=True))[0]
        # rev = found['key'].unpack(latest.key)[0]
        # if rev is None:
        #     rev = -1
        # return rev

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
        for fp in self.listdir(repository, walk=True, open_files=True, rev=rev):
            yield fp

    def __getitem__(self, path):
        """
        gets the stored data
        """
        with self._begin(buffers=True) as tr:
            val = tr[self._kv[path]]

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
        key = self._kv[path]
        rec = KVRecord()
        rec.value = data
        val = rec.to_bytes()
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
                path = u'/' + u'/'.join(k)
                path = path.replace(prefix, '', 1)
                if path != prefix and path.count(delimiter) == 1:
                    pref[path.split(delimiter)[0]] += 1
        return pref.items()

    def get_acl(self, path, tr=None):
        tr = tr or self._begin(buffers=True)
        ppath = self._perm_path(path)
        basekey = self._perms
        acl = None
        with tr:
            while ppath:
                key = basekey[ppath]
                acl = tr[key]
                if acl:
                    acl = ACLRecord.from_bytes(acl).acl
                    break
                ppath.pop(-1)
        return acl

    def set_acl(self, path, acl):
        ppath = self._perm_path(path)
        key = self._perms[ppath]
        rec = ACLRecord()
        rec.acl = acl
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

