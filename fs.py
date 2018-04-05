import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB, insert
import io
import hashlib
import os.path
import mimetypes
from collections import defaultdict


try:
    PermissionError
except NameError:
    class PermissionError(IOError):
        pass
    class FileNotFoundError(IOError):
        pass

try:
    unicode = unicode
except NameError:
    unicode = str


CHUNKSIZE = 1024*1024

meta = sa.MetaData()
history = sa.Table('fs_history', meta,
        sa.Column('id', UUID, primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('path', sa.String, nullable=False),
        sa.Column('rev', sa.Integer, default=0, nullable=False),
        sa.Column('created', sa.TIMESTAMP(timezone=True), default=sa.func.now(), index=True),
        sa.Column('content_type', sa.String),
        sa.Column('owner', sa.String),
        sa.Column('meta', JSONB),
        sa.Column('data', sa.Binary),
        sa.UniqueConstraint('path', 'rev'),
        sa.Index('meta_idx', 'meta', postgresql_using="gin")
)

active = sa.Table('fs_files', meta,
        sa.Column('path', sa.String, primary_key=True, nullable=False),
        sa.Column('created', sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column('modified', sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column('version', sa.ForeignKey(history.c.id), nullable=False),
        sa.Column('length', sa.Integer, nullable=False, default=0),
)

chunks = sa.Table('fs_chunks', meta,
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('version', sa.ForeignKey(history.c.id), nullable=False),
        sa.Column('data', sa.Binary),
)

perms = sa.Table('fs_perms', meta,
        sa.Column('path', sa.String, nullable=False),
        sa.Column('owner', sa.String, nullable=False),
        sa.Column('perm', sa.String, nullable=False, default='r'),
        sa.PrimaryKeyConstraint('path', 'owner', 'perm')
)


NEXTREV = sa.select([sa.func.ifnull(sa.func.max(history.c.rev), -1) + 1])

def _file_meta_query(rev=None, version=None, include_data=True, cols=None):
    scols = []
    scols.extend([history.c.id,
            history.c.rev,
            history.c.content_type,
            history.c.owner,
            history.c.meta
        ])
    if not (version or rev):
        scols.extend([
            active.c.created,
            active.c.modified,
            active.c.version,
            active.c.path,
            active.c.length])
    sql = sa.select(scols)
    if include_data:
        sql.append_column(history.c.data)
    if cols:
        for c in cols:
            sql.append_column(c)
    if version:
        sql = sql.where(history.c.id == version)
    elif rev:
        sql = sql.where(history.c.rev == rev)
    else:
        # this is important because the query planner isn't smart enough to do the right join
        j = sa.join(history, active, (active.c.version == history.c.id) & (active.c.path == history.c.path))
        sql = sql.select_from(j)
    return sql


def check_perm(conn, path, owner='*', perm='r', raise_exception=True):
    path = os.path.normpath(path)
    dirs = [path]
    sp = path.split('/')[:-1]
    while sp:
        p = '/'.join(sp) + '/'
        dirs.append(p)
        sp.pop(-1)

    sql = sa.select([perms]).where(perms.c.perm == perm).where(perms.c.path.in_(dirs))
    if owner != '*':
        sql = sql.where(perms.c.owner.in_([owner, '*']))
    else:
        sql = sql.where(perms.c.owner == owner)
    sql = sql.order_by(sa.desc(perms.c.path))
    result = list(conn.execute(sql))
    if raise_exception and not result:
        raise PermissionError(path)
    else:
        return result

def set_perm(conn, path, owner, perm='r'):
    sql = insert(perms)
    if isinstance(perm, list):
        sql = sql.values([{'path': path, 'owner': owner, 'perm': p} for p in perm])
    else:
        values = {
            'path': path,
            'owner': owner,
            'perm': perm
        }
        sql = sql.values(path=path, owner=owner, perm=perm)
    # sql = sql.on_conflict_do_update(constraint=perms.primary_key, set_=values)
    sql = sql.on_conflict_do_nothing(constraint=perms.primary_key)
    result = conn.engine.execute(sql)


class VersionedFile(io.BufferedIOBase):
    def __init__(self, filename, conn, mode='r', requestor='*', meta=None, rev=None, version=None, **kwargs):
        io.BufferedIOBase.__init__(self)
        self.path = self.name = filename
        check_perm(conn, self.path, owner=requestor, perm=mode)
        self.created = None
        self.modified = None
        self.meta = meta or {}
        self.mode = mode
        self._version = None
        _transaction = None
        if mode == 'r' and 'id' not in kwargs:
            result = conn.execute(_file_meta_query(rev=rev, version=version).where(active.c.path == self.path)).first()
            if not result:
                raise FileNotFoundError(self.path)
            self.update(result)
            # if self.data:
            #     conn.close()
        elif mode == 'w':
            _transaction = conn.begin()
            result = conn.execute(_file_meta_query(rev=rev, version=version).where(active.c.path == self.path)).first()
            if result:
                self.update(result)
                self.data = None
            self.owner = requestor 

        self._transaction = _transaction
        self._conn = conn
        self._buf = bytearray()
        self._chunks = None
        
        self.update(kwargs)
        if mode == 'w':
            self.sha256 = hashlib.sha256()
            self._length = 0

    @property
    def _hist_data(self):
        d = {
            'path': self.path,
            'rev': NEXTREV.where(history.c.path==self.path)
        }
        if self.created:
            d['created'] = self.created
        content_type = getattr(self, 'content_type', None)
        if not content_type:
            content_type = mimetypes.guess_type(self.path)[0]
        d['content_type'] = content_type
        if getattr(self, 'force_rev', None):
            d['rev'] = self.force_rev
        return d

    @property
    def version(self):
        if self.mode == 'w':
            if not self._version:
                # trigger an insert
                result = self._conn.execute(history.insert(self._hist_data))
                self._version = result.inserted_primary_key[0]
        return self._version
    
    @version.setter
    def version(self, v):
        self._version = v

    def close(self):
        if self.writable():
            data = bytes(self._buf) or None
            self.meta['sha256'] = self.sha256.hexdigest()
            hist_data = {
                'data': data,
                'meta': self.meta,
                'owner': getattr(self, 'owner', None)
            }
            # try to insert into history
            if not self._version:
                hist_data.update(self._hist_data)
                self.version = self._conn.execute(history.insert(hist_data)).inserted_primary_key[0]
            else:
                self._conn.execute(history.update().where(history.c.id == self.version).values(hist_data))
            created = self.created or sa.func.now()
            upd = insert(active).values(
                            path=self.path,
                            created=created,
                            modified=created, 
                            version=self.version,
                            length=self._length).on_conflict_do_update(constraint=active.primary_key, set_={
                                    'version': self.version,
                                    'length': self._length,
                                    'modified': sa.func.now()})
            self._conn.execute(upd)
            self._transaction.commit()
            self._conn.close()
            self._transaction = None
        self.mode = None
    
    def get_chunks(self):
        result = self._conn.execute(sa.select([chunks.c.data], order_by=chunks.c.id).where(chunks.c.version==self.version))
        for r in result:
            yield r[0]

    def readable(self):
        return self.mode == 'r'

    def writable(self):
        return self.mode == 'w'

    def read(self, size=-1):
        if not self.readable():
            return
        d = None
        if size == -1:
            d = self.readall()
        elif size:
            if self.data is not None:
                d, self.data = self.data[:size], self.data[size:]
            elif not self._buf:
                self.readinto(self._buf)
                d, self._buf = self._buf[:size], self._buf[size:]
                d = bytes(d)
        return d
    
    def readall(self):
        if self.readable():
            d = self.data
            if d is None:
                d = b''
                for chunk in self.get_chunks():
                    d += chunk
            self.data = None
            return d

    def readinto(self, b):
        if self.readable():
            if self.data:
                b += self.data
                return len(self.data)
            else:
                if self._chunks is None:
                    self._chunks = self.get_chunks()
                try:
                    data = next(self._chunks)
                except StopIteration:
                    return None
                b += data
                return len(data)

    def write(self, data):
        if not data:
            return
        if not self.writable():
            raise FileError()
        if isinstance(data, unicode):
            data = data.encode('utf8')
        self._buf += data
        self.sha256.update(data)
        self._length += len(data)
        if len(self._buf) >= CHUNKSIZE:
            while self._buf:
                chunk, self._buf = self._buf[:CHUNKSIZE], self._buf[CHUNKSIZE:]
                self._conn.execute(chunks.insert({'version': self.version, 'data': chunk}))
        return len(data)

    def update(self, kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)

    def seekable(self):
        return False


class FSManager(object):
    sqlalchemy_meta = meta

    def __init__(self, dsn, debug=False):
        self.dsn = dsn
        self.engine = sa.create_engine(dsn, echo=debug, json_deserializer=lambda x: x)
        self.setup()

    def setup(self):
        self.sqlalchemy_meta.create_all(self.engine)

    def get_meta_history(self, path):
        """
        return historical metadata for the path.
        if path is a directory, returns metadata for all items in the directory
        """
        sql = sa.select([history.c.path, history.c.id, history.c.rev, history.c.created, history.c.owner, history.c.meta]).order_by(sa.desc(history.c.created))
        if path.endswith('/'):
            sql = sql.where(history.c.path.like(path + '%'))
            do_dir = False
        else:
            sql = sql.where(history.c.path == path)
            do_dir = path.count('/')
        for row in self.engine.execute(sql):
            if do_dir and row.path.count('/') > do_dir:
                break
            yield row

    def __contains__(self, path):
        result = self.engine.execute(sa.select([active.c.path]).where(active.c.path == path)).first()
        return bool(result)

    def subdirectories(self, dirname):
        """
        returns the subdirectories off of dirname
        """
        dirname = os.path.normpath(dirname)
        if not dirname.endswith('/'):
            dirname += '/'
        
        sql = r"select regexp_replace(path, %s, %s) as sd from fs_files where path like %s"
        counts = defaultdict(int)
        for sd, in self.engine.execute(sql, ['{0}(.*)/.*'.format(dirname), r'\1', '{}%'.format(dirname)]):
            counts[sd] += 1
        return counts.items()

    def listdir(self, dirname, walk=False, owner=None, limit=None, open_files=False, order=None, where=None, cols=None):
        dirname = os.path.normpath(dirname)
        if not dirname.endswith('/'):
            dirname += '/'
        sql = _file_meta_query(include_data=open_files)
        sql = sql.where(active.c.path.like('{}%'.format(dirname)))
        if where is not None:
            sql = sql.where(where)
        # if not walk:
        #     sql = sql.where(active.c.path.notlike('{}%/%'.format(dirname)))
        if order is not None:
            sql = sql.order_by(order)
        
        if limit is not None:
            sql = sql.limit(limit)
        numslashes = dirname.count('/') 
        with self.engine.begin() as conn:
            for row in conn.execute(sql):
                if not walk and row.path.count('/') > numslashes:
                    continue
                if open_files:
                    data = dict(row)
                    yield VersionedFile(row.path, conn, mode='r', requestor=owner, **row)
                else:
                    if owner and not check_perm(conn, row.path, owner=owner, raise_exception=False):
                        continue
                    yield row
    
    def copyfile(self, filename_or_fileobj, topath, content_type=None):
        if isinstance(filename_or_fileobj, unicode):
            filename_or_fileobj = open(filename_or_fileobj, 'rb')
        if not content_type and hasattr(filename_or_fileobj, 'name'):
            content_type = mimetypes.guess_type(filename_or_fileobj.name)[0]
            to_ctype = mimetypes.guess_type(topath)[0]
            if to_ctype != content_type:
                content_type = to_ctype
        with self.open(topath, mode='w') as tofile:
            tofile.content_type = content_type
            while 1:
                data = filename_or_fileobj.read(8192)
                if not data:
                    break
                tofile.write(data)
            filename_or_fileobj.close()
        return tofile

    def delete(self, path, owner='*', include_history=False):
        """
        delete a file
        """
        path = os.path.normpath(path)
        with self.engine.begin() as conn:
            check_perm(conn, path, owner=owner, perm='d')
            sql = active.delete().where(active.c.path == path)
            result = conn.execute(sql)
            if include_history:
                # delete everything
                conn.execute(chunks.delete().where(
                        chunks.c.version.in_(
                                sa.select([history.c.id]).where(history.c.path == path)
                                )
                            )
                        )    
                conn.execute(history.delete().where(history.c.path == path))
            else:
                # record the history of deletion
                hist_inst = history.insert({'path': path, 
                                            'rev': NEXTREV.where(history.c.path==path),
                                            'owner': owner,
                                            'meta': {'comment': 'deleted'}
                                           })
                conn.execute(hist_inst)
            return bool(result)

    def delete_old_versions(self, path, owner='*', maxrev=-1):
        path = os.path.normpath(path)
        with self.engine.begin() as conn:
            check_perm(conn, path, owner=owner, perm='d')
            sql = history.delete().where(history.c.path == path)
            if maxrev > -1:
                sql = sql.where(history.c.rev < maxrev)
            else:
                # get the active version
                version = conn.execute(sa.select([active.c.version]).where(active.c.path == path)).first()[0]
                sql = sql.where(history.c.id != version)
            return conn.execute(sql).rowcount

    def rename(self, frompath, topath, owner='*'):
        frompath = os.path.normpath(frompath)
        topath = os.path.normpath(topath)
        assert frompath in self
        with self.engine.begin() as conn:
            check_perm(conn, frompath, owner=owner, perm='w')
            check_perm(conn, topath, owner=owner, perm='w')
            hist_inst = history.insert({'path': frompath, 
                                        'rev': NEXTREV.where(history.c.path==frompath),
                                        'owner': owner,
                                        'meta': {'comment': 'moved to %s' % topath}
                                       })
            conn.execute(hist_inst)
            sql = active.update().where(active.c.path == frompath).values(path=topath)
            result = conn.execute(sql)
            return result.rowcount

    def set_perm(self, path, owner, perm='r'):
        return set_perm(self.engine, path, owner, perm=perm)

    def clear_perm(self, path, owner, perm):
        return self.engine.execute(perms.delete().where(perms.c.path == path).where(perms.c.owner == owner).where(perms.c.perm == perm))

    def maxrev(self, prefix='/'):
        """
        return maximum revision for fs, starting at prefix
        """
        sql = sa.select([sa.func.max(history.c.rev)]).where(history.c.path.like(prefix + '%'))
        result = self.engine.execute(sql).first()[0] or -1
        return result

    def changes(self, prefix='/', since=0):
        sql = sa.select([history.c.path]).where(history.c.path.like(prefix + '%')).where(history.c.rev > since).order_by(sa.desc(history.c.created))
        for row in self.engine.execute(sql):
            yield row[0]

    def get_data(self, path, owner='*'):
        """
        gets the stored data
        """
        sql = sa.select([history.c.data, history.c.content_type]).select_from(sa.join(history, active)).where(active.c.path == path)
        result = self.engine.execute(sql).first()
        if result:
            data, ctype = result
            if ctype == 'application/msgpack':
                import msgpack
                return msgpack.unpackb(data, encoding='utf8')
            else:
                return data, ctype

    def set_data(self, path, data, owner='*'):
        """
        sets the data as a msgpack string
        """
        import msgpack
        with self.open(path, mode='w', owner=owner) as fp:
            fp.content_type = 'application/msgpack'
            fp.write(msgpack.packb(data, use_bin_type=True))

    def open(self, path, mode='r', owner='*', rev=None, version=None):
        path = os.path.normpath(path)
        return VersionedFile(path, self.engine.connect(), mode=mode, rev=rev, requestor=owner, version=version)

    def open_many(self, paths, mode='r', owner='*'):
        """
        Open files
        """
        with self.engine.begin() as conn:
            paths = (os.path.normpath(p) for p in paths)
            result = conn.execute(_file_meta_query().where(active.c.path.in_(paths)))
        
            for data in result:
                vf = VersionedFile(data.path, conn, requestor=owner, mode=mode, **data)
                yield vf


MANAGERS = {}

def get_manager(dsn, debug=False):
    if dsn not in MANAGERS:
        MANAGERS[dsn] = FSManager(dsn, debug=debug)
    return MANAGERS[dsn]



if __name__ == '__main__':
    fs = FSManager('cockroachdb://root@localhost:26257/test?application_name=cockroach&sslmode=disable', debug=True)
    
    vf = fs.open('/test.jpg', mode='r')
    hr = hashlib.md5()
    while 1:
        data = vf.read(8192)
        if not data:
            break
        hr.update(data)
    print(hr.hexdigest())
    # print(vf.__dict__)
