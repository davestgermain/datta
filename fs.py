import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB, insert
import io
import hashlib
import os.path
import mimetypes


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


class VersionedFile(io.BufferedIOBase):
    created = None
    modified = None
    version = None

    def __init__(self, path, conn=None, mode='r', transaction=None, meta=None, **kwargs):
        io.BufferedIOBase.__init__(self)
        self.path = self.name = path
        self.mode = mode
        self._conn = conn
        self._transaction = transaction
        self._buf = bytearray()
        self.meta = meta or {}
        self._chunks = None
        self.update(kwargs)
        if mode == 'w':
            self.sha256 = hashlib.sha256()
            self._length = 0

    def close(self):
        if self.writable() and self.version:
            data = bytes(self._buf) or None
            content_type = getattr(self, 'content_type', None)
            if not content_type:
                content_type = mimetypes.guess_type(self.path)[0]
            self.meta['length'] = self._length
            self.meta['sha256'] = self.sha256.hexdigest()
            hist_data = {
                'data': data,
                'meta': self.meta,
                'content_type': content_type,
                'owner': getattr(self, 'owner', None)
            }
            self._conn.execute(history.update().where(history.c.id == self.version).values(hist_data))
            upd = insert(active).values(path=self.path, created=sa.func.now(), modified=sa.func.now(), version=self.version).on_conflict_do_update(constraint=active.primary_key, set_={'version': self.version, 'modified': sa.func.now()})
            self._conn.execute(upd)
            self._transaction.commit()
            self._conn.close()
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

    def update(self, kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


class FSManager:
    nextrev = sa.select([sa.func.ifnull(sa.func.max(history.c.rev), -1) + 1])

    def __init__(self, dsn, debug=False):
        self.dsn = dsn
        self.engine = sa.create_engine(dsn, echo=debug, json_deserializer=lambda x: x)
        self.setup()

    def setup(self):
        meta.create_all(self.engine)

    def get_meta_history(self, path):
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
        result = self.engine.execute(sa.select([active.c.path]).where(active.c.path == path)).fetchone()
        return bool(result)

    def listdir(self, dirname, walk=False):
        dirname = os.path.normpath(dirname)
        if not dirname.endswith('/'):
            dirname += '/'
        sql = sa.select([active]).where(active.c.path.like('{}%'.format(dirname))).order_by(sa.asc(active.c.path))
        numslashes = dirname.count('/')
        for row in self.engine.execute(sql):
            if not walk and row.path.count('/') > numslashes:
                continue
            yield row.path, row.created, row.modified, row.version
    
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

    def delete(self, path, owner='*'):
        """
        delete a file
        """
        path = os.path.normpath(path)
        if not self.check_perm(path, owner=owner, perm='d'):
            raise PermissionError(path)
        with self.engine.begin() as conn:
            # record the history of deletion
            hist_inst = history.insert({'path': path, 
                                        'rev': self.nextrev.where(history.c.path==path),
                                        'owner': owner,
                                        'meta': {'comment': 'deleted'}
                                       })
            conn.execute(hist_inst)
            sql = active.delete().where(active.c.path == path)
            result = conn.execute(sql)
            return bool(result)

    def check_perm(self, path, owner='*', perm='r', conn=None):
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
        result = (conn or self.engine).execute(sql)
        return list(result)

    def set_perm(self, path, owner, perm='r'):
        values = {
            'path': path,
            'owner': owner,
            'perm': perm
        }
        # sql = insert(perms).values(**values).on_conflict_do_update(constraint=perms.primary_key, set_=values)
        sql = insert(perms).values(**values).on_conflict_do_nothing(constraint=perms.primary_key)
        result = self.engine.execute(sql)


    def clear_perm(self, path, owner, perm):
        return self.engine.execute(perms.delete().where(path == path).where(owner == owner).where(perm == perm))

    def maxrev(self, prefix='/'):
        """
        return maximum revision for fs, starting at prefix
        """
        sql = sa.select([sa.func.max(history.c.rev)]).where(history.c.path.like(prefix + '%'))
        result = self.engine.execute(sql).fetchone()[0] or 0
        return result

    def changes(self, prefix='/', since=0):
        sql = sa.select([history.c.path]).where(history.c.path.like(prefix + '%')).where(history.c.rev > since).order_by(sa.desc(history.c.created))
        for row in self.engine.execute(sql):
            yield row[0]

    def open(self, path, mode='r', rev=None, version=None, owner='*'):
        path = os.path.normpath(path)

        connection = self.engine.connect()
        vf = VersionedFile(path, mode=mode, conn=connection)
        if mode == 'r':
            cols = [history.c.id, 
                    history.c.rev,
                    history.c.data,
                    history.c.content_type,
                    history.c.owner,
                    history.c.meta]
            if not (version or rev):
                cols.extend([
                    active.c.created,
                    active.c.modified,
                    active.c.version])
            sql = sa.select(cols)
            if version:
                sql = sql.where(history.c.id == version)
            elif rev:
                sql = sql.where(history.c.rev == rev)
            else:
                sql = sql.where(active.c.path == path).where(active.c.version == history.c.id)
            result = connection.execute(sql).fetchone()
            if not result:
                raise FileNotFoundError(path)
            elif not self.check_perm(path, owner=owner, perm=mode, conn=connection):
                raise PermissionError(path)  
            vf.update(result)
        elif mode == 'w':
            if not self.check_perm(path, owner=owner, perm=mode, conn=connection):
                raise PermissionError(path)
            trans = connection.begin()
            hist_inst = history.insert({'path': path, 
                                        'rev': self.nextrev.where(history.c.path==path)
                                       })
            result = connection.execute(hist_inst)
            vf.version = result.inserted_primary_key[0]
            vf._transaction = trans
        return vf

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
