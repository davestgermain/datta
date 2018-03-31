import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB, insert
import io
import hashlib
import os.path


CHUNKSIZE = 1024*1024

meta = sa.MetaData()
history = sa.Table('fs_history', meta,
        sa.Column('id', UUID, primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('path', sa.String, nullable=False),
        sa.Column('created', sa.TIMESTAMP(timezone=True), default=sa.func.now()),
        sa.Column('rev', sa.Integer, default=0, nullable=False),
        sa.Column('data', sa.Binary),
        sa.Column('content_type', sa.String),
        sa.Column('owner', sa.String),
        sa.Column('meta', JSONB),
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



class VersionedFile(io.BufferedIOBase):
    created = None
    modified = None
    version = None

    def __init__(self, path, engine=None, mode='r', transaction=None, meta=None, **kwargs):
        self.path = path
        self.mode = mode
        self.engine = engine
        self.transaction = transaction
        self._buf = bytearray()
        self.meta = meta or {}
        self._chunks = None
        self.update(kwargs)
        if mode == 'w':
            self.sha256 = hashlib.sha256()
            self._length = 0

    def close(self):
        if self.writable() and self.version:
            self.mode = None
            data = bytes(self._buf) or None
            self.meta['length'] = self._length
            self.meta['sha256'] = self.sha256.hexdigest()
            self.engine.execute(history.update().where(history.c.id == self.version).values({'data': data, 'meta': self.meta}))
            upd = insert(active).values(path=self.path, created=sa.func.now(), modified=sa.func.now(), version=self.version).on_conflict_do_update(constraint=active.primary_key, set_={'version': self.version, 'modified': sa.func.now()})
            self.engine.execute(upd)
            self.transaction.commit()
    
    def get_chunks(self):
        result = self.engine.execute(sa.select([chunks.c.data], order_by=chunks.c.id).where(chunks.c.version==self.version))
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
        if size:
            if self.data is not None:
                d, self.data = self.data[:size], self.data[size:]
            elif not self._buf:
                self.readinto(self._buf)
            d, self._buf = self._buf[:size], self._buf[size:]
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
        if isinstance(data, str):
            data = data.encode('utf8')
        self._buf += data
        self.sha256.update(data)
        self._length += len(data)
        if self._length >= CHUNKSIZE:
            while self._buf:
                chunk, self._buf = self._buf[:CHUNKSIZE], self._buf[CHUNKSIZE:]
                self.engine.execute(chunks.insert({'version': self.version, 'data': chunk}))

    def update(self, kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


def setup(engine):
    meta.create_all(engine)

def get_engine():
    return sa.create_engine('cockroachdb://root@localhost:26257/test?application_name=cockroach&sslmode=disable', echo=True, json_deserializer=lambda x: x)

def open(path, engine=None, mode='r', rev=None):
    path = os.path.normpath(path)
    engine = engine or get_engine()

    connection = engine.connect()
    vf = VersionedFile(path, mode=mode, engine=connection)
    if mode == 'r':
        sql = sa.select([history.c.id, 
                         active.c.version,
                         history.c.rev,
                         history.c.data,
                         active.c.created,
                         active.c.modified,
                         history.c.meta]).where(active.c.path == path).where(active.c.version == history.c.id)
        if rev:
            sql = sql.where(history.c.rev == rev)
        result = connection.execute(sql)
        if not result:
            raise FileNotFoundError(path)
        info = result.fetchone()
        vf.update(info)
    elif mode == 'w':
        trans = connection.begin()
        hist_inst = history.insert({'path': path, 
                                    'rev': sa.select([sa.func.ifnull(sa.func.max(history.c.rev), -1) + 1]).where(history.c.path==path)
                                   })
        result = connection.execute(hist_inst)
        vf.version = result.inserted_primary_key[0]
        vf.transaction = trans
    return vf

if __name__ == '__main__':
    engine = get_engine()
    setup(engine)
    # vf = open('/test.jpg', engine=engine, mode='w')
    # with io.open('/Users/dcs/Pictures/Jean-Léon_Gérôme_-_Diogenes_-_Walters_37131.jpg', 'rb') as fp:
    #     vf.write(fp.read())
    # vf.close()
    # print(vf.__dict__)
    vf = open('/test.jpg', engine=engine, mode='r')
    hr = hashlib.md5()
    while 1:
        data = vf.read(8192)
        if not data:
            break
        hr.update(data)
    print(hr.hexdigest())
