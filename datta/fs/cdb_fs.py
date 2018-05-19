from .base import BaseManager, VersionedFile
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB, insert


CHUNKSIZE = 800*1024

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


class FSManager(BaseManager):
    sqlalchemy_meta = meta

    def _setup(self):
        self.engine = sa.create_engine(self.dsn, echo=self.debug, json_deserializer=lambda x: x)
        self.sqlalchemy_meta.create_all(self.engine)

    def __contains__(self, path):
        result = self.engine.execute(sa.select([active.c.path]).where(active.c.path == path)).first()
        return bool(result)

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

    def get_file_metadata(self, path, rev):
        result = self.engine.execute(_file_meta_query(rev=rev).where(active.c.path == path)).first()
        result.bs = CHUNKSIZE
        return result
    
    def save_file_data(self, path, meta, buf, cipher=None):
        rev = meta.get('rev', None)
        if rev is None:
            meta['rev'] = NEXTREV.where(history.c.path == self.path)
            modified = sa.func.now()
        else:
            modified = meta['created']
        created = meta.get('created', sa.func.now())

        if meta['length'] <= CHUNKSIZE:
            data = buf.getvalue()
        else:
            data = None
        hist_data = {
            'created': created,
            'path': path,
            'meta': meta['meta'],
            'content_type': meta['content_type'],
            'rev': meta['rev'],
            'owner': meta['owner'],
            'data': data
        }
        with self.engine.begin() as conn:
            # try to insert into history
            version = conn.execute(history.insert(meta)).inserted_primary_key[0]
            # now write the chunks, if necessary
            if data is None and meta['length']:
                while 1:
                    chunk = buf.read(CHUNKSIZE)
                    if not chunk:
                        break
                    if cipher:
                        chunk = cipher['encrypt'](chunk)
                    r = conn.execute(chunks.insert({'version': version, 'data': chunk}))
            upd = insert(active).values(
                            path=path,
                            created=created,
                            modified=created, 
                            version=version,
                            length=meta['length']).on_conflict_do_update(constraint=active.primary_key, set_={
                                    'version': version,
                                    'length': meta['length'],
                                    'modified': modified})
            conn.execute(upd)

    def get_file_chunks(self, path, rev, chunk=None, cipher=None):
        result = self.engine.execute(sa.select([chunks.c.data], order_by=chunks.c.id).where(history.c.path==path).where(history.c.rev==rev).where(chunks.c.version==history.c.id))
        for r in result:
            chunk = r[0]
            if cipher:
                chunk = cipher['decrypt'](chunk)
            yield chunk

    def subdirectories(self, dirname, delimiter='/'):
        """
        returns the subdirectories off of dirname
        """
        dirname = os.path.normpath(dirname)
        if not dirname.endswith(delimiter):
            dirname += delimiter
        
        slashcount = dirname.count(delimiter)
        dirname += '%'

        sql = sa.text(r"select split_part(path, :d, :sc), count(*) from fs_files where path like :p and split_part(path, :d, :sd) != '' group by 1").bindparams(d=delimiter, p=dirname, sc=slashcount + 1, sd=slashcount + 2)
        counts = []
        for sd, count in self.engine.execute(sql):
            counts.append((sd, count))
        return counts

    def common_prefixes(self, prefix, delimiter):
        slashcount = prefix.count(delimiter)
        sql = sa.text(r"select split_part(path, :d, :sc), count(*) from fs_files where path like :p and split_part(path, :d, :sd) != '' group by 1").bindparams(d=delimiter, p=prefix + '%', sc=slashcount + 1, sd=slashcount + 2)
        counts = []
        for sd, count in self.engine.execute(sql):
            counts.append((sd, count))
        return counts

    def listdir(self, dirname, walk=False, owner=None, limit=None, open_files=False, order=None, where=None, cols=None, delimiter='/'):
        if delimiter:
            nd = os.path.normpath(dirname)
            if dirname.endswith(delimiter) and not nd.endswith(delimiter):
                nd += delimiter

            dirname = nd
        sql = _file_meta_query(include_data=open_files)
        sql = sql.where(active.c.path.like('{}%'.format(dirname)))
        if where is not None:
            sql = sql.where(where)
        if not walk:
            slashcount = dirname.count(delimiter)
            endq = sa.text("split_part(fs_files.path, :d, :c) = ''").bindparams(d=delimiter, c=slashcount + 2)
            sql = sql.where(endq)

        if order is not None:
            sql = sql.order_by(order)
        
        if limit is not None:
            sql = sql.limit(limit)

        with self.engine.begin() as conn:
            for row in conn.execute(sql):
                if open_files:
                    data = dict(row)
                    yield VersionedFile(row.path, conn, mode='r', requestor=owner, **row)
                else:
                    if owner and not self.check_perm(row.path, owner=owner, raise_exception=False, tr=conn):
                        continue
                    yield row

    def delete(self, path, owner='*', include_history=False, force_timestamp=None):
        """
        delete a file
        """
        path = os.path.normpath(path)
        with self.engine.begin() as conn:
            self.check_perm(path, owner=owner, perm='d', tr=conn)
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
                                            'meta': {'operation': 'del'},
                                            'created': force_timestamp or sa.func.now(),
                                           })
                conn.execute(hist_inst)
            return bool(result)

    def delete_old_versions(self, path, owner='*', maxrev=-1):
        path = os.path.normpath(path)
        with self.engine.begin() as conn:
            self.check_perm(path, owner=owner, perm='d', tr=conn)
            sql = history.delete().where(history.c.path == path)
            if maxrev > -1:
                sql = sql.where(history.c.rev < maxrev)
            else:
                # get the active version
                version = conn.execute(sa.select([active.c.version]).where(active.c.path == path)).first()[0]
                sql = sql.where(history.c.id != version)
            return conn.execute(sql).rowcount

    def rename(self, frompath, topath, owner='*', record_move=True):
        frompath = os.path.normpath(frompath)
        topath = os.path.normpath(topath)
        assert frompath in self
        with self.engine.begin() as conn:
            self.check_perm(frompath, owner=owner, perm='w', tr=conn)
            self.check_perm(topath, owner=owner, perm='w', tr=conn)
            last_rev = conn.execute(sa.select([history]).where(history.c.path == frompath).order_by(sa.desc(history.c.rev))).first()
            
            # move the latest history item
            conn.execute(history.update().where(history.c.id == last_rev.id).values(path=topath))
            # create a history item for the old path
            if record_move:
                hist_inst = history.insert({'path': frompath, 
                                            'rev': NEXTREV.where(history.c.path==topath),
                                            'owner': owner,
                                            'meta': {'operation': 'mv', 'dest': topath}
                                           })
                conn.execute(hist_inst)
            sql = active.update().where(active.c.path == frompath).values(path=topath)
            result = conn.execute(sql)
            return result.rowcount

    def check_perm(self, path, owner='*', perm='r', raise_exception=True, tr=None):
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
        if tr is None:
            tr = self.engine
        result = list(tr.execute(sql))
        if raise_exception and not result:
            raise PermissionError(path)
        else:
            return result

    def set_perm(self, path, owner, perm='r'):
        with self.engine.begin() as conn:
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

    def clear_perm(self, path, owner, perm):
        return self.engine.execute(perms.delete().where(perms.c.path == path).where(perms.c.owner == owner).where(perms.c.perm == perm))

    def repo_rev(self, repository):
        """
        return maximum revision for fs, starting at prefix
        """
        sql = sa.select([sa.func.max(history.c.rev)]).where(history.c.path.like(repository + '%'))
        result = self.engine.execute(sql).first()[0]
        if result is None:
            result = -1
        return result

    def repo_changes(self, prefix='/', since=0):
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
        with self.open(path, mode='w', owner=owner, rev=0) as fp:
            fp.content_type = 'application/msgpack'
            fp.write(msgpack.packb(data, use_bin_type=True))


    
