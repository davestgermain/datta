from whoosh import index, fields, query
from whoosh.qparser import QueryParser
from whoosh.filedb.filestore import Storage
from whoosh.filedb.structfile import StructFile
import six
import os.path, os
import time
import threading



class DBStorage(Storage):
    def __init__(self, fs, prefix):
        self.fs = fs
        self.prefix = prefix
        self.locks = {}

    def create(self):
        self.fs.set_perm(self.prefix, u'*', u'rwd')
        config = self.fs.get_path_config(self.prefix)
        if config.get('versioning', None) is None:
            config.versioning = False
            self.fs.set_path_config(self.prefix, config)

    def _topath(self, name):
        return os.path.join(self.prefix, name)

    def create_file(self, name, mode=u'w'):
        return self.open_file(six.text_type(name), mode=u'w')

    def delete_file(self, name):
        self.fs.delete(self._topath(name), include_history=True)

    def rename_file(self, fromname, toname, safe=False):
        if safe and self.file_exists(toname):
            raise Exception(toname)
        self.fs.rename(self._topath(fromname), self._topath(toname), record_move=False)

    def file_exists(self, name):
        return self._topath(name) in self.fs

    def file_length(self, name):
        with self.fs.open(self._topath(name), mode=u'r') as fp:
            return fp.length

    def file_modified(self, name):
        with self.fs.open(self._topath(name), mode=u'r') as fp:
            return fp.modified

    def __iter__(self):
        l = self.list()
        return iter(l)

    def list(self):
        return [p.path.replace(self.prefix, u'') for p in self.fs.listdir(self.prefix) if p.get('content_type') != u'application/x-directory']

    def open_file(self, name, mode=u'r'):
        path = self._topath(name)
        uf = self.fs.open(path, mode=mode)
        if mode == u'w':
            uf.content_type = 'application/structfile'
            uf.force_rev = 0
        sf = StructFile(uf)
        sf.is_real = False
        sf.fileno = None
        return sf

    def lock(self, name):
        if name not in self.locks:
            self.locks[name] = threading.Lock()
        return self.locks[name]

    def temp_storage(self, name=None):
        name = name or (u'temp%d' % time.time())
        prefix = os.path.join(os.path.dirname(self.prefix), name)
        return DBStorage(self.fs, prefix)

    def destroy(self):
        for f in self.fs.listdir(self.prefix):
            self.fs.delete(f.path, include_history=True)


class IndexManager(object):
    def __init__(self, fs):
        self.fs = fs
        self.istore = DBStorage(self.fs, u'/.search/')
        self.istore.create()
        self.indexes = {}

    def get_index(self, name):
        if name not in self.indexes:
            self.indexes[name] = self.istore.open_index(name)
        return self.indexes[name].refresh()

    def index_searcher(self, index_name):
        return self.get_index(index_name).searcher()

    def index_writer(self, index_name):
        return self.get_index(index_name).writer()

    def index_exists(self, index_name):
        return self.istore.index_exists(index_name)

    def create_index(self, index_name, schema):
        """
        schema config looks like:
        {
            fieldname: {
                    type: KEYWORD
                    kwargs: {kwargs}
                }
        }
        """
        constructed = {}
        for field, config in schema.items():
            klass = getattr(fields, config['type'].upper())
            if 'kwargs' in config:
                klass = klass(**config['kwargs'])
            constructed[field] = klass
        schema = fields.Schema(**constructed)
        index = self.istore.create_index(schema, indexname=index_name)
        self.indexes[index_name] = index
        return index

    def simple_search(self, index_name, words, limit=1000, field='content'):
        if isinstance(words, six.text_type):
            words = words.split()
        sq = query.And([query.Term(field, w) for w in words])
        return self.run_query(index_name, sq, limit=limit)

    def run_query(self, index_name, query, limit=1000):
        with self.index_searcher(index_name) as searcher:
            results = searcher.search(query, limit=limit)
            for result in results:
                yield result

    def get_index_revision(self, index_name):
        """Retrieve the last indexed repository revision."""
        try:
            with self.istore.open_file(index_name + '-rev') as fp:
                rev = int(fp.read())
        except:
            rev = -1
        return rev

    def set_index_revision(self, index_name, rev):
        """Store the last indexed repository revision."""
        with self.istore.create_file(index_name + '-rev') as fp:
            fp.write(str(rev))
