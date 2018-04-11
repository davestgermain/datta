from hatta.search import WikiSearch
import hatta
import threading
import os.path, os
import time
from collections import defaultdict
from whoosh import index, fields, query
from whoosh.qparser import QueryParser
from whoosh.filedb.filestore import Storage, FileStorage
from whoosh.filedb.structfile import StructFile
try:
    import cPickle as pickle
except ImportError:
    import pickle


class DBStorage(Storage):
    def __init__(self, fs, prefix):
        self.fs = fs
        self.prefix = prefix
        self.locks = {}

    def create(self):
        self.fs.set_perm(self.prefix, '*', ['r', 'w', 'd'])

    def _topath(self, name):
        return os.path.join(self.prefix, name)

    def create_file(self, name, mode='w'):
        return self.open_file(name, mode='w')

    def delete_file(self, name):
        self.fs.delete(self._topath(name), include_history=True)

    def rename_file(self, fromname, toname, safe=False):
        if safe and self.file_exists(toname):
            raise Exception(toname)
        self.fs.rename(self._topath(fromname), self._topath(toname), record_move=False)

    def file_exists(self, name):
        return self._topath(name) in self.fs

    def file_length(self, name):
        with self.fs.open(self._topath(name), mode='r') as fp:
            return fp.length

    def file_modified(self, name):
        with self.fs.open(self._topath(name), mode='r') as fp:
            return fp.modified

    def __iter__(self):
        l = self.list()
        return iter(l)

    def list(self):
        return [p.path.replace(self.prefix, u'') for p in self.fs.listdir(self.prefix)]

    def open_file(self, name, mode='r'):
        path = self._topath(name)
        sf = StructFile(self.fs.open(path, mode=mode))
        sf.is_real = False
        sf.fileno = None
        return sf

    def lock(self, name):
        if name not in self.locks:
            self.locks[name] = threading.Lock()
        return self.locks[name]

    def temp_storage(self, name=None):
        name = name or ('temp%d' % time.time())
        prefix = os.path.join(os.path.dirname(self.prefix), name)
        return DBStorage(self.fs, prefix)

    def destroy(self):
        for f in self.fs.listdir(self.prefix):
            self.fs.delete(f.path, include_history=True)


class WikiDBSearch(WikiSearch):
    INDEX_THREAD = None

    def __init__(self, cache_path, lang, storage):
        self.fs = storage.fs
        self.storage = storage
        self.lang = lang
        if lang == "ja":
            self.split_text = self.split_japanese_text
        self.schema = fields.Schema(links=fields.KEYWORD(stored=True), title=fields.ID(stored=True, unique=True), content=fields.TEXT, has_links=fields.BOOLEAN, wanted=fields.KEYWORD(stored=True))
        
        ipath = os.path.join(cache_path, 'search')
        if not os.path.exists(ipath):
            os.makedirs(ipath)
        self.istore = FileStorage(ipath)
        # self.istore = DBStorage(self.fs, os.path.join('/.meta/', storage._wiki, 'search/'))
        
        if self.istore.index_exists():
            self.index = self.istore.open_index()
        else:
            self.index = self.istore.create_index(schema=self.schema)
        # self._thread = None

    def get_last_revision(self):
        """Retrieve the last indexed repository revision."""
        try:
            with self.istore.open_file('reporev') as fp:
                rev = int(fp.read())
        except:
            rev = -1
        return rev

    def set_last_revision(self, rev):
        """Store the last indexed repository revision."""
        with self.istore.create_file('reporev') as fp:
            fp.write(str(rev))

    def find(self, words):
        """Iterator of all pages containing the words, and their scores."""
        with self.index.searcher() as searcher:
            sq = query.And([query.Term("content", w) for w in words])
            results = searcher.search(sq, limit=1000)
            for result in results:
                title = result['title']
                score = int(result.score)
                yield score, title

    def update(self, wiki):
        """Reindex al pages that changed since last indexing."""
        last_rev = self.get_last_revision()
        if last_rev == -1:
            changed = self.storage.all_pages()
        else:
            changed = self.storage.changed_since(last_rev)
        changed = list(changed)
        if changed:
            self.reindex(wiki, changed)
            # if self.INDEX_THREAD and self.INDEX_THREAD.is_alive:
            #     print 'alreading reindexing'
            # else:
            #     self.INDEX_THREAD = threading.Thread(target=self.reindex, args=(wiki, changed))
            #     self.INDEX_THREAD.daemon = True
            #     self.INDEX_THREAD.start()

    def reindex(self, wiki, pages):
        with self.index.writer() as writer:
            with self.index.searcher() as s:
                for title in pages:
                    writer.delete_by_term('title', title, searcher=s)
            for title in pages:
                page = hatta.page.get_page(None, title, wiki)
                self.reindex_page(page, title, writer)
                # print 'INDEXED', title
        self.empty = False
        rev = self.storage.repo_revision()
        self.set_last_revision(rev)
        self.INDEX_THREAD = None

    def reindex_page(self, page, title, writer, text=None):
        """Updates the content of the database, needs locks around."""

        if text is None:
            get_text = getattr(page, 'plain_text', lambda: u'')
            try:
                text = get_text()
            except hatta.error.NotFoundErr:
                text = None

        extract_links = getattr(page, 'extract_links', None)
        links = []
        wanted = []
        if extract_links and text:
            for link, label in extract_links(text):
                qlink = link.replace(u' ', u'%20')
                label = label.replace(u' ', u'%20')
                links.append(u'%s:%s' % (qlink, label))
                if link[0] != '+' and link not in wanted and link not in self.storage:
                    wanted.append(qlink)
        else:
            links = []
        doc = {'title': unicode(title)}
        if links:
            doc['links'] = u' '.join(links)
            doc['has_links'] = True
        if wanted:
            doc['wanted'] = u' '.join(wanted)
        if text:
            doc['content'] = text
            writer.add_document(**doc)
        else:
            writer.delete_by_term('title', title)

    def update_page(self, page, title, data=None, text=None):
        """Updates the index with new page content, for a single page."""

        if text is None and data is not None:
            text = unicode(data, self.storage.charset, 'replace')
        self.set_last_revision(self.storage.repo_revision())
        with self.index.writer() as writer:
            with self.index.searcher as s:
                writer.delete_by_term('title', title, searcher=s)
            self.reindex_page(page, title, writer, text=text)

    def orphaned_pages(self):
        """Gives all pages with no links to them."""
        linked = set()
        total = {p for p in self.storage}
        with self.index.searcher() as searcher:
            for doc in searcher.search(query.Every('has_links'), limit=10000):
                for link in doc['links'].split():
                    link = link.split(':', 1)[0]
                    linked.add(link.replace('%20', ' '))
        return sorted(total - linked)

    def wanted_pages(self):
        """Gives all pages that are linked to, but don't exist, together with
        the number of links."""
        with self.index.searcher() as searcher:
            wanted = defaultdict(int)
            for doc in searcher.search(query.Every('wanted'), limit=8000):
                for link in doc['wanted'].split(' '):
                    wanted[link.replace('%20', ' ')] += 1
        items = [(count, link) for link, count in wanted.items()]
        items.sort(reverse=True)
        return items

    def page_backlinks(self, title):
        """Gives a list of pages linking to specified page."""
        with self.index.searcher() as searcher:
            title = title.replace(' ', '%20')
            sq = query.Prefix("links", title + ':')
            results = set()
            for result in searcher.search(sq, limit=8000):
                results.add(result['title'])
            return results

    def page_links(self, title):
        """Gives a list of links on specified page."""
        return [l[0] for l in self.page_links_and_labels(title)]

    def page_links_and_labels(self, title):
        with self.index.searcher() as searcher:
            doc = searcher.document(title=title)
            if doc:
                links = doc.get('links', '')
                for l in links.split():
                    link, label = l.split(':', 1)
                    yield link.replace('%20', ' '), label.replace('%20', ' ')
