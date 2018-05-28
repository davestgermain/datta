# from hatta.search import WikiSearch
import hatta
import os.path, os
import time
from collections import defaultdict
import six
from datta.search import IndexManager, query




class WikiDBSearch(hatta.search.WikiSearch):
    INDEX_THREAD = None

    def __init__(self, cache_path, lang, storage):
        self.fs = storage.fs
        self.storage = storage
        self.lang = lang
        if lang == "ja":
            self.split_text = self.split_japanese_text
        self.index = IndexManager(self.fs)
        self.name = storage._wiki
        
        if not self.index.index_exists(self.name):
            schema = {
                'links': {
                    'type': 'KEYWORD',
                    'kwargs': {'stored': True}
                },
                'title': {
                    'type': 'ID',
                    'kwargs': {'stored': True, 'unique': True}
                },
                'content': {
                    'type': 'TEXT',
                },
                'has_links': {
                    'type': 'BOOLEAN',
                },
                'wanted': {
                    'type': 'KEYWORD',
                    'kwargs': {'stored': True}
                },
            }
            self.index.create_index(self.name, schema)
        # self._thread = None

    def get_last_revision(self):
        """Retrieve the last indexed repository revision."""
        return self.index.get_index_revision(self.name)

    def set_last_revision(self, rev):
        """Store the last indexed repository revision."""
        return self.index.get_index_revision(self.name, rev)

    def find(self, words):
        """Iterator of all pages containing the words, and their scores."""
        for result in self.index.simple_search(self.name, words, field='content'):
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
        six.print_('changed', changed, last_rev)
        if changed:
            self.reindex(wiki, changed)
            # if self.INDEX_THREAD and self.INDEX_THREAD.is_alive:
            #     print 'alreading reindexing'
            # else:
            #     self.INDEX_THREAD = threading.Thread(target=self.reindex, args=(wiki, changed))
            #     self.INDEX_THREAD.daemon = True
            #     self.INDEX_THREAD.start()

    def reindex(self, wiki, pages):
        with self.index.index_writer(self.name) as writer:
            self.index.index_searcher(self.name) as searcher:
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
        with self.index.index_writer(self.name) as writer:
            with self.index.index_searcher(self.name) as s:
                writer.delete_by_term('title', title, searcher=s)
            self.reindex_page(page, title, writer, text=text)

    def orphaned_pages(self):
        """Gives all pages with no links to them."""
        linked = set()
        total = {p for p in self.storage}
        for doc in self.index.run_query(self.name, query.Every('has_links'), limit=10000):
            for link in doc['links'].split():
                link = link.split(':', 1)[0]
                linked.add(link.replace('%20', ' '))
        return sorted(total - linked)

    def wanted_pages(self):
        """Gives all pages that are linked to, but don't exist, together with
        the number of links."""
        wanted = defaultdict(int)
        for doc in self.index.run_query(self.name, query.Every('wanted'), limit=8000):
            for link in doc['wanted'].split(' '):
                wanted[link.replace('%20', ' ')] += 1
        items = [(count, link) for link, count in wanted.items()]
        items.sort(reverse=True)
        return items

    def page_backlinks(self, title):
        """Gives a list of pages linking to specified page."""
        title = title.replace(' ', '%20')
        sq = query.Prefix("links", title + ':')
        results = set()
        for doc in self.index.run_query(self.name, sq, limit=8000):
            results.add(doc['title'])
        return results

    def page_links(self, title):
        """Gives a list of links on specified page."""
        return [l[0] for l in self.page_links_and_labels(title)]

    def page_links_and_labels(self, title):
        with self.index.index_searcher(self.name) as searcher:
            doc = searcher.document(title=title)
            if doc:
                links = doc.get('links', '')
                for l in links.split():
                    link, label = l.split(':', 1)
                    yield link.replace('%20', ' '), label.replace('%20', ' ')
