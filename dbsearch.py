from hatta.search import WikiSearch
import hatta
import threading
import sqlalchemy as sa


class WikiDBSearch(WikiSearch):
    INDEX_THREAD = None

    def __init__(self, cache_path, lang, storage):
        self.storage = storage
        self.engine = storage.fs.engine
        self.lang = lang
        if lang == "ja":
            self.split_text = self.split_japanese_text
        self._thread = None
        self._lastrev = -1
        self.setup()

    def setup(self):
        meta = self.storage.fs.sqlalchemy_meta
        self.words = sa.Table('search_words', meta,
            sa.Column('page', sa.String, nullable=False, index=True),
            sa.Column('word', sa.String, nullable=False, index=True),
            sa.Column('count', sa.Integer, default=0, nullable=False))
        self.links = sa.Table('search_links', meta,
            sa.Column('src', sa.String, nullable=False, index=True),
            sa.Column('target', sa.String, nullable=False, index=True),
            sa.Column('label', sa.String, nullable=False),
            sa.Column('number', sa.Integer, nullable=False, default=0))
        meta.create_all(self.engine)
    
    def get_last_revision(self):
        """Retrieve the last indexed repository revision."""
        # return self.storage.get_counter('searchrev') or -1
        return self._lastrev

    def set_last_revision(self, rev, cursor=None):
        """Store the last indexed repository revision."""
        # self.storage.set_counter('searchrev', rev, cursor=cursor)
        self._lastrev = rev

    def find(self, words):
        """Iterator of all pages containing the words, and their scores."""

        with self.engine.begin() as c:
            ranks = []
            for word in words:
                # Calculate popularity of each word.
                sql = 'SELECT SUM(count) FROM search_words WHERE word LIKE %s'
                result = c.execute(sql, ('%%%s%%' % word,))
                rank = result.fetchone()[0]
                # If any rank is 0, there will be no results anyways
                if not rank:
                    return
                ranks.append((rank, word))
            ranks.sort()
            # Start with the least popular word. Get all pages that contain it.
            first_rank, first = ranks[0]
            rest = ranks[1:]
            sql = ('SELECT page, SUM(count) '
                   'FROM search_words '
                   'WHERE word LIKE %s '
                   'GROUP BY page')
            result = c.execute(sql, ('%%%s%%' % first,))
            # Check for the rest of words
            for title, first_count in result:
                # Score for the first word
                score = float(first_count) / float(first_rank)
                for rank, word in rest:
                    sql = ('SELECT SUM(count) FROM search_words '
                           'WHERE page=%s AND word LIKE %s')
                    r = c.execute(sql,
                        (title, '%%%s%%' % word))
                    count = r.fetchone()[0]
                    if not count:
                        # If page misses any of the words, its score is 0
                        score = 0
                        break
                    score += float(count) / rank
                if score > 0:
                    yield int(100 * score), unicode(title)

    def update(self, wiki):
        """Reindex al pages that changed since last indexing."""
        last_rev = self.get_last_revision()
        if last_rev == -1:
            changed = self.storage.all_pages()
        else:
            changed = self.storage.changed_since(last_rev)
        changed = list(changed)
        if changed:
            if self.INDEX_THREAD and self.INDEX_THREAD.is_alive:
                print 'alreading reindexing'
            else:
                self.INDEX_THREAD = threading.Thread(target=self.reindex, args=(wiki, changed))
                self.INDEX_THREAD.daemon = True
                self.INDEX_THREAD.start()

    def reindex(self, wiki, pages):
        for title in pages:
            with self.engine.begin() as conn:
                page = hatta.page.get_page(None, title, wiki)
                self.reindex_page(page, title, conn)
                print title
        self.empty = False
        rev = self.storage.repo_revision()
        self.set_last_revision(rev)
        self.INDEX_THREAD = None

    def reindex_page(self, page, title, conn, text=None):
        """Updates the content of the database, needs locks around."""

        if text is None:
            get_text = getattr(page, 'plain_text', lambda: u'')
            try:
                text = get_text()
            except hatta.error.NotFoundErr:
                text = None

        extract_links = getattr(page, 'extract_links', None)
        if extract_links and text:
            links = extract_links(text)
        else:
            links = []
        self.update_links(title, links, conn=conn)
        if text is not None:
            self.update_words(title, text, conn=conn)

    def update_page(self, page, title, data=None, text=None):
        """Updates the index with new page content, for a single page."""

        if text is None and data is not None:
            text = unicode(data, self.storage.charset, 'replace')
        self.set_last_revision(self.storage.repo_revision())
        with self.engine.begin() as conn:
            self.reindex_page(page, title, conn, text)

    def update_words(self, title, text, conn):
        conn.execute(self.words.delete().where(self.words.c.page == title))
        if not text:
            return
        words = self.count_words(self.split_text(text))
        title_words = self.count_words(self.split_text(title))
        for word, count in title_words.iteritems():
            words[word] = words.get(word, 0) + count
        chunk = []
        chunksize = 100
        inst = self.words.insert()
        for word, count in words.iteritems():
            chunk.append({'word': word, 'page': title, 'count': count})
            if len(chunk) == chunksize:
                conn.execute(inst.values(chunk))
                chunk = []

    def update_links(self, title, links_and_labels, conn):
        conn.execute(self.links.delete().where(self.links.c.src == title))
        inst = self.links.insert()
        for number, (link, label) in enumerate(links_and_labels):
            conn.execute(inst.values(src=title, target=link, label=label, number=number))

    def orphaned_pages(self):
        """Gives all pages with no links to them."""
        sql = 'SELECT title FROM titles left join links on titles.title = links.target WHERE links.src IS NULL ORDER BY title'
        result = self.engine.execute(sql)
        for (title,) in result:
            yield unicode(title)

    def wanted_pages(self):
        """Gives all pages that are linked to, but don't exist, together with
        the number of links."""
        sql = '''SELECT count(*) AS c, target FROM search_links 
        LEFT JOIN titles ON titles.title = links.target 
        WHERE titles.title IS NULL 
        GROUP BY target ORDER BY c DESC'''
        result = self.engine.execute(sql)
        for (refs, db_title) in result:
            title = unicode(db_title)
            yield refs, title

    def page_backlinks(self, title):
        """Gives a list of pages linking to specified page."""
        sql = ('SELECT DISTINCT(search_links.src) '
               'FROM search_links '
               'WHERE search_links.target=%s '
               'ORDER BY target')
        result = self.engine.execute(sql, (title,))
        for (backlink,) in result:
            yield unicode(backlink)

    def page_links(self, title):
        """Gives a list of links on specified page."""
        sql = 'SELECT target FROM search_links WHERE src = %s ORDER BY number'
        result = self.engine.execute(sql, (title,))
        for (link,) in result:
            yield unicode(link)

    def page_links_and_labels(self, title):
        sql = '''SELECT target, label 
            FROM search_links 
            WHERE src = %s 
            ORDER BY number'''
        result = self.engine.execute(sql, (title,))
        for link, label in result:
            yield unicode(link), unicode(label)
