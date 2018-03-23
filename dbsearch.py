from datta.base import BaseDB
from hatta.search import WikiSearch
import hatta
import threading


class WikiDBSearch(BaseDB, WikiSearch):
    INDEX_THREAD = None
    CREATE_SQL = '''
    CREATE TABLE IF NOT EXISTS titles (
        id SERIAL PRIMARY KEY, 
        title VARCHAR
    );
    CREATE TABLE IF NOT EXISTS words (
        word VARCHAR,
        page INTEGER,
        count INTEGER,
        INDEX (page),
        INDEX (word)
    );
    CREATE TABLE IF NOT EXISTS links (
        src INT, 
        target VARCHAR, 
        label VARCHAR, 
        number INTEGER,
        INDEX (src),
        INDEX (target)
    )
    '''
    def __init__(self, cache_path, lang, storage):
        self.storage = storage
        self.lang = lang
        if lang == "ja":
            self.split_text = self.split_japanese_text
        BaseDB.__init__(self, self.storage.dsn)
        self._thread = None

    def get_last_revision(self):
        """Retrieve the last indexed repository revision."""
        return self.storage.get_counter('searchrev') or -1

    def set_last_revision(self, rev, cursor=None):
        """Store the last indexed repository revision."""
        self.storage.set_counter('searchrev', rev, cursor=cursor)

    def find(self, words):
        """Iterator of all pages containing the words, and their scores."""

        with self.cursor() as c:
            ranks = []
            for word in words:
                # Calculate popularity of each word.
                sql = 'SELECT SUM(words.count) FROM words WHERE word LIKE %s'
                c.execute(sql, ('%%%s%%' % word,))
                rank = c.fetchone()[0]
                # If any rank is 0, there will be no results anyways
                if not rank:
                    return
                ranks.append((rank, word))
            ranks.sort()
            # Start with the least popular word. Get all pages that contain it.
            first_rank, first = ranks[0]
            rest = ranks[1:]
            sql = ('SELECT words.page, titles.title, SUM(words.count) '
                   'FROM words, titles '
                   'WHERE word LIKE %s AND titles.id=words.page '
                   'GROUP BY words.page, titles.title')
            c.execute(sql, ('%%%s%%' % first,))
            # Check for the rest of words
            for title_id, title, first_count in c:
                # Score for the first word
                score = float(first_count) / float(first_rank)
                for rank, word in rest:
                    sql = ('SELECT SUM(count) FROM words '
                           'WHERE page=%s AND word LIKE %s;')
                    c.execute(sql,
                        (title_id, '%%%s%%' % word))
                    count = c.fetchone()[0]
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
        with self.cursor() as c:
            for title in pages:
                page = hatta.page.get_page(None, title, wiki)
                self.reindex_page(page, title, c)
                c.connection.commit()
            self.empty = False
            rev = self.storage.repo_revision(cursor=c)
            self.set_last_revision(rev, cursor=c)
        self.INDEX_THREAD = None

    def reindex_page(self, page, title, cursor, text=None):
        """Updates the content of the database, needs locks around."""

        if text is None:
            get_text = getattr(page, 'plain_text', lambda: u'')
            try:
                text = get_text()
            except hatta.error.NotFoundErr:
                text = None
                title_id = self.title_id(title, cursor)
                cursor.execute("DELETE FROM titles WHERE id = %s", (title_id,))

        extract_links = getattr(page, 'extract_links', None)
        if extract_links and text:
            links = extract_links(text)
        else:
            links = []
        self.update_links(title, links, cursor=cursor)
        if text is not None:
            self.update_words(title, text, cursor=cursor)

    def update_page(self, page, title, data=None, text=None):
        """Updates the index with new page content, for a single page."""

        if text is None and data is not None:
            text = unicode(data, self.storage.charset, 'replace')
        self.set_last_revision(self.storage.repo_revision())
        with self.cursor() as c:
            self.reindex_page(page, title, c, text)

    def title_id(self, title, cursor):
        r = cursor.execute('SELECT id FROM titles WHERE title = %s', (title,))
        idents = cursor.fetchone()
        if idents is None:
            cursor.execute('INSERT INTO titles (title) VALUES (%s) RETURNING id', (title,))
            idents = cursor.fetchone()
        return idents[0]

    def update_words(self, title, text, cursor):
        title_id = self.title_id(title, cursor)
        cursor.execute('DELETE FROM words WHERE page = %s', (title_id,))
        if not text:
            return
        words = self.count_words(self.split_text(text))
        title_words = self.count_words(self.split_text(title))
        for word, count in title_words.iteritems():
            words[word] = words.get(word, 0) + count
        chunk = []
        chunksize = 100
        for word, count in words.iteritems():
            chunk.append((word, title_id, count))
            if len(chunk) == chunksize:
                cursor.executemany('INSERT INTO words VALUES (%s, %s, %s)', chunk)
                chunk = []

    def update_links(self, title, links_and_labels, cursor):
        title_id = self.title_id(title, cursor)
        cursor.execute('DELETE FROM links WHERE src = %s', (title_id,))
        for number, (link, label) in enumerate(links_and_labels):
            cursor.execute('INSERT INTO links VALUES (%s, %s, %s, %s)',
                             (title_id, link, label, number))

    def orphaned_pages(self):
        """Gives all pages with no links to them."""
        with self.cursor() as c:
            sql = 'SELECT title FROM titles left join links on titles.title = links.target WHERE links.src IS NULL ORDER BY title'
            c.execute(sql)
            for (title,) in c:
                yield unicode(title)

    def wanted_pages(self):
        """Gives all pages that are linked to, but don't exist, together with
        the number of links."""
        with self.cursor() as c:
            sql = '''SELECT count(*) AS c, target FROM links 
            LEFT JOIN titles ON titles.title = links.target 
            WHERE titles.title IS NULL 
            GROUP BY target ORDER BY c DESC'''
            c.execute(sql)
            for (refs, db_title) in c:
                title = unicode(db_title)
                yield refs, title

    def page_backlinks(self, title):
        """Gives a list of pages linking to specified page."""
        with self.cursor() as c:
            sql = ('SELECT DISTINCT(titles.title) '
                   'FROM links, titles '
                   'WHERE (titles.id=links.src) AND (links.target=%s) '
                   'ORDER BY links.target')
            c.execute(sql, (title,))
            for (backlink,) in c:
                yield unicode(backlink)

    def page_links(self, title):
        """Gives a list of links on specified page."""
        with self.cursor() as c:
            sql = 'SELECT links.target FROM links, titles WHERE links.src=titles.id AND titles.title=%s ORDER BY links.number;'
            c.execute(sql, (title,))
            for (link,) in c:
                yield unicode(link)

    def page_links_and_labels(self, title):
        with self.cursor() as c:
            sql = '''SELECT links.target, links.label 
                FROM links, titles 
                WHERE links.src=titles.id and titles.title=%s 
                ORDER BY links.number'''
            c.execute(sql, (title,))
            for link, label in c:
                yield unicode(link), unicode(label)
