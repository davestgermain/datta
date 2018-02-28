#!/usr/bin/python
# -*- coding: utf-8 -*-

import datetime
import time
import os
import thread
import io

# Note: we have to set these before importing Mercurial
os.environ['HGENCODING'] = 'utf-8'

import mercurial.util
import mercurial.simplemerge

from hatta import error
from hatta import page
import psycopg2
from datta.base import BaseDB


class StorageError(Exception):
    """Thrown when there are problems with configuration of storage."""


def merge_func(base, other, this):
    """Used for merging edit conflicts."""

    if (mercurial.util.binary(this) or mercurial.util.binary(base) or
        mercurial.util.binary(other)):
        raise ValueError("can't merge binary data")
    m3 = mercurial.simplemerge.Merge3Text(base, this, other)
    return ''.join(m3.merge_lines(start_marker='<<<<<<< local',
                                  mid_marker='=======',
                                  end_marker='>>>>>>> other',
                                  base_marker=None))


class WikiStorage(BaseDB):
    """
    Provides means of storing wiki pages and keeping track of their
    change history, using Mercurial repository as the storage method.
    """
    
    CREATE_SQL = '''
            CREATE TABLE IF NOT EXISTS counters (
                k STRING PRIMARY KEY,
                v INT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS {history_table} (
                title VARCHAR NOT NULL,
                rev INT,
                ts TIMESTAMPTZ, 
                author VARCHAR, 
                comment VARCHAR,
                content BYTES,
                PRIMARY KEY (title, rev),
                INDEX (ts)
            );
            CREATE TABLE IF NOT EXISTS {page_table} (
                title VARCHAR NOT NULL,
                rev INT,
                ts TIMESTAMPTZ,
                author VARCHAR,
                comment VARCHAR,
                INDEX (ts),
                PRIMARY KEY (title),
                CONSTRAINT fk_hist FOREIGN KEY (title, rev) REFERENCES {history_table} (title, rev)
            );
            CREATE TABLE IF NOT EXISTS {chunk_table} (
                title VARCHAR NOT NULL,
                rev INT,
                id SERIAL, 
                chunk BYTEA, 
                PRIMARY KEY (title, rev, id),
                CONSTRAINT fk_hist FOREIGN KEY (title, rev) REFERENCES {history_table} (title, rev)
            ) INTERLEAVE IN PARENT {history_table} (title, rev);
    '''
    CREATE_PARS = {'page_table': 'pages', 
                  'history_table': 'history', 
                  'chunk_table': 'chunks'}

    def __init__(self, path, charset=None, _=lambda x: x, unix_eol=False,
                 extension=None, repo_path=None):
        """
        Takes the path to the directory where the pages are to be kept.
        If the directory doesn't exist, it will be created. If it's inside
        a Mercurial repository, that repository will be used, otherwise
        a new repository will be created in it.
        """

        self._ = _
        self.charset = charset or 'utf-8'
        self.unix_eol = unix_eol
        self.extension = extension
        self.page_table = 'pages'
        self.history_table = 'history'
        self.chunk_table = 'chunks'
        BaseDB.__init__(self, repo_path)
        self.repo_path = repo_path

    def init_db(self):
        BaseDB.init_db(self)
        tables = self.CREATE_PARS
        with self.cursor() as c:
            # check the repo counter
            c.execute('SELECT v from counters WHERE k = %s', ('reporev', ))
            r = c.fetchone()
            if not r:
                c.execute('select IFNULL(max(rev), 0) from {history_table}'.format(**tables))
                r = c.fetchone()[0] or 0
                c.execute('INSERT INTO counters (k,v) VALUES (%s, %s)', ('reporev', r))
        self.GET_PAGE_SQL = '''SELECT p.title, p.rev, p.ts, p.author, p.comment, h.content 
                                FROM {page_table} p, {history_table} h
                                WHERE h.title = p.title AND h.rev = p.rev
                                AND p.title = %s'''.format(**tables)
        self.GET_PAGE_META_SQL = 'SELECT rev, ts, author, comment FROM {page_table} WHERE title = %s'.format(**tables)
        self.GET_HISTORY_SQL = 'SELECT rev, ts, author, comment FROM {history_table} WHERE title = %s ORDER BY ts DESC'.format(**tables)
        self.SAVE_HISTORY_SQL = """INSERT INTO {history_table} 
                (title, ts, author, comment, content, rev) 
                VALUES (%s, %s, %s, %s, %s, (
                    SELECT IFNULL(MAX(rev), -1) + 1 from {history_table} where title = %s)
                    ) 
                RETURNING rev, ts""".format(**tables)
        self.SAVE_PAGE_SQL = 'UPSERT INTO {page_table} (title, rev, ts, author, comment) VALUES (%s, %s, %s, %s, %s)'.format(**tables)
        self.CHECK_TITLE_SQL = 'SELECT 1 FROM {page_table} WHERE title = %s'.format(**tables)
        self.FIRST_REV_SQL = 'INSERT INTO {page_table} (title) VALUES (%s)'.format(**tables)
        self.GET_REV_SQL = 'SELECT content FROM {history_table} WHERE title = %s and rev = %s'.format(**tables)
        self.GET_LASTREV_SQL = 'SELECT content FROM {history_table} WHERE title = %s and rev <= %s ORDER BY rev DESC LIMIT 1'.format(**tables)
        self.ALL_HISTORY_SQL = 'SELECT title, rev, ts, author, comment FROM {history_table} ORDER BY ts DESC'.format(**tables)
        self.SAVE_CHUNK_SQL = 'INSERT INTO {chunk_table} (title, rev, chunk) VALUES (%s, %s, %s) RETURNING id'.format(**tables)
        self.GET_CHUNKS_SQL = 'SELECT id, chunk FROM {chunk_table} WHERE title = %s and rev = %s ORDER BY id'.format(**tables)
        self.DELETE_PAGE_SQL = 'DELETE FROM {page_table} WHERE title = %s'.format(**tables)
    
    def reopen(self):
        """Close and reopen the repo, to make sure we are up to date."""
        pass

    def __contains__(self, title):
        with self.cursor() as c:
            c.execute(self.CHECK_TITLE_SQL, (title,))
            return bool(c.rowcount)

    def __iter__(self):
        return self.all_pages()
    
    def inc_counter(self, cursor, counter='reporev'):
        cursor.execute('UPDATE counters SET v = v+1 WHERE k = %s RETURNING NOTHING', (counter,))

    def get_counter(self, counter='reporev'):
        count = self.execute('SELECT v from counters where k = %s', (counter,), retone=True)
        if count:
            return count[0]
        else:
            return 0
    
    def set_counter(self, counter, val):
        self.execute('UPSERT INTO counters (v, k) VALUES (%s, %s)', (val, counter))

    def save_data(self, title, data, author=None, comment=None, parent_rev=None, ts=None):
        """Save a new revision of the page. If the data is None, deletes it."""
        _ = self._
        user = (author or _(u'anon')).encode('utf-8')
        text = (comment or _(u'comment')).encode('utf-8')
        
        if data is None:
            if title not in self:
                raise error.ForbiddenErr()
            else:
                return self.delete_page(title, user, text)
        # else:
        #     if other is not None:
        #         try:
        #             data = self._merge(repo_file, parent, other, data)
        #         except ValueError:
        #             text = _(u'failed merge of edit conflict').encode('utf-8')
        with self.cursor() as c:
            ts = ts or time.time()
            ts = psycopg2.TimestampFromTicks(ts)
            if len(data) > 1024*1024:
                # must save chunks
                c.execute(self.SAVE_HISTORY_SQL, (title, ts, user, text, None, title))
                rev, ts = c.fetchone()
                
                csize = 1024*1024
                while data:
                    chunk = psycopg2.Binary(data[:csize])
                    c.execute(self.SAVE_CHUNK_SQL, (title, rev, chunk))
                    data = data[csize:]
                data = None
            else:
                data = psycopg2.Binary(data)
                c.execute(self.SAVE_HISTORY_SQL, (title, ts, user, text, data, title))
                rev, ts = c.fetchone()
            c.execute(self.SAVE_PAGE_SQL, (title, rev, ts, user, text))
            self.inc_counter(c)

    def delete_page(self, title, author, comment, ts=None):
        with self.cursor() as c:
            c.execute(self.CHECK_TITLE_SQL, (title,))
            if c.rowcount:            
                # record the history
                ts = psycopg2.TimestampFromTicks(ts or time.time())
                c.execute(self.SAVE_HISTORY_SQL, (title, ts, author, comment, None, title))
                # delete the reference
                c.execute(self.DELETE_PAGE_SQL, (title,))
                self.inc_counter(c)
            else:
                raise error.ForbiddenErr()

    def save_text(self, title, text, author=u'', comment=u'', parent=None):
        """Save text as specified page, encoded to charset."""

        data = text.encode(self.charset)
        if self.unix_eol:
            data = data.replace('\r\n', '\n')
        self.save_data(title, data, author, comment, parent)

    def page_text(self, title):
        """Read unicode text of a page."""
        data = self.page_data(title)
        text = unicode(data, self.charset, 'replace')
        return text

    def open_page(self, title):
        """Open the page and return a file-like object with its contents."""
        return io.BytesIO(self.page_data(title))
    
    def _get_chunks(self, title, rev, c):
        data = b''
        c.execute(self.GET_CHUNKS_SQL, (title, rev))
        for cid, chunk in c:
            data += bytes(chunk)
        return data

    def page_data(self, title):
        with self.cursor() as c:
            c.execute(self.GET_PAGE_SQL, (title,))
            row = c.fetchone()
            # import pdb;pdb.set_trace()
            if row:
                data = row[5]
                if data is None:
                    # need to combine chunks
                    data = self._get_chunks(title, row[1], c)
                else:
                    data = bytes(data)
                return data
        raise error.NotFoundErr()

    def page_meta(self, title):
        """Get page's revision, date, last editor and his edit comment."""
        row = self.execute(self.GET_PAGE_META_SQL, (title,), retone=True)
        if row:
            return row
        raise error.NotFoundErr()

    def repo_revision(self):
        """Give the latest revision of the repository."""
        return self.get_counter('reporev')

    def page_history(self, title):
        """Iterate over the page's history."""
        with self.cursor() as c:
            c.execute(self.GET_HISTORY_SQL, (title,))
            for rev, ts, author, comment in c:
                yield rev, ts, author, comment

    def page_revision(self, title, rev):
        """Get binary content of the specified revision of the page."""
        with self.cursor() as c:
            c.execute(self.GET_REV_SQL, (title, rev))
            row = c.fetchone()
            if row:
                data = row[0]
                if data is None:
                    data = self._get_chunks(title, rev, c)
                else:
                    data = bytes(data)
                return data
            else:
                c.execute(self.GET_LASTREV_SQL, (title, rev))
                row = c.fetchone()
                if row:
                    return bytes(row[0])
                else:
                    # return b''
                    raise error.NotFoundErr()

    def revision_text(self, title, rev):
        """Get unicode text of the specified revision of the page."""

        data = self.page_revision(title, rev)
        text = unicode(data, self.charset, 'replace')
        return text

    def history(self):
        """Iterate over the history of entire wiki."""
        with self.cursor() as c:
            c.execute(self.ALL_HISTORY_SQL)
            for row in c:
                yield row

    def all_pages(self):
        """Iterate over the titles of all pages in the wiki."""
        with self.cursor() as c:
            c.execute('SELECT title from {page_table}'.format(page_table=self.page_table))
            for title in c:
                yield title[0]

    def changed_since(self, rev):
        """
        Return all pages that changed since specified repository revision.
        """
        with self.cursor() as c:
            c.execute('SELECT title FROM {page_table} WHERE rev > %s'.format(page_table=self.page_table), (rev,))
            for title in c:
                yield title[0]


