#!/usr/bin/python
# -*- coding: utf-8 -*-

import datetime
import time
import os, os.path
import six
import mimetypes

from datta.wiki import error
from datta.fs import get_manager, FileNotFoundError, Perm


class StorageError(Exception):
    """Thrown when there are problems with configuration of storage."""


def merge_func(base, other, this):
    """Used for merging edit conflicts."""
    import mercurial.util
    import mercurial.simplemerge

    if (mercurial.util.binary(this) or mercurial.util.binary(base) or
        mercurial.util.binary(other)):
        raise ValueError("can't merge binary data")
    m3 = mercurial.simplemerge.Merge3Text(base, this, other)
    return ''.join(m3.merge_lines(start_marker='<<<<<<< local',
                                  mid_marker='=======',
                                  end_marker='>>>>>>> other',
                                  base_marker=None))


class WikiStorage(object):
    """
    Provides means of storing wiki pages and keeping track of their
    change history, using database repository as the storage method.
    """

    def __init__(self, dsn, charset=None, _=lambda x: x, unix_eol=False,
                 extension=None):
        """

        """

        self._ = _
        self.charset = charset or 'utf-8'
        self.unix_eol = unix_eol
        self.extension = extension
        
        self._lastpage = None
        self._wiki = None
        self._root = None
        self.fs = get_manager(dsn, debug=False)
        self._created_repos = set()
        # self.set_wiki(path.split('/')[-1])

    def set_wiki(self, wikiname='DEFAULT'):
        if wikiname != self._wiki:
            self._wiki = wikiname
            self._root = self._path() + '/'
            if self._root not in self._created_repos:
                self.fs.set_perm(self._root, owner=u'*', perm=['r', 'w', 'd'])
                self.fs.create_repository(self._root)
                self._created_repos.add(self._root)

    def _path(self, path=''):
        path = os.path.normpath(path)
        return os.path.normpath(os.path.join('/wiki', self._wiki, path))

    def __contains__(self, title):
        if title:
            return self._path(title) in self.fs
        else:
            return False

    def __iter__(self):
        return self.all_pages()

    def save_data(self, title, data, author=None, comment=None, parent_rev=None, ts=None):
        """Save a new revision of the page. If the data is None, deletes it."""
        _ = self._
        user = author or _('anon')
        text = comment or _('comment')
        
        if data is None:
            if title not in self:
                raise error.ForbiddenErr()
            else:
                return self.delete_page(title, user, text, ts=ts)
        # else:
        #     if other is not None:
        #         try:
        #             data = self._merge(repo_file, parent, other, data)
        #         except ValueError:
        #             text = _(u'failed merge of edit conflict').encode('utf-8')

        with self.open_page(title, mode=Perm.write, owner=user) as fp:
            fp.owner = user
            fp.meta[u'comment'] = text
            fp.content_type = six.text_type(mimetypes.guess_type(title)[0] or u'text/plain')
            if parent_rev:
                fp.meta[u'parent'] = parent_rev
            if ts:
                fp.created = ts
            fp.write(data)

    def delete_page(self, title, author, comment, ts=None):
        self.fs.delete(self._path(title), owner=author, force_timestamp=ts)

    def save_text(self, title, text, author='', comment='', parent=None):
        """Save text as specified page, encoded to charset."""

        data = text.encode(self.charset)
        if self.unix_eol:
            data = data.replace(b'\r\n', b'\n')
        self.save_data(title, data, author, comment, parent)

    def page_text(self, title):
        """Read unicode text of a page."""
        data = self.page_data(title)
        text = six.text_type(data, self.charset, 'replace')
        return text

    def open_page(self, title, mode=Perm.read, rev=None, owner='*', meta_only=False):
        """Open the page and return a file-like object with its contents."""
        path = self._path(title)
        if meta_only and self._lastpage and self._lastpage.path == path and rev is None:
            self._lastpage.seek(0)
            fp = self._lastpage
        else:
            try:
                fp = self.fs.open(path, owner=owner, mode=mode, rev=rev)
                if mode == Perm.read:
                    self._lastpage = fp
            except FileNotFoundError:
                if rev is not None:
                    raise
                raise error.NotFoundErr()
        if meta_only:
            return fp.rev, fp.modified.replace(tzinfo=None), fp.owner, fp.meta.get(u'comment', '')
        else:
            return fp

    def page_data(self, title):
        with self.open_page(title) as fp:
            data = fp.read()
            return data

    def page_meta(self, title):
        """Get page's revision, date, last editor and his edit comment."""
        return self.open_page(title, meta_only=True)

    def repo_revision(self):
        """Give the latest revision of the repository."""
        rev = self.fs.repo_rev(self._root)
        return rev

    def page_history(self, title):
        """Iterate over the page's history."""
        for row in self.fs.get_meta_history(self._path(title)):
            yield row.rev, row.created, row.owner, row.meta.get('comment', '')

    def page_revision(self, title, rev):
        """Get binary content of the specified revision of the page."""
        try:
            with self.open_page(title, rev=rev) as fp:
                return fp.read()
        except FileNotFoundError:
            return b''

    def revision_text(self, title, rev):
        """Get unicode text of the specified revision of the page."""

        data = self.page_revision(title, rev)
        try:
            text = six.text_type(data, self.charset)
        except UnicodeDecodeError:
            text = self._('Unable to display')
        return text

    def history(self):
        """Iterate over the history of entire wiki."""
        for info in self.fs.repo_history(self._root):
            owner = info.owner or ''
            if not isinstance(owner, str):
                owner = owner.decode('utf8')
            yield info.path.replace(self._root, '', 1), info.rev, info.created, owner, info.meta.get(u'comment', '')

    def all_pages(self):
        """Iterate over the titles of all pages in the wiki."""
        for info in self.fs.listdir(self._root, walk=True):
            if info.get('content_type') != 'application/x-directory':
                yield info.path.replace(self._root, '', 1)

    def changed_since(self, rev):
        """
        Return all pages that changed since specified repository revision.
        """
        for title in self.fs.repo_changed_files(self._root, since=rev):
            yield title.replace(self._root, '', 1)


