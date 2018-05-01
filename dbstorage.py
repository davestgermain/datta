#!/usr/bin/python
# -*- coding: utf-8 -*-

import datetime
import time
import os, os.path
import six


# Note: we have to set these before importing Mercurial
os.environ['HGENCODING'] = 'utf-8'


from hatta import error
from hatta import page
from datta.fs import get_manager, FileNotFoundError


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

    def __init__(self, path, charset=None, _=lambda x: x, unix_eol=False,
                 extension=None, repo_path=None):
        """

        """

        self._ = _
        self.charset = charset or 'utf-8'
        self.unix_eol = unix_eol
        self.extension = extension
        self.fs = get_manager(repo_path, debug=False)
        self._wiki = path.split('/')[-1]
        self._root = self._path() + '/'
        self.fs.set_perm(self._root, owner='*', perm=['r', 'w', 'd'])
        self.fs.create_repository(self._root)
        self.repo_path = repo_path

    def reopen(self):
        """Close and reopen the repo, to make sure we are up to date."""
        pass

    def _path(self, path=''):
        path = os.path.normpath(path)
        return os.path.normpath(os.path.join('/', self._wiki, path))

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
        user = (author or _(u'anon')).encode('utf-8')
        text = (comment or _(u'comment')).encode('utf-8')
        
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

        with self.open_page(title, mode='w', owner=user) as fp:
            fp.owner = user
            fp.meta[u'comment'] = text
            if parent_rev:
                fp.meta[u'parent'] = parent_rev
            if ts:
                fp.created = ts
            fp.write(data)

    def delete_page(self, title, author, comment, ts=None):
        self.fs.delete(self._path(title), owner=author, force_timestamp=ts)

    def save_text(self, title, text, author=u'', comment=u'', parent=None):
        """Save text as specified page, encoded to charset."""

        data = text.encode(self.charset)
        if self.unix_eol:
            data = data.replace('\r\n', '\n')
        self.save_data(title, data, author, comment, parent)

    def page_text(self, title):
        """Read unicode text of a page."""
        data = self.page_data(title)
        text = six.text_type(data, self.charset, 'replace')
        return text

    def open_page(self, title, mode='r', rev=None, owner='*'):
        """Open the page and return a file-like object with its contents."""
        try:
            return self.fs.open(self._path(title), owner=owner, mode=mode, rev=rev)
        except FileNotFoundError:
            if rev is not None:
                raise
            raise error.NotFoundErr()

    def page_data(self, title):
        with self.open_page(title) as fp:
            data = fp.read()
            return data

    def page_meta(self, title):
        """Get page's revision, date, last editor and his edit comment."""
        with self.open_page(title) as fp:
            return fp.rev, fp.modified.replace(tzinfo=None), fp.owner, fp.meta.get(u'comment', '')

    def repo_revision(self):
        """Give the latest revision of the repository."""
        rev = self.fs.repo_rev(self._root)
        return rev

    def page_history(self, title):
        """Iterate over the page's history."""
        for row in self.fs.get_meta_history(self._path(title)):
            yield row.rev, row.created, row.owner, row.meta.get(u'comment', '')

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
            text = unicode(data, self.charset)
        except UnicodeDecodeError:
            text = self._('Unable to display')
        return text

    def history(self):
        """Iterate over the history of entire wiki."""
        for info in self.fs.repo_history(self._root):
            yield info.path.replace(self._root, '', 1), info.rev, info.created, info.owner or '', info.meta.get(u'comment', '')

    def all_pages(self):
        """Iterate over the titles of all pages in the wiki."""
        for info in self.fs.listdir(self._root, walk=True):
            yield info.path.replace(self._root, '', 1)

    def changed_since(self, rev):
        """
        Return all pages that changed since specified repository revision.
        """
        for title in self.fs.repo_changed_files(self._root, since=rev):
            yield title.replace(self._root, '', 1)


