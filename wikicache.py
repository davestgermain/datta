import hatta
import werkzeug
import time
import datetime
import cPickle
import os, os.path
import math
from hashlib import md5
import psycopg2
from werkzeug.contrib.fixers import ProxyFix

OLD_DATE = datetime.datetime(2018, 1, 1, 0, 0, 0)

# because the hatta WikiResponse deletes stuff it shouldn't
class CachedWikiResponse(werkzeug.BaseResponse, werkzeug.ETagResponseMixin,
                   werkzeug.CommonResponseDescriptorsMixin):
    def make_conditional(self, request):
        # default pages have an etag that ends with -1
        # since these are static files, add an old modified date
        if not self.last_modified:
            if self.get_etag()[0].endswith('/-1'):
                self.last_modified = OLD_DATE
        return super(CachedWikiResponse, self).make_conditional(request)


def response(request, title, content, etag='', mime='text/html',
             rev=None, size=None):
    """Create a hatta.request.WikiResponse for a page."""
    # copied from hatta.response
    response = CachedWikiResponse(content, mimetype=mime)
    if rev is None:
        rev, date, author, comment = request.wiki.storage.page_meta(title)
        response.set_etag(u'%s/%s/%d-%s' % (etag,
                                            werkzeug.url_quote(title),
                                            rev, date.isoformat()))
        # add a modified date for better conditional requests
        response.last_modified = date
    else:
        response.set_etag(u'%s/%s/%s' % (etag, werkzeug.url_quote(title),
                                         rev))
    if size:
        response.content_length = size
    response.make_conditional(request)
    return response

hatta.response.WikiResponse = CachedWikiResponse
hatta.response.response = response

class CacheManager(object):
    def __init__(self, wiki):
        self.wiki = wiki
        self._stats = {'h': 0, 'm': 0}
        self._setup()
    
    def _setup(self):
        pass

    def __getitem__(self, url):
        pass
    
    def __setitem__(self, url, response):
        pass
    
    def __delitem__(self, url):
        pass
    
    def clear(self):
        pass

    def stats(self):
        hits, misses = self._stats['h'], self._stats['m']
        if hits or misses:
            ratio = (float(hits) / (hits + misses)) * 100
        else:
            ratio = 0
        return hits, misses, ratio


class FSCacheManager(CacheManager):
    def _setup(self):
        self.page_cache_path = os.path.join(self.wiki.cache, 'rendered')
        if not os.path.isdir(self.page_cache_path):
            os.makedirs(self.page_cache_path)

    def url_to_pagecache(self, url):
        return os.path.join(self.page_cache_path, md5(url).hexdigest())
    
    def __getitem__(self, url):
        path = self.url_to_pagecache(url)
        if os.path.exists(path):
            try:
                with open(path) as fp:
                    resp, exp = cPickle.load(fp)
                if exp >= time.time():
                    self._stats['h'] += 1
                    return resp
                else:
                    resp = None
                    os.unlink(path)
            except OSError:
                pass
        self._stats['m'] += 1
    
    def __setitem__(self, url, val):
        response, exp = val
        path = self.url_to_pagecache(url)
        try:
            with open(path, 'wb') as fp:
                cPickle.dump((response, exp), fp)
        except OSError:
            import traceback
            traceback.print_exc()
    
    def __delitem__(self, url):
        try:
            os.unlink(self.url_to_pagecache(url))
        except OSError:
            pass
            
    def clear(self):
        for f in os.listdir(self.page_cache_path):
            try:
                os.unlink(os.path.join(self.page_cache_path, f))
            except OSError:
                pass


class DBCacheManager(CacheManager):
    def _setup(self):
        self.fs = self.wiki.storage.fs
        self._prefix = os.path.join('/.cache', self.wiki.storage._root.replace('/', '')) + '/'
        self.fs.set_perm(self._prefix, 'cache', ['r', 'w', 'd'])
    
    def _path(self, url):
        return os.path.join(self._prefix, url[1:])

    def __getitem__(self, url):
        path = self._path(url)
        try:
            with self.fs.open(path, mode='r', owner='cache') as fp:
                exp = fp.meta['exp']
                if exp >= time.time():
                    resp = cPickle.load(fp)
                    self._stats['h'] += 1
                    return resp
                else:
                    self.fs.delete(path, owner='cache', include_history=True)
        except Exception:
            pass
        self._stats['m'] += 1

    def __setitem__(self, url, val):
        response, exp = val
        path = self._path(url)
        with self.fs.open(path, mode='w', owner='cache') as fp:
            fp.meta['exp'] = exp
            cPickle.dump(response, fp)
    
    def __delitem__(self, url):
        self.fs.delete(self._path(url), owner='cache', include_history=True)
    
    def clear(self, url):
        for i in self.fs.listdir('/+cache/'):
            self.fs.delete(i.path, include_history=True)


class CachedWiki(hatta.Wiki):
    def __init__(self, config, **kwargs):
        hatta.Wiki.__init__(self, config, **kwargs)
        cmanager = config.get('cache_manager')
        if cmanager == 'fs':
            self.cache_manager = FSCacheManager(self)
        elif cmanager == 'db':
            self.cache_manager = DBCacheManager(self)
        else:
            self.cache_manager = None
        self._app = super(CachedWiki, self).application

    @werkzeug.responder
    def application(self, environ, start_response):
        do_cache = False
        purge_cache = False
        if self.cache_manager:
            method = environ['REQUEST_METHOD']
            path = environ['PATH_INFO']
            if method in ('GET', 'HEAD') and not path.startswith('/+'):
                if not environ['QUERY_STRING']:
                    do_cache = path
            elif method == 'POST' and path.startswith(('/+edit/', '/+undo/')):
                purge_cache = path[6:]
            elif path.startswith('/+cache/'):
                op = path.split('/')[2]
                info = getattr(self, 'cache_' + op)()
                resp = CachedWikiResponse(response=info, status=200)
                return resp

        if do_cache:
            resp = self.get_cached_page(do_cache, environ)
        elif purge_cache:
            resp = self.purge_cached_page(purge_cache, environ)
        else:
            resp = self.get_uncached_page(environ)
        return resp
    
    def get_uncached_page(self, environ):
        # copied from parent class
        adapter = self.url_map.bind_to_environ(environ)
        request = hatta.request.WikiRequest(self, adapter, environ)
        try:
            endpoint, values = adapter.match()
            view = self.views[endpoint]
            resp = view(request, **values)
        except werkzeug.exceptions.HTTPException as err:
            resp = err
        return resp
    
    def get_cached_page(self, url, environ):
        resp = self.cache_manager[url]
        if not resp:
            resp = self.get_uncached_page(environ)
            if resp.status.startswith('200'):
                # only cache complete responses
                resp.freeze()
                try:
                    del resp.headers['Date']
                except KeyError:
                    pass

                # exp = (math.sqrt(resp.content_length) * 7200)
                # just cache for 30 days
                exp = 86400 * 30
                exp += time.time()
                self.cache_manager[url] = (resp, exp)
        resp.make_conditional(environ)
        return resp

    def purge_cached_page(self, url, environ):
        resp = self.get_uncached_page(environ)
        if resp.status.startswith('303'):
            if url == '/Menu':
                # must clear the whole cache!
                self.cache_clear()
            else:
                del self.cache_manager[url]
        return resp
    
    def cache_clear(self):
        for st in self.cache_stats():
            yield st
        self.cache_manager.clear()

    def cache_stats(self):
        hits, misses, ratio = self.cache_manager.stats()
        yield 'hits: %d\nmisses: %d\nratio: %.1f%%\n\n' % (hits, misses, ratio)

