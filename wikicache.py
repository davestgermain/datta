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
from datta.base import BaseDB

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


class DBCacheManager(CacheManager, BaseDB):
    CREATE_SQL = '''
            CREATE TABLE IF NOT EXISTS pagecache (
                url STRING PRIMARY KEY,
                response BYTES,
                exp INT
            )
            '''
    GET_RESP_SQL = 'SELECT response, exp FROM pagecache WHERE url = %s'
    DEL_RESP_SQL = 'DELETE FROM pagecache WHERE url = %s RETURNING NOTHING'
    SET_RESP_SQL = 'UPSERT INTO pagecache (url, response, exp) VALUES (%s, %s, %s) RETURNING NOTHING'

    def _setup(self):
        BaseDB.__init__(self, self.wiki.storage.dsn)

        self.inc_counter = self.wiki.storage.inc_counter
        self.storage = self.wiki.storage

        if not self.storage.get_counter('cache_hit'):
            self.storage.set_counter('cache_hit', 0)
            self.storage.set_counter('cache_miss', 0)
    
    def __getitem__(self, url):
        with self.cursor() as c:
            c.execute(self.GET_RESP_SQL, (url,))
            r = c.fetchone()
            if r:
                resp, exp = r
                if exp >= time.time():
                    resp = cPickle.loads(bytes(resp))
                    self.inc_counter(c, 'cache_hit')
                    return resp
                else:
                    c.execute(self.DEL_RESP_SQL, (url,))
            self.inc_counter(c, 'cache_miss')

    def __setitem__(self, url, val):
        response, exp = val
        data = cPickle.dumps(response)
        self.execute(self.SET_RESP_SQL, (url, data, int(exp)))
    
    def __delitem__(self, url):
        self.execute(self.DEL_RESP_SQL, (url,))
    
    def clear(self, url):
        self.execute('TRUNCATE pagecache')

    def stats(self):
        hits = self.storage.get_counter('cache_hit')
        misses = self.storage.get_counter('cache_miss')
        if hits or misses:
            ratio = (float(hits) / (hits + misses)) * 100
        else:
            ratio = 0
        return hits, misses, ratio


class CachedWiki(hatta.Wiki):
    def __init__(self, config, **kwargs):
        hatta.Wiki.__init__(self, config, **kwargs)
        cmanager = config.get('cache_manager', 'fs')
        if cmanager == 'fs':
            self.cache_manager = FSCacheManager(self)
        elif cmanager == 'db':
            self.cache_manager = DBCacheManager(self)
        else:
            raise Exception(cmanager)
        self._app = super(CachedWiki, self).application

    @werkzeug.responder
    def application(self, environ, start_response):
        do_cache = False
        purge_cache = False
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

