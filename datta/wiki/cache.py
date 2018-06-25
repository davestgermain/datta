import time
import datetime
import pickle
import os, os.path
import math
from flask import request, current_app



class DBCacheManager(object):
    def __init__(self, wiki):
        self.wiki = wiki
        self._stats = {'h': 0, 'm': 0}
    
    def stats(self):
        hits, misses = self._stats['h'], self._stats['m']
        if hits or misses:
            ratio = (float(hits) / (hits + misses)) * 100
        else:
            ratio = 0
        return hits, misses, ratio

    def initialize(self):
        self.wiki.before_request(cache_request_middleware)
        self.wiki.after_request(cache_response_middleware)
        
        self.fs = self.wiki.storage.fs
        self._prefix = '/.cache/wiki'
        config = self.fs.get_path_config(self._prefix)
        if config.get('versioning') is None:
            config.versioning = False
            self.fs.set_path_config(self._prefix, config)
            self.fs.set_perm(self._prefix, 'cache', 'rwd')
    
    def _path(self, url):
        return os.path.join(self._prefix, url[1:])

    def open(self, url, mode='r'):
        path = self._path(url)
        try:
            return self.fs.open(path, mode=mode, owner='cache')
        except FileNotFoundError:
            return None

    def __getitem__(self, url):
        try:
            with self.open(url, mode='r') as fp:
                exp = fp.meta['exp']
                if exp >= time.time():
                    resp = pickle.loads(fp.read())
                    self._stats['h'] += 1
                    return resp
                else:
                    self.fs.delete(fp.path, owner='cache', include_history=True)
        except Exception:
            pass
        self._stats['m'] += 1

    def __setitem__(self, url, val):
        response, exp = val
        with self.open(url, mode='w') as fp:
            fp.meta['exp'] = exp
            fp.force_rev = 0
            pickle.dump(response, fp, protocol=-1)
    
    def __delitem__(self, url):
        self.fs.delete(self._path(url), owner='cache', include_history=True)
    
    def clear(self, url):
        self.fs.rmtree(self._prefix, include_history=True)


def make_key(url):
    return url.replace('http:/', '').replace('https:/', '')
    
def cache_request_middleware():
    do_cache = False
    purge_cache = False
    method = request.method
    path = request.path
    resp = None
    if method in ('GET', 'HEAD') and not path.startswith('/+'):
        if not request.query_string:
            do_cache = path
    elif method == 'POST' and path.startswith(('/+edit/', '/+undo/')):
        request._purge_cache = make_key(request.url.replace('/+edit', '').replace('/+undo', ''))
    # elif path.startswith('/+cache/'):
    #     op = path.split('/')[2]
    #     info = getattr(self, 'cache_' + op)()
    #     resp = CachedWikiResponse(response=info, status=200)
    #     return resp
    if do_cache:
        key = make_key(request.url)
        resp = current_app.cache[key]
        if not resp:
            request._docache = key
        else:
            resp.make_conditional(request)
            return resp
    # elif purge_cache:
    #     resp = self.purge_cached_page(purge_cache, environ)
    # else:
    #     resp = self.get_uncached_page(environ)
    return resp
    
def cache_response_middleware(resp):
    cache_key = getattr(request, '_docache', None)
    if resp.status_code == 200 and cache_key:
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
        current_app.cache[cache_key] = (resp, exp)
    elif resp.status_code == 303:
        key = getattr(request, '_purge_cache', None)
        if key:
            del current_app.cache[key]
    return resp

#
# def purge_cached_page(self, url, environ):
#     resp = self.get_uncached_page(environ)
#     if resp.status.startswith('303'):
#         if url == '/Menu':
#             # must clear the whole cache!
#             self.cache_clear()
#         else:
#             del self.cache_manager[url]
#     return resp
#
# def cache_clear(self):
#     for st in self.cache_stats():
#         yield st
#     self.cache_manager.clear()
#
# def cache_stats(self):
#     hits, misses, ratio = self.cache_manager.stats()
#     yield 'hits: %d\nmisses: %d\nratio: %.1f%%\n\n' % (hits, misses, ratio)

