from . import Wiki
from . import dbstorage, dbsearch
from copy import copy
import os.path


class MultiWiki(object):
    def __init__(self, config):
        self.baseconfig = config
        self.wikis = {}
        Wiki.storage_class = dbstorage.WikiStorage
        Wiki.index_class = dbsearch.WikiDBSearch

    def add_domain(self, domains, name=''):
        config = copy(self.baseconfig)
        if not isinstance(domains, list):
            domains = [domains]
        config.set('pages_path', domains[0])
        config.set('cache_path', os.path.join(config.get('cache_path'), domains[0]))
        config.set('site_name', name or domains[0])
        wikiapp = Wiki(config).application
        for domain in domains:
            self.wikis[domain] = wikiapp

    def application(self, environ, start_response):
        host = environ['HTTP_HOST'].split(':')[0].replace('.', '_').lower()
        return self.wikis[host](environ, start_response)
