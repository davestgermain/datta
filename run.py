import hatta
from datta import dbstorage, dbsearch
import wikicache

config = hatta.WikiConfig(
    repo_path='postgresql://root@banzai.local:26257/wiki?application_name=cockroach&sslmode=disable',
    site_name='Gate Gate Paragate Parasamgate Bodhi Svaha',
)
config.set('cache_manager', 'db')

# hatta.Wiki.storage_class = dbstorage.WikiStorage
# hatta.Wiki.index_class = dbsearch.WikiDBSearch
# wikiapp = hatta.Wiki(config).application

wikicache.CachedWiki.storage_class = dbstorage.WikiStorage
wikicache.CachedWiki.index_class = dbsearch.WikiDBSearch
wikiapp = wikicache.CachedWiki(config).application

    
if __name__ == '__main__':
    import werkzeug
    werkzeug.run_simple('', 8282, wikiapp, use_reloader=True)
