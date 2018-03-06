from datta.wiki import Wiki, WikiConfig
from datta import dbstorage, dbsearch
# import hatta import Wiki, WikiConfig

config = WikiConfig(
    repo_path='postgresql://root@banzai.local:26257/wiki?application_name=cockroach&sslmode=disable',
    site_name='Gate Gate Paragate Parasamgate Bodhi Svaha',
)
# config.set('cache_manager', 'db')

Wiki.storage_class = dbstorage.WikiStorage
Wiki.index_class = dbsearch.WikiDBSearch
wikiapp = Wiki(config).application

# wikicache.CachedWiki.storage_class = dbstorage.WikiStorage
# wikicache.CachedWiki.index_class = dbsearch.WikiDBSearch
# wikiapp = wikicache.CachedWiki(config).application

    
if __name__ == '__main__':
    import werkzeug
    werkzeug.run_simple('', 8282, wikiapp, use_reloader=True)
