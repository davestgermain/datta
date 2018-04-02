from datta.wiki import Wiki, WikiConfig
from datta import dbstorage, dbsearch
# import hatta import Wiki, WikiConfig

config = WikiConfig(
    repo_path='cockroachdb://root@localhost:26257/wiki?application_name=cockroach&sslmode=disable',
    pages_path='/false-dilemma',
    site_name='Gate Gate Paragate Parasamgate Bodhi Svaha',
)
# config.set('cache_manager', 'db')

Wiki.storage_class = dbstorage.WikiStorage
# Wiki.index_class = dbsearch.WikiDBSearch
wikiapp = Wiki(config).application

# wikicache.CachedWiki.storage_class = dbstorage.WikiStorage
# wikicache.CachedWiki.index_class = dbsearch.WikiDBSearch
# wikiapp = wikicache.CachedWiki(config).application

    
if __name__ == '__main__':
    import werkzeug
    werkzeug.run_simple('', 8282, wikiapp, use_reloader=True)
