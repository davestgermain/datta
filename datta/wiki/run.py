from . import Wiki, WikiConfig
from .multi import MultiWiki
from . import dbstorage, dbsearch
# import hatta import Wiki, WikiConfig

dsn = 'cockroachdb://root@localhost:26257/wiki?sslcert=%2FUsers%2Fdcs%2F.cockroach-certs%2Fclient.root.crt&sslkey=%2FUsers%2Fdcs%2F.cockroach-certs%2Fclient.root.key&sslmode=verify-full&sslrootcert=%2FUsers%2Fdcs%2F.cockroach-certs%2Fca.crt'

dsn = 'lmdb:///Users/dcs/lmdbfs/'

config = WikiConfig(
    repo_path=dsn,
    pages_path='/false-dilemma',
    site_name='Gate Gate Paragate Parasamgate Bodhi Svaha',
    cache_path='/tmp/wiki/false-dilemma/'
)
config2 = WikiConfig(
    repo_path=dsn,
    pages_path='/stgermain',
    site_name='St.Germain',
    cache_path='/tmp/wiki/st.germa.in/'
)

config.set('cache_manager', 'db')

Wiki.storage_class = dbstorage.WikiStorage
Wiki.index_class = dbsearch.WikiDBSearch
wikiapp = Wiki(config).application


    
if __name__ == '__main__':
    import werkzeug
    werkzeug.run_simple('', 8282, wikiapp, use_reloader=False)
