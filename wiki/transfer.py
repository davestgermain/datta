from . import dbstorage, dbsearch
import hatta.storage
import wikicache
import hatta
import sys
import time
import datetime
import six



mstore = hatta.storage.WikiStorage(sys.argv[1])
# dbstore = dbstorage.WikiStorage('false-dilemma', repo_path='cockroachdb://root@localhost:26257/wiki?sslcert=%2FUsers%2Fdcs%2F.cockroach-certs%2Fclient.root.crt&sslkey=%2FUsers%2Fdcs%2F.cockroach-certs%2Fclient.root.key&sslmode=verify-full&sslrootcert=%2FUsers%2Fdcs%2F.cockroach-certs%2Fca.crt')
dbstore = dbstorage.WikiStorage('false-dilemma', repo_path='lmdb:///Users/dcs/lmdbfs/')

history = list(mstore.history())
history.reverse()
# tz = datetime.timezone(datetime.timedelta(hours=0))
class utc(datetime.tzinfo):
    def utcoffset(self, x):
        return None

for title, rev, dt, author, comment in history:
    content = mstore.page_revision(title, rev)
    ts = dt.replace(tzinfo=utc())
    if rev == -1:
        six.print_('\tDELETE')
        dbstore.delete_page(title, author, comment, ts=ts)
    else:
        dbstore.save_data(title, content, author=author, comment=comment, ts=ts)
    six.print_(title, rev)

wiki = wikicache.CachedWiki(hatta.WikiConfig())
wiki.storage = dbstore
wiki.index = dbsearch.WikiDBSearch('/tmp/wiki/false-dilemma/', 'en', dbstore)
wiki.index.update(wiki)


