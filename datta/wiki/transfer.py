from . import dbstorage
import hatta.storage
import sys
import time
import datetime
import six



mstore = hatta.storage.WikiStorage(sys.argv[1])
dsn = 'lmdb:///Users/dcs/lmdbfs/'
dsn = 'lmdb:///tmp/wiki/'
dbstore = dbstorage.WikiStorage(dsn)
dbstore.set_wiki('om.paragate.club')

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

# wiki = wikicache.CachedWiki(hatta.WikiConfig())
# wiki.storage = dbstore
# wiki.index = dbsearch.WikiDBSearch('/tmp/wiki/false-dilemma/', 'en', dbstore)
# wiki.index.update(wiki)


