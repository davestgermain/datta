import dbstorage
import dbsearch
import hatta.storage
import wikicache
import hatta
import sys
import time


mstore = hatta.storage.WikiStorage(sys.argv[1])
dbstore = dbstorage.WikiStorage('false-dilemma', repo_path='cockroachdb://root@banzai.local:26257/wiki?application_name=cockroach&sslmode=disable')

history = list(mstore.history())
history.reverse()
for title, rev, dt, author, comment in history:
    content = mstore.page_revision(title, rev)
    ts = time.mktime(dt.timetuple())
    if rev == -1:
        print '\tDELETE', 
        dbstore.delete_page(title, author, comment, ts=ts)
    else:
        dbstore.save_data(title, content, author=author, comment=comment, ts=ts)
    print title, rev

wiki = wikicache.CachedWiki(hatta.WikiConfig())
wiki.storage = dbstore
# wiki.index = dbsearch.WikiDBSearch('', 'en', dbstore)
wiki.index.update(wiki)


