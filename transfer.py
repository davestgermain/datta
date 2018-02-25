import wikidbstore
import dbsearch
import hatta.storage
import sys
import time


mstore = hatta.storage.WikiStorage(sys.argv[1])
dbstore = wikidbstore.WikiStorage('', repo_path='postgresql://root@banzai.local:26257/wiki?application_name=cockroach&sslmode=disable')

history = list(mstore.history())
history.reverse()
for title, rev, dt, author, comment in history:
    content = mstore.page_revision(title, rev)
    ts = time.mktime(dt.timetuple())
    if rev == -1:
        print 'DELETE', 
        dbstore.delete_page(title, author, comment, ts=ts)
    else:
        dbstore.save_data(title, content, author=author, comment=comment, ts=ts)
    print title, rev
    
# dbsearch.WikiDBSearch('', 'en', dbstore).update()

