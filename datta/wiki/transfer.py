from . import dbstorage
import hatta.storage
import sys
import time
import datetime
import six
import json



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
    # print(ts)
    # continue
    if rev == -1:
        six.print_('\tDELETE')
        dbstore.delete_page(title, author, comment, ts=ts)
    else:
        dbstore.save_data(title, content, author=author, comment=comment, ts=ts, new=rev==0)
    six.print_(title, rev)


conf = {u'PAGE_PATH': u'om.paragate.club', u'SITE_NAME': u'false-dilemma'}
with dbstore.fs.open(u'/.config/wiki/localhost:8080', owner=u'root', mode=u'w') as fp:
    fp.write(json.dumps(conf))

dbstore.fs.set_perm(u'/.config/wiki/', u'*', u'r')
