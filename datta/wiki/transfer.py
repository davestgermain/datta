from . import dbstorage
import hatta.storage
import sys
import time
import datetime
import six
import json

class utc(datetime.tzinfo):
    def utcoffset(self, x):
        return None


def transfer_wiki(dsn, pages_dir, domain, site_name):

    mstore = hatta.storage.WikiStorage(pages_dir)
    dbstore = dbstorage.WikiStorage(dsn)
    dbstore.set_wiki(domain)

    conf = {u'PAGE_PATH': domain, u'SITE_NAME': site_name}
    with dbstore.fs.open(u'/.config/wiki/%s' % domain, owner=u'root', mode=u'w') as fp:
        fp.write(json.dumps(conf))

    dbstore.fs.set_perm(u'/.config/wiki/', u'*', u'r')

    history = list(mstore.history())
    history.reverse()
    # tz = datetime.timezone(datetime.timedelta(hours=0))

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

if __name__ == '__main__':
    import argparse


    parser = argparse.ArgumentParser(prog='datta.wiki.transfer', description='transfer hatta pages')
    parser.add_argument('-d', default='fdb', dest='dsn', help='DSN for file manager')
    parser.add_argument('-p', dest='page_dir', help='hatta pages', required=True)
    parser.add_argument('-D', dest='domain', help='domain name', type=six.text_type)
    parser.add_argument('-s', dest='site', help='site name', type=six.text_type)
    
    args = parser.parse_args()
    # six.print_(args)
    transfer_wiki(args.dsn, args.page_dir, args.domain, args.site)

