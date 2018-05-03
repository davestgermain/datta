#!/usr/bin/env python
import argparse
import six
import sys
import os.path
from . import get_manager

def main():
    parser = argparse.ArgumentParser(prog='datta.fs', description='navigate the filesytem')
    parser.add_argument('-d', default='fdb', dest='dsn', help='DSN for file manager')
    subparsers = parser.add_subparsers(dest='command', help='commands')
    
    ls_parser = subparsers.add_parser('ls', help='list a path')
    ls_parser.add_argument('-r', action='store_true', default=False, dest='recurse', help='recurse')
    ls_parser.add_argument('-l', action='store_true', default=False, dest='detail', help='detailed info')
    ls_parser.add_argument('path', help='path')
    
    cat_parser = subparsers.add_parser('cat', help='cat a file')
    cat_parser.add_argument('-v', dest='version', type=int, help='version to open', default=None)
    cat_parser.add_argument('path', help='path')
    
    cp_parser = subparsers.add_parser('cp', help='copy a file')
    cp_parser.add_argument('-r', action='store_true', default=False, dest='recurse', help='recurse')
    cp_parser.add_argument('frompath', help='path')
    cp_parser.add_argument('topath', help='path')
    
    rm_parser = subparsers.add_parser('rm', help='delete a file')
    rm_parser.add_argument('-r', action='store_true', default=False, dest='recurse', help='recurse')
    rm_parser.add_argument('-f', action='store_true', default=False, dest='history', help='include history')
    rm_parser.add_argument('path', help='path')

    log_parser = subparsers.add_parser('log', help='show history of file')
    # log_parser.add_argument('-r', action='store_true', default=False, dest='recurse', help='recurse')
    log_parser.add_argument('path', help='path')

    
    args = parser.parse_args()
    
    man = get_manager(args.dsn)

    if args.command == 'ls':
        templ = '{path:48}\t{length:8}\t{created:26}\t{modified:26}'
        kwargs = dict(path='Path', length='Size', created='Created', modified='Modified')
        if args.detail:
            templ += '\t{rev:6}\t{meta}'
            kwargs.update({'rev': 'Rev', 'meta': 'Meta'})
        row = templ.format(**kwargs)
        six.print_ed = False
        for p in man.listdir(args.path, walk=args.recurse):
            if not six.print_ed:
                six.print_(row)
                six.print_('=' * (len(row) +32))
                six.print_ed = True
            p['created'] = str(p.created)
            p['modified'] = str(p.modified)
            row = templ.format(**p)
            six.print_(row)
    elif args.command == 'cat':
        with man.open(args.path, mode='r', rev=args.version) as fp:
            fn = sys.stdout.fileno()
            if os.isatty(fn):
                try:
                    six.print_(fp.read().decode('utf8'))
                except UnicodeDecodeError:
                    six.print_('==== BINARY NOT SHOWN ====')
            else:
                while 1:
                    block = fp.read(8192)
                    if not block:
                        break
                    os.write(fn, block)
                sys.stdout.flush()
    elif args.command == 'cp':
        if args.recurse:
            return man.copydir(args.frompath, args.topath)
        else:
            frompath, topath = args.frompath, args.topath
            if frompath.startswith('@') and topath.startswith('@'):
                with man.open(frompath[1:], mode='r') as fp:
                    with man.open(topath[1:], mode='w') as tp:
                        while 1:
                            block = fp.read(8192)
                            if not block:
                                break
                            tp.write(block)
            elif frompath.startswith('@'):
                # copy from fs to here
                with man.open(frompath[1:], mode='r') as fp:
                    if topath.endswith('/'):
                        topath = os.path.join(topath, os.path.basename(frompath))
                    with open(topath, mode='wb') as tp:
                        while 1:
                            block = fp.read(8192)
                            if not block:
                                break
                            tp.write(block)
            else:
                if not man.copyfile(args.frompath, args.topath):
                    return -1
    elif args.command == 'rm':
        if args.recurse:
            six.print_(man.rmtree(args.path, include_history=args.history))
        else:
            if not man.delete(args.path, include_history=args.history):
                return -1
    elif args.command == 'log':
        row = '{rev:8}\t{length:8}\t{owner:20}\t{created:26}\t{meta}'
        six.print_(row.format(rev='Rev', length='Size', owner='Owner', created='Created', meta='Meta'))
        six.print_('=' * 80)
        for info in man.get_meta_history(args.path):
            if info.path != args.path:
                six.print_('\t', info.path)
            info['created'] = str(info['created'])
            owner = info['owner']
            if not isinstance(owner, six.text_type):
                info['owner'] = owner.decode('utf8')
            if 'length' not in info:
                info['length'] = 0
            six.print_(row.format(**info))
    else:
        parser.six.print__help()

if __name__ == '__main__':
    sys.exit(main())

