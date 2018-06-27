#!/usr/bin/env python
import argparse
import six
import sys
import os.path
import os
from pprint import pprint
from . import get_manager, Perm

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

    pipe_parser = subparsers.add_parser('pipe', help='pipe STDIN to a file')
    # pipe_parser.add_argument('-v', dest='version', type=int, help='version to open', default=None)
    pipe_parser.add_argument('path', help='path')
    
    cp_parser = subparsers.add_parser('cp', help='copy a file')
    cp_parser.add_argument('-r', action='store_true', default=False, dest='recurse', help='recurse')
    cp_parser.add_argument('frompath', help='path')
    cp_parser.add_argument('topath', help='path')
    
    rm_parser = subparsers.add_parser('rm', help='delete a file')
    rm_parser.add_argument('-r', action='store_true', default=False, dest='recurse', help='recurse')
    rm_parser.add_argument('-f', action='store_true', default=False, dest='history', help='include history')
    rm_parser.add_argument('path', help='path')

    mv_parser = subparsers.add_parser('mv', help='move a file')
    # mv_parser.add_argument('-r', action='store_true', default=False, dest='recurse', help='recurse')
    mv_parser.add_argument('frompath', help='from path')
    mv_parser.add_argument('topath', help='to path')

    log_parser = subparsers.add_parser('log', help='show history of file')
    # log_parser.add_argument('-r', action='store_true', default=False, dest='recurse', help='recurse')
    log_parser.add_argument('path', help='path')

    shell_parser = subparsers.add_parser('shell', help='start shell')

    perm_parser = subparsers.add_parser('set_perm', help='set permission')
    perm_parser.add_argument('path', help='path')
    perm_parser.add_argument('-u', dest='owner', help='owner')
    perm_parser.add_argument('-p', dest='perm', help='perm')
    

    
    args = parser.parse_args()
    
    man = get_manager(args.dsn)

    owner = os.getlogin()
    if args.command == 'ls':
        templ = u'{path:64}{length:8} {created:20} {modified:20}'
        kwargs = dict(path='Path', length='Size', created='Created', modified='Modified')
        if args.detail:
            templ += u' {rev:4} {content_type:20} {meta}'
            kwargs.update({'rev': 'Rev', 'meta': 'Meta', 'content_type': 'Content-Type'})
        row = templ.format(**kwargs)
        printed = False
        timeformat = '%Y-%m-%d %H:%M:%S'
        for p in man.listdir(args.path, walk=args.recurse):
            if not printed:
                six.print_(row)
                six.print_('=' * (len(row) +32))
                printed = True
            info = p.to_dict()
            info['created'] = p.created.strftime(timeformat)
            info['modified'] = p.modified.strftime(timeformat)
            info['content_type'] = six.text_type(p.get('content_type', ''))
            # print(p.to_dict())
            row = templ.format(**info)
            six.print_(row)
    elif args.command == 'cat':
        with man.open(args.path, mode=Perm.read, rev=args.version, owner=owner) as fp:
            fn = sys.stdout.fileno()
            if os.isatty(fn):
                try:
                    data = fp.read()
                    six.print_(data.decode('utf8'))
                except UnicodeDecodeError:
                    if fp.content_type == 'application/x-directory':
                        from datta import pack
                        rec = pack.Record.from_bytes(data)
                        pprint(rec.to_dict())
                    else:
                        six.print_('==== BINARY NOT SHOWN ====')
            else:
                while 1:
                    block = fp.read(8192)
                    if not block:
                        break
                    try:
                        os.write(fn, block)
                    except BrokenPipeError:
                        break
                sys.stdout.flush()
    elif args.command == 'pipe':
        fn = sys.stdin.fileno()
        with man.open(args.path, mode=Perm.write, owner=owner) as fp:
            while 1:
                block = os.read(fn, 8192)
                if not block:
                    break
                fp.write(block)
    elif args.command == 'cp':
        if args.recurse:
            return man.copydir(args.frompath, args.topath)
        else:
            frompath, topath = args.frompath, args.topath
            if frompath.startswith('@') and topath.startswith('@'):
                with man.open(frompath[1:], mode=Perm.read, owner=owner) as fp:
                    with man.open(topath[1:], mode=Perm.write, owner=owner) as tp:
                        while 1:
                            block = fp.read(8192)
                            if not block:
                                break
                            tp.write(block)
            elif frompath.startswith('@'):
                # copy from fs to here
                with man.open(frompath[1:], mode=Perm.read, owner=owner) as fp:
                    if topath.endswith('/'):
                        topath = os.path.join(topath, os.path.basename(frompath))
                    with open(topath, mode='wb') as tp:
                        while 1:
                            block = fp.read(8192)
                            if not block:
                                break
                            tp.write(block)
            else:
                if not man.copyfile(args.frompath, args.topath, owner=owner):
                    return -1
    elif args.command == 'rm':
        if args.recurse:
            six.print_(man.rmtree(args.path, include_history=args.history))
        else:
            if not man.delete(args.path, owner=owner, include_history=args.history):
                return -1
    elif args.command == 'mv':
        if not man.rename(args.frompath, args.topath):
            return -1
    elif args.command == 'log':
        row = '{rev:8}\t{length:8}\t{owner:20}\t{created:26}\t{meta}'
        six.print_(row.format(rev='Rev', length='Size', owner='Owner', created='Created', meta='Meta'))
        six.print_('=' * 80)
        for info in man.get_meta_history(args.path):
            idict = info.to_dict()
            if info.path != args.path:
                six.print_('\t', info.path)
            idict['created'] = str(info.created)
            owner = info.owner
            if not isinstance(owner, six.text_type):
                idict['owner'] = owner.decode('utf8')
            if not info.length:
                idict['length'] = 0
            six.print_(row.format(**idict))
    elif args.command == 'shell':
        from IPython import start_ipython
        ns = {
            'fs': man
        }
        return start_ipython(argv=[], user_ns=ns)
    elif args.command == 'set_perm':
        man.set_perm(args.path, args.owner, args.perm)
    else:
        parser.print_help()

if __name__ == '__main__':
    sys.exit(main())

