from datta.fs.cas.client import SyncRemoteManager
import os.path, os, glob
import sys
import argparse



def sync_one(from_fp, to_fp, encryption_key=None):
    st = os.stat(from_fp.fileno())
    if to_fp.created and abs(st.st_mtime - to_fp.created.timestamp()) < .25:
        raise Exception('%s not modified' % to_fp.path)
    to_fp.created = st.st_ctime
    to_fp.modified = st.st_mtime
    to_fp.do_hash()
    if encryption_key:
        to_fp.set_encryption(password)
    while 1:
        chunk = from_fp.read(65536)
        if not chunk:
            break
        to_fp.write(chunk)


def sync_dir(client, local_dir, remote_dir, encryption_key=None):
    root = client.opendir(remote_dir, encryption_key=encryption_key)
    if os.path.isfile(local_dir):
        dirname, fname = os.path.split(local_dir)
        d = root.chdir(dirname)
        try:
            with open(local_dir, 'rb') as ofp, d.open(fname, 'w') as tofp:
                sync_one(ofp, tofp, encryption_key)
        except Exception as e:
            print(e)
    else:
        root = root.chdir(local_dir, auto_save=False)
        for dirpath, dirnames, filenames in os.walk(local_dir):
            curdir = dirpath.replace(local_dir, '', 1)
            if curdir:
                d = root.chdir(curdir, auto_save=False)
            else:
                d = root
            for name in filenames:
                p = os.path.join(dirpath, name)
                try:
                    with open(p, 'rb') as ofp, d.open(name, 'w') as tofp:
                        sync_one(ofp, tofp, encryption_key)
                except Exception as e:
                    print(e)
                    continue
                print(p)
            if root.current_dir != d.current_dir:
                d.save()
    root.save()


def main():
    parser = argparse.ArgumentParser(prog='datta.fs.sync', description='sync to a remote block server')
    parser.add_argument('-a', default='127.0.0.1:10811', dest='addr', help='address of server')
    parser.add_argument('-f', dest='save_file', help='save file', default=None)
    parser.add_argument('-e', dest='encryption_key', help='encryption key', default=None)
    parser.add_argument('-l', dest='list_file', help='list save file', default=False, action='store_true')
    parser.add_argument('local_path', help='local path')
    parser.add_argument('remote_path', help='remote path')

    args = parser.parse_args()

    client = SyncRemoteManager(addr=tuple(args.addr.split(':')), save_file=args.save_file)
    with client:
        if args.list_file:
            d = client.opendir(args.remote_path)
            for info in d.listdir(walk=True):
                print(info.path, info.rev)
        else:
            sync_dir(client, args.local_path, args.remote_path, encryption_key=args.encryption_key)
            client.save()


if __name__ == '__main__':
    sys.exit(main())

