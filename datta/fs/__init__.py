import importlib
import os
import six
from .base import Perm
from urllib.parse import urlsplit
try:
    from .base import FileNotFoundError
except ImportError:
    FileNotFoundError = FileNotFoundError
    PermissionError = PermissionError


MANAGERS = {}

def get_manager(dsn=None, debug=False, **kwargs):
    if dsn is None:
        dsn = os.environ.get('FS_DSN', 'lmdb:///tmp/data/')
    dsn = urlsplit(dsn)
    if dsn not in MANAGERS:
        if dsn.path == 'fdb':
            module = 'datta.fs.fdb_fs'
        elif dsn.scheme == 'lmdb':
            module = 'datta.fs.lmdb_fs'
        else:
            module = 'datta.fs.cdb_fs'
        MANAGERS[dsn] = importlib.import_module(module).FSManager(dsn, debug=debug, **kwargs)
    return MANAGERS[dsn]

dbopen = get_manager
