import importlib
import os
import six
try:
    from .base import FileNotFoundError
except ImportError:
    FileNotFoundError = FileNotFoundError


MANAGERS = {}

def get_manager(dsn=None, debug=False):
    if dsn is None:
        dsn = os.environ.get('FS_DSN', 'fdb')
    
    if dsn not in MANAGERS:
        if dsn == 'fdb':
            module = 'datta.fs.fdb_fs'
        else:
            module = 'datta.fs.cdb_fs'
        MANAGERS[dsn] = importlib.import_module(module).FSManager(dsn, debug=debug)
    return MANAGERS[dsn]

