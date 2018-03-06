import psycopg2
from psycopg2.pool import ThreadedConnectionPool
from contextlib import contextmanager


try:
    from threading import get_ident
except ImportError:
    from threading import current_thread
    def get_ident():
        return current_thread().ident


class ContextConnectionPool(ThreadedConnectionPool):
    """
    Postgresql connection pool that can be used as a context manager
    """
    def __init__(self, *args, **kwargs):
        ThreadedConnectionPool.__init__(self, *args, **kwargs)
        self._conns = {}

    def __enter__(self):
        tid = get_ident()
        conn = self.getconn(tid)
        self._conns[tid] = conn
        return conn

    def __exit__(self, etype, value, traceback):
        tid = get_ident()
        conn = self._conns.pop(tid)
        if not etype:
            conn.commit()
        else:
            conn.rollback()
        self.putconn(conn, key=tid)

    def close(self):
        self.closeall()
        self._conns = {}


class BaseDB(object):
    """
    handles the boilerplate of postgres connections
    """
    CREATE_SQL = ''
    CREATE_PARS = {}
    CONNECTIONS = {}

    def __init__(self, dsn):
        parsed = psycopg2.extensions.parse_dsn(dsn)
        self.dsn = dsn
        self._pool = ContextConnectionPool(1, 4, self.dsn)
        self._dbname = parsed['dbname']
        self.init_db()
    
    @property
    def conn(self):
        tid = get_ident()
        # conn = self._pool.getconn(tid)
        
        try:
            conn = BaseDB.CONNECTIONS[tid, self._dbname]
        except KeyError:
            conn = BaseDB.CONNECTIONS[tid, self._dbname] = psycopg2.connect(self.dsn)
        return conn
    
    @contextmanager
    def cursor(self):
        cursor = conn = None
        try:
            # tid = get_ident()
            conn = self.conn
            cursor = conn.cursor()
            yield cursor
            conn.commit()
        except:
            if conn and not conn.closed:
                conn.rollback()
            raise
        finally:
            if cursor is not None:
                cursor.close()
            # if conn:
            #     print('putting conn', tid)
            #     try:
            #         self._pool.putconn(conn, key=tid)
            #     except:
            #         import traceback;traceback.print_exc()

    def init_db(self):
        if self.CREATE_SQL:
            self.execute(self.CREATE_SQL.format(**self.CREATE_PARS))

    def execute(self, sql, pars=None, retone=False, cursor=None):
        if cursor:
            cursor.execute(sql, pars)
            if retone:
                r = cursor.fetchone()
                return r
        else:
            with self.cursor() as cursor:
                cursor.execute(sql, pars)
                if retone:
                    r = cursor.fetchone()
                    return r

