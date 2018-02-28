import psycopg2
from contextlib import contextmanager


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
        self._dbname = parsed['dbname']
        self.init_db()
    
    @property
    def conn(self):
        try:
            return BaseDB.CONNECTIONS[self._dbname]
        except KeyError:
            conn = BaseDB.CONNECTIONS[self._dbname] = psycopg2.connect(self.dsn)
            return conn
    
    @contextmanager
    def cursor(self):
        try:
            conn = self.conn
            cursor = conn.cursor()
            yield cursor
            conn.commit()
        except:
            conn.rollback()
            raise
        finally:
            cursor.close()

    def init_db(self):
        if self.CREATE_SQL:
            self.execute(self.CREATE_SQL.format(**self.CREATE_PARS))

    def execute(self, sql, pars=None, retone=False):
        with self.cursor() as c:
            c.execute(sql, pars)
            if retone:
                r = c.fetchone()
                return r

