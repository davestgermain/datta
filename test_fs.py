from datta import fs
import unittest
import time


def test_get_default_manager():
    man = fs.get_manager()
    assert man.dsn == 'fdb'

class FDBTests(unittest.TestCase):
    def setUp(self):
        self.man = fs.get_manager('fdb')
    
    def tearDown(self):
        for data in self.man.listdir('/test/', walk=True):
            self.man.delete(data.path, include_history=True)
    
    def test_read_missing(self):
        self.assertRaises(FileNotFoundError, self.man.open, '/test/missing/file', mode='r')

    def test_create_file(self):
        data = 'test 123'
        fp = self.man.open('/test/create', mode='w')
        fp.write(data)
        fp.meta['testing'] = True
        fp.close()
        
        read = self.man.open('/test/create', mode='r')
        self.assertEquals(read.rev, 0)
        self.assertEquals(data.encode('utf8'), read.read())
        self.assertTrue(fp.meta['testing'])
        fp.close()
        self.assertTrue(fp.closed)
    
    def test_rename(self):
        fname = '/test/file1'
        toname = '/test/renamed'
        ts = time.time()
        created = self.man.open(fname, mode='w')
        created.meta['testing'] = ts
        created.close()
        self.man.rename(fname, toname)
        renamed = self.man.open(toname, mode='r')
        self.assertEquals(renamed.meta['testing'], ts)