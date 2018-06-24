from datta import fs
import unittest
import time
import os
import io


# def test_get_default_manager():
#     man = fs.get_manager()
#     assert man.dsn == 'fdb'

class LMDBTests(unittest.TestCase):
    dsn = 'lmdb:///tmp/testfs/'

    def tearDown(self):
        tdir = '/tmp/testfs/'
        for p in os.listdir(tdir):
            p = os.path.join(tdir, p)
            os.unlink(p)

    def setUp(self):
        self.man = fs.get_manager(self.dsn)
        self.man.set_perm('/test', 'test', 'rwd')

    def test_read_missing(self):
        self.assertRaises(FileNotFoundError, self.man.open, '/test/missing/file', mode='r', owner='test')

    def test_create_file(self):
        data = 'test 123'
        fp = self.man.open('/test/create', owner='test', mode='w')
        fp.write(data)
        fp.meta['testing'] = True
        fp.close()
        
        read = self.man.open('/test/create', owner='test', mode='r')
        self.assertEqual(read.rev, 0)
        self.assertEqual(data.encode('utf8'), read.read())
        self.assertTrue(fp.meta['testing'])
        fp.close()
        self.assertTrue(fp.closed)
    
    def test_rename(self):
        fname = '/test/file1'
        toname = '/test/renamed'
        ts = time.time()
        created = self.man.open(fname, owner='test', mode='w')
        created.meta['testing'] = ts
        created.close()
        self.man.rename(fname, toname, owner='test')
        renamed = self.man.open(toname, owner='test', mode='r')
        self.assertEqual(renamed.meta['testing'], ts)
    
    def test_random_read(self):
        fname = '/test/randomread'
        data = os.urandom(100*1024)
        with self.man.open(fname, mode='w', owner='test') as fp:
            fp.write(data)
            fp.meta['testing'] = True
        
        comp = io.BytesIO(data)
        fp = self.man.open(fname, owner='test')
        operations = [
            (1000, 0, 1),
            (1000, 1, 100),
            (67 * 1024, 0, 4),
            (-5, 2, 4),
            (-5, 2, 5),
            (63*1024, 0, 1028),
        ]
        while operations:
            seek, whence, read = operations.pop(0)
            fp.seek(seek, whence)
            comp.seek(seek, whence)
            self.assertEqual(fp.read(read), comp.read(read))

    def test_perms(self):
        self.man.set_acl('/test/public/filename', {})
        self.man.clear_perm('/test/public', '*', 'rwd')
        self.man.set_perm('/test/', 'test', 'r')
        self.assertTrue(self.man.check_perm('/test/', 'test', 'r', raise_exception=False))
        self.assertRaises(fs.PermissionError, self.man.check_perm, '/test/', 'badguy', 'r')
        self.assertTrue(self.man.check_perm('/test/foo', 'test', 'r', raise_exception=False))
        self.man.set_perm('/test/public/', '*', 'r')
        self.assertTrue(self.man.check_perm('/test/public/filename', 'foo', 'r', raise_exception=False))
        self.assertFalse(self.man.check_perm('/test/public/filename', 'foo', 'w', raise_exception=False))
        self.man.set_perm('/test/public/filename', '*', 'w')
        self.assertTrue(self.man.check_perm('/test/public/filename', 'foo', 'w', raise_exception=False))

    def test_kv(self):
        self.man['testkey'] = 1
        self.assertEqual(self.man['testkey'], 1)
        del self.man['testkey']
        self.assertEqual(self.man['testkey'], None)
        self.man['testkey'] = {'complex': True, 'Structure': [1,2,3], 'val': -1.3}
        self.assertEqual(self.man['testkey']['val'], -1.3)
        del self.man['testkey']

    def test_repo(self):
        rdir = '/test/repo/'
        self.man.create_repository(rdir)
        self.assertEqual(self.man.repo_rev(rdir), -1)
        with self.man.open(os.path.join(rdir, 'first'), owner='test', mode='w') as fp:
            fp.write('first file')
        self.assertEqual(self.man.repo_rev(rdir), 0)
        with self.man.open(os.path.join(rdir, 'second'), owner='test', mode='w') as fp:
            fp.write('second file')
        self.assertEqual(self.man.repo_rev(rdir), 1)
        with self.man.open(os.path.join(rdir, 'second'), owner='test', mode='r') as fp:
            self.assertEqual(fp.rev, 1)
        with self.man.open(os.path.join(rdir, 'first'), owner='test', mode='w') as fp:
            fp.write('first file, rev 2')
        self.assertEqual(self.man.repo_rev(rdir), 2)
        self.assertEqual(self.man.get_file_metadata(os.path.join(rdir, 'first'), None).rev, 2)
        self.assertEqual(len(list(self.man.repo_history(rdir))), 3)


# class FDBTests(FsTests):
#     dsn = 'fdb'
#     def tearDown(self):
#         self.man.rmtree('/test/', include_history=True)
#         self.man.clear_perm('/test', 'test', 'rwd')

if __name__ == '__main__':
    unittest.main()
