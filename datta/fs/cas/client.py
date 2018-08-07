from . import BaseCASManager, CasDir
import socket
import six

try:
    from nacl.public import PrivateKey, PublicKey, Box
    from nacl.hash import sha256, blake2b
    from nacl.encoding import RawEncoder
    ENCRYPTION = True
except ImportError:
    import warnings; warnings.warn('NaCl not available')
    ENCRYPTION = False



class SyncRemoteManager(BaseCASManager):
    def __init__(self, addr=('127.0.0.1', 10811), save_file=None):
        BaseCASManager.__init__(self)
        self.addr = addr
        self.save_file = save_file or '%s_%s.vac' % self.addr
        self.sock = None
        self.rfile = self.wfile = None
        self._record = None
        self._changed = False
        self.server_box = None
        self.cache = Cache(maxsize=256)

    def load(self, return_file=False):
        try:
            fp = open(self.save_file, 'rb')
            if return_file:
                return fp
            with fp:
                return CasDir.from_bytes(fp.read())
        except FileNotFoundError:
            if return_file:
                return None
            return CasDir.from_dict({})

    def save(self):
        if self._changed:
            rec = self.record
            parent = self.load(return_file=True)
            if parent:
                rec.parent, level = self.writefile(parent, blocksize=4096)
                parent.close()
            val = rec.to_bytes()
            with open(self.save_file, 'wb') as fp:
                fp.write(rec.to_bytes())
            self._changed = False

    @property
    def record(self):
        if self._record is None:
            self._record = self.load()
        return self._record

    @record.setter
    def record(self, rec):
        self._record = rec

    def save_file_data(self, path, meta, buf, cipher=None, subdir=False):
        hist = BaseCASManager.save_file_data(self, path, meta, buf, cipher=cipher)
        if not subdir:
            self.record.files[hist.path] = hist.to_bytes()
            self._changed = True
        return hist

    def open(self, filename, mode=Perm.read, owner=Owner.ALL, rev=None):
        try:
            hist = self.record.get_file(filename)
        except KeyError:
            if mode == Perm.read:
                raise FileNotFoundError(filename)
            else:
                hist = CasHistoryInfo.from_dict({'path': filename})
        hist.history_key = self.record.parent
        return VersionedFile(self, filename, mode=mode, rev=rev, file_info=hist)

    def _negotiate_encryption(self, server_pub_key, server_auth=None):
        six.print_('server public_key: %s' % server_pub_key.hex())
        self.server_box = None
        if blake2b(server_pub_key + b'datta', encoder=RawEncoder) != server_auth:
            raise RuntimeError('Bad Server Auth! %s' % server_auth)
        self.private_key = PrivateKey.generate()
        my_pub_key = bytes(self.private_key.public_key)
        six.print_('client public_key: %s' % my_pub_key.hex())
        auth = blake2b(my_pub_key + b'datta', encoder=RawEncoder)
        self._send(b'N' + my_pub_key + auth)
        resp  = self.rfile.read(2)
        if resp == b'OK':
            self.server_box = Box(self.private_key, PublicKey(server_pub_key))
        else:
            six.print_(resp)
        
    def connect(self):
        self.sock = socket.create_connection(self.addr)
        self.rfile = self.sock.makefile('rb')
        self.wfile = self.sock.makefile('wb')
        line = self.rfile.read(64)
        six.print_('connected to %s:%s' % (self.addr, line.hex()))
        if ENCRYPTION:
            public_key, auth = line[:32], line[32:]
            self._negotiate_encryption(public_key, auth)

    def _decrypt(self, message):
        if self.server_box:
            return self.server_box.decrypt(message)
        else:
            return message

    def readblock(self, key, verify=False):
        block = self.cache.get(key)
        if block is None:
            message = b'R %s\n' % key
            self._send(message)
            resp =  self.rfile.read(4)
            if resp != b'ERRR':
                length = struct.unpack('>I', resp)[0]
                block = self._decrypt(self.rfile.read(length))
                if verify:
                    if self._hash_block(block) != key[1:]:
                        raise Exception('Bad block!')
                self.cache.set(key, block)
            else:
                block = None
        return block

    def writeblock(self, level, block):
        key = struct.pack('>B20s', level, self._hash_block(block))
        if not self.cache.get(key):
            message = b'W %s\n' % struct.pack('>BI', level, len(block))
            message += block
            self._send(message)
            length = struct.unpack('>I', self.rfile.read(4))[0]
            key = self._decrypt(self.rfile.read(length))
            assert len(key) == 21, key
            self.cache.set(key, block)
        return key

    def walkblocks(self, key):
        message = b'T %s\n' % key
        self._send(message)
        while 1:
            resp = self.rfile.read(4)
            if resp == b'\x00\x00\x00\x00':
                break
            if resp != b'ERRR':
                length = struct.unpack('>I', resp)[0]
                block = self._decrypt(self.rfile.read(length))
                yield block
            else:
                yield None
                break

    def missing(self, keys):
        missing = []
        while keys:
            to_check, keys = keys[:10000], keys[10000:]
            message = b'H ' + b''.join(to_check)
            self._send(message)
            while 1:
                resp = self.rfile.read(21)
                if resp != b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00':
                    missing.append(resp)
                else:
                    break
        return missing

    def get_stats(self):
        import json
        message = b'S\n'
        self._send(message)
        return json.loads(self.rfile.readline().decode('utf8'))

    def _send(self, message):
        if not self.sock:
            self.connect()
        if self.server_box:
            message = self.server_box.encrypt(message)
        lm = len(message)
        mess = struct.pack('>I', lm) + message
        self.wfile.write(mess)
        self.wfile.flush()
        
    def close(self):
        if self._record:
            self.save()
        self._send(b'Q\n')
        self.wfile.close()
        self.rfile.close()
        self.sock.close()
        self.sock = None

    def __enter__(self):
        if not self.sock:
            self.connect()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        if exc:
            six.reraise(exc_type, exc, tb)