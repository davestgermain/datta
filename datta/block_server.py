import asyncio
import traceback
import struct
import time
import json
import sys
import os.path
from collections import defaultdict
from nacl.public import PrivateKey, PublicKey, Box
from nacl.hash import sha256, blake2b
from nacl.encoding import RawEncoder
from datta.fs import dbopen

if 'PyPy' not in sys.version:
    try:
        import uvloop
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    except ImportError:
        pass



class BlockProtocol:
    def __init__(self, cas, debug=False):
        for k in ('readblock', 'writeblock', 'walkblocks'):
            setattr(self, k, getattr(cas, k))
        self.stats = defaultdict(int)
        self.stats['start'] = time.time()
        self.debug = debug
        self.private_key = PrivateKey.generate()
        self.public_key = bytes(self.private_key.public_key)
        self.client_box = None

    def get_key(self, line):
        key = line[1:-1]
        # print('KEY', key)
        is_hex = len(key) == 42
        if is_hex:
            key = bytes.fromhex(key.decode('utf8'))
        return key, is_hex

    def make_response(self, message):
        if self.client_box:
            message = self.client_box.encrypt(message)
        return struct.pack('>I', len(message)) + message

    def handle_N(self, message):
        """
        encryption key negotiation
        """
        pub_key = PublicKey(message[:32])
        auth = message[32:64]
        self.client_box = Box(self.private_key, pub_key)
        if self.debug:
            print('server public_key: %s' % self.public_key.hex())
            print('client public_key: %s' % bytes(pub_key).hex())
        return [b'OK']

    def handle_Q(self, message):
        return [b'BYE\n', None]

    def handle_R(self, message):
        key, is_hex = self.get_key(message)
        block = self.readblock(key)
        if block:
            resp = self.make_response(block)
            if is_hex:
                resp = resp.hex().encode('utf8')
            self.stats['bytes-sent'] += len(resp)
            self.stats['read'] += 1
            if self.debug:
                print('READ %s (%d)' % (key.hex(), len(block)))
            return [resp]
        else:
            # await asyncio.sleep(.5)
            return [b'ERRR']
            self.stats['errors'] += 1

    def handle_W(self, message):
        level, size = struct.unpack('>BI', message[1:6])
        block = message[7:]
        bl = len(block)
        assert bl == size
        key = self.writeblock(level, block)
        self.stats['bytes-recv'] += size
        if self.debug:
            print('WRITE %s (%d)' % (key.hex(), bl))
        return [self.make_response(key)]

    def handle_T(self, message):
        key, is_hex = self.get_key(message)
        wrote = False
        for block in self.walkblocks(key):
            if block:
                resp = self.make_response(block)
                if is_hex:
                    resp = resp.hex().encode('utf8')
                yield resp
                self.stats['bytes-sent'] += len(resp)
                wrote = True
        if not wrote:
            # await self.sleep(.5)
            yield b'ERRR'
            self.stats['errors'] += 1
        else:
            yield b'\x00\x00\x00\x00'
            self.stats['read'] += 1
        if self.debug:
            print('WALK %s (%s)' % (key.hex(), wrote))

    def handle_S(self, message):
        self.stats['uptime'] = time.time() - self.stats['start']
        return [json.dumps(self.stats).encode('utf8'), b'\n']

    def handle_P(self, message):
        return [self.make_response(b'PONG!')]

    def handle_H(self, message):
        keys = (k[0] for k in struct.iter_unpack('21s', message[1:]))
        for key in self.fs.missing(keys):
            print('MISSING', key.hex())
            yield key
        yield b'\x00' * 21

    def welcome(self):
        self.stats['total-conn'] += 1
        self.stats['open-conn'] += 1
        if self.debug:
            print('CONNECT %s' % self.stats['open-conn'])
        auth = blake2b((self.public_key + b'datta'), encoder=RawEncoder)
        return self.public_key + auth

    def close(self):
        self.stats['open-conn'] -= 1

    async def get_response(self, message):
        if self.client_box:
            message = self.client_box.decrypt(message)
        command = chr(message[0])
        if command in ('', ' ', '\n'):
            return
        return getattr(self, 'handle_%s' % command)(message[1:])



class BaseBlockServer:
    def __init__(self, dsn, port=10811, host='127.0.0.1', debug=False):
        self.cas = dbopen(dsn).cas
        self.port = port
        self.host = host
        self.debug = debug


class AsyncioBlockServer(BaseBlockServer):
    def start(self, loop=None, run_loop=True):
        self.sleep = asyncio.sleep
        loop = loop or asyncio.get_event_loop()
        coro = asyncio.start_server(self.handle_client, self.host, self.port, loop=loop)
        if self.debug:
            print('Starting block server on %s:%s' % (self.host, self.port))
        server = loop.run_until_complete(coro)
        if run_loop:
            try:
                loop.run_forever()
            except KeyboardInterrupt:
                pass
            server.close()
            loop.run_until_complete(server.wait_closed())
            loop.close()
        else:
            return server

    async def handle_client(self, reader, writer):
        proto = BlockProtocol(self.cas, debug=self.debug)
        writer.write(proto.welcome())
        unpack = struct.unpack
        running = True
        while running:
            try:
                buf = await reader.readexactly(4)
            except asyncio.streams.IncompleteReadError:
                break
            if not buf:
                break
            try:
                message_size = unpack('>I', buf)[0]
                if message_size > 1048576:
                    raise IOError('too big %d' % message_size)
                message = await reader.readexactly(message_size)
                response = await proto.get_response(message)
                if response is None:
                    continue
                for chunk in response:
                    if chunk is not None:
                        writer.write(chunk)
                    else:
                        running = False
                        break
            except Exception as e:
                traceback.print_exc()
                await asyncio.sleep(5)
                writer.write(str(e).encode('utf8') + b'\n')
                break
            else:
                await writer.drain()
        writer.close()
        proto.close()

    
class TrioBlockServer(BaseBlockServer):
    def start(self, ssl_certs=None):
        ssl_context = self._get_ssl(ssl_certs)
        import trio
        self.sleep = trio.sleep
        trio.run(trio.serve_tcp, self.handle_client, self.port)
        self.fs.close()

    async def handle_client(self, stream):
        try:
            await stream.send_all(self.welcome())
            buf = bytearray()
            unpack = struct.unpack
            to_recv = 4
            message_size = 0
            running = True
            while running:
                buf += await stream.receive_some(to_recv)
                if not buf:
                    break
                elif len(buf) < to_recv:
                    continue
                if not message_size:
                    message_size = unpack('>I', buf)[0]
                    buf = bytearray()
                    if message_size > 1048576:
                        raise IOError('too big %d' % message_size)
                buf += await stream.receive_some(message_size)
                if len(buf) == message_size:
                    response = await self.get_response(buf)
                    if response is None:
                        continue
                    for chunk in response:
                        if chunk is not None:
                            await stream.send_all(chunk)
                        else:
                            running = False
                            break
                    to_recv = 4
                    message_size = 0
                    buf = bytearray()
                else:
                    to_recv = message_size - len(buf)
        except Exception as e:
            traceback.print_exc()
            await self.sleep(5)
        await stream.aclose()
        # print('Closed')
        self.stats['open-conn'] -= 1

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(prog='datta.block_server', description='start the CAS block server')
    parser.add_argument('-d', default='lmdb:///tmp/bad', dest='dsn', help='DSN for file manager')
    parser.add_argument('-t', default=False, dest='trio', help='Use Trio', action='store_true')
    parser.add_argument('--debug', default=False, dest='debug', action='store_true')
    parser.add_argument('address', default='127.0.0.1:10811')
    args = parser.parse_args()
    
    host, port = args.address.split(':')
    port = int(port)
    server = AsyncioBlockServer(args.dsn, host=host, port=port, debug=args.debug)
    server.start()

