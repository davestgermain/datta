import asyncio
import traceback
import struct
import time
import json
import sys
import os.path
from collections import defaultdict
from datta.fs import dbopen



class BaseBlockServer:
    def __init__(self, dsn, port=10811, host='127.0.0.1'):
        fs = dbopen(dsn).cas
        for k in ('readblock', 'writeblock', 'walkblocks'):
            setattr(self, k, getattr(fs, k))
        self.port = port
        self.host = host
        self.stats = defaultdict(int)
        self.stats['start'] = time.time()

    def get_key(self, line):
        key = line[1:].strip()
        # print('KEY', key)
        is_hex = len(key) == 42
        if is_hex:
            key = bytes.fromhex(key.decode('utf8'))
        return key, is_hex

    def make_response(self, message):
        return struct.pack('>I', len(message)) + message

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
        return [self.make_response(key)]

    def handle_T(self, message):
        key, is_hex = self.get_key(line)
        wrote = False
        for block in self.walkblocks(key):
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
            self.stats['read'] += 1

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
        return b'CAS uptime: %ds\n' % (time.time() - self.stats['start'])

    async def get_response(self, message):
        command = chr(message[0])
        if command in ('', ' ', '\n'):
            return
        return getattr(self, 'handle_%s' % command)(message[1:])

    def _get_ssl(self, cert_path=None):
        if cert_path:
            import ssl
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.set_ciphers('ECDHE+AESGCM')
            ssl_context.load_cert_chain(os.path.join(cert_path, 'cert.pem'), keyfile=os.path.join(cert_path, 'key.pem'))
            return ssl_context


class AsyncioBlockServer(BaseBlockServer):
    def start(self, ssl_certs=None):
        ssl_context = self._get_ssl(ssl_certs)
        if 'PyPy' not in sys.version:            
            try:
                import uvloop
                loop = uvloop.new_event_loop()
            except ImportError:
                loop = asyncio.get_event_loop()
        else:
            loop = asyncio.get_event_loop()
        self.sleep = asyncio.sleep
        coro = asyncio.start_server(self.handle_client, self.host, self.port, loop=loop, ssl=ssl_context)
        server = loop.run_until_complete(coro)
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            pass
        server.close()
        loop.run_until_complete(server.wait_closed())
        loop.close()

    async def handle_client(self, reader, writer):
        writer.write(self.welcome())
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
                response = await self.get_response(message)
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
        # print('Closed')
        self.stats['open-conn'] -= 1

    
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
    import sys
    server = AsyncioBlockServer(sys.argv[1], host='0.0.0.0')
    server.start()

