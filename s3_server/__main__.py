from . import app
import os
import os.path
import sys
import ssl

debug = os.getenv('DEBUG', '').lower() == 'true'
cert_loc = os.getenv('SSL_CERT', '')
if cert_loc:
    ssl_context = ssl.SSLContext()
    ssl_context.load_cert_chain(os.path.join(cert_loc, 'cert.pem'), keyfile=os.path.join(cert_loc, 'key.pem'))
else:
    ssl_context = None

if 'PyPy' in sys.version:
    import asyncio
    asyncio.set_event_loop_policy(asyncio.DefaultEventLoopPolicy())


try:
    app.run(host="127.0.0.1", port=8484, debug=debug, workers=2, ssl=ssl_context)
except KeyboardInterrupt:
    sys.exit(0)


