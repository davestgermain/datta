#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import sys

from datta.wiki.wiki import Wiki




def main(wiki=None):
    """Start a standalone WSGI server."""

    if len(sys.argv) > 1:
        dsn = sys.argv[1]
    else:
        sys.exit(1)
    wiki = wiki or Wiki(dsn=dsn)
    
    host, port = (wiki.config.get('interface', '0.0.0.0'),
                  int(wiki.config.get('port', 8080)))

    try:
        wiki.run(
            host=host,
            port=port,
            debug=True)
    except KeyboardInterrupt:
        wiki.stop()

if __name__ == "__main__":
    main()
