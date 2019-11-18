# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License") version 1.1!
# You may not use this file except in compliance with the License.
#
# See LICENSE.txt included in this distribution for the specific
# language governing permissions and limitations under the License.
#
# Copyright 2019 Jens Elkner (jel+acme-src@cs.ovgu.de)
"""Simple ACME challenge response HTTP Server.

Usage: AcmeHTTPServer [response_dir [prefix [port]]]

response_dir .. the directory, which contains the files for challenge response
                requests. This server serves only files in this directory.
                After each request answer the server checks, whether this
                directory contains the file 'sacme.exit'. If so, it terminates.
                If not given, the current working directory is used instead.
prefix       .. The ACME server's URL path prefix. The default is
                '/.well-known/acme-challenge', which is correct for Let's
                encrypt servers, possibly not for other ACME implementations.
port         .. The port to use to listen for ACME challenge response requests.
                Default: 80

Logs each response as "clientIP method URLpath HTTPstatus" to stdout.
"""

__version__ = "1.0"
__all__ = ["AcmeHTTPRequestHandler"]

import os
import posixpath
import sys
import shutil
from six.moves import urllib
from six.moves import BaseHTTPServer
from six.moves import StringIO

PIDPATH=""
class AcmeHTTPRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    uname = os.uname()
    server_version = ( 'acme-ksh/' + __version__
        + ' (' +  uname[0] + ' ' + uname[2] + ' ' + uname[4] + ')' )
    prefix = '/.well-known/acme-challenge'

    def version_string(self):
        return self.server_version;

    def log_error(self, format, *args):
        """ Do nothing on maleformed requests """

    def log_request(self, code='-', size='-'):
        p = self.path if hasattr(self, 'path') else '-'
        m = self.command if hasattr(self, 'command') else '-'
        sys.stdout.write('%s %s %s %s\n' % (self.client_address[0], m, p, str(code)))
        sys.stdout.flush()

    def do_GET(self):
        rpath = urllib.parse.unquote(self.path)
        if posixpath.dirname(rpath) != self.prefix:
            self.send_error(404, 'File not found')
            return
        f = None
        try:
            f = open(posixpath.basename(rpath), 'rb')
            fs = os.fstat(f.fileno())
        except IOError:
            self.send_error(404, 'File not found')
            return
        try:
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.send_header('Content-Length', str(fs[6]))
            self.send_header("Last-Modified", self.date_time_string(fs.st_mtime))
            self.end_headers()
            shutil.copyfileobj(f, self.wfile)
        except:
            return
        finally:
            if f:
                f.close()

def keep_running():
    fp = None
    try:
        fp = open('../sacme.exit')
    except:
        return True
    finally:
        if fp:
            fp.close()
    if PIDPATH and posixpath.exists(PIDPATH):
        return True

    return False

def doMain(HandlerClass = AcmeHTTPRequestHandler,
         ServerClass = BaseHTTPServer.HTTPServer):
    if sys.argv[1:]:
    	os.chdir(sys.argv[1])
    if sys.argv[2:]:
        HandlerClass.prefix = sys.argv[2]
    server_address = ('', int(sys.argv[3]) if sys.argv[3:] else 80)
    PIDPATH=posixpath.join('/proc', str(os.getppid()))

    httpd = ServerClass(server_address, HandlerClass)
    while keep_running():
        httpd.handle_request()

if __name__ == '__main__':
    doMain()
