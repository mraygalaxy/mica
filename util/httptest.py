#!/usr/bin/env python

import sys
import BaseHTTPServer
from urlparse import urlparse, parse_qs
from SimpleHTTPServer import SimpleHTTPRequestHandler

body = "it worked"

def my_parse(data) :
    url_parameters = {}
    parsed_data = parse_qs(data) 
    for k, v in parsed_data.iteritems() :
        v = v[0] if (isinstance(v, list) and len(v) == 1) else v
        url_parameters[k] = v
    return url_parameters
class MyHandler( BaseHTTPServer.BaseHTTPRequestHandler):
    def do_POST( self ):
        url = urlparse(self.path)
        parameters = my_parse(url.query)
        path = url.path.replace("/", "")
        print str(path) + ": " + str(parameters)
        length = int(self.headers.getheader('content-length'))
        parameters = my_parse(self.rfile.read(length))
        print str(parameters)
        try:
          self.send_response( 200 )
          self.send_header('Content-type','text/html')
          self.send_header( "Content-length", str(len(body)) )
          self.end_headers()
          self.wfile.write(body)
        except:
          print "Error"

    def do_GET(self):
        if self.path.endswith(".html"):
            #self.path has /index.htm
            f = open(curdir + sep + self.path)
            self.send_response(200)
            self.send_header('Content-type','text/html')
            self.end_headers()
            self.wfile.write("<h1>Device Static Content</h1>")
            self.wfile.write(f.read())
            f.close()
            return

        url = urlparse(self.path)
        parameters = my_parse(url.query)
        path = url.path.replace("/", "")
        print unicode(path) + u": " + str(parameters)

        body = "hello world"
        if path == "foo" :
            body = "bar"

        self.send_response(200, 'OK')
        self.send_header('Content-type', 'html')
        self.end_headers()
        self.wfile.write(u"<html><head><title></title></head><body>" + body + "</body></html>")

HandlerClass = MyHandler 

class TimeoutServer(BaseHTTPServer.HTTPServer):
    def get_request(self):
        result = self.socket.accept()
        result[0].settimeout(10)
        return result

ServerClass  = TimeoutServer 

if sys.argv[1:]:
    port = int(sys.argv[1])
else:
    port = 8080

server_address = ('127.0.0.1', port)

#HandlerClass.protocol_version = Protocol
httpd = ServerClass(server_address, HandlerClass)

sa = httpd.socket.getsockname()
try:
    print "Serving HTTP on", sa[0], "port", sa[1], "..."
    httpd.serve_forever()
except KeyboardInterrupt:
    httpd.socket.close()

