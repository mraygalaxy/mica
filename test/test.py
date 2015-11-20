#!/usr/bin/env python
# coding: utf-8

from re import compile as re_compile, IGNORECASE as re_IGNORECASE, sub as re_sub
from os import path as os_path, getuid as os_getuid, urandom as os_urandom, remove as os_remove, makedirs as os_makedirs
from docker import Client
from json import loads as json_loads, dumps as json_dumps
from time import sleep
from urlparse import urlparse, parse_qs
from SimpleHTTPServer import SimpleHTTPRequestHandler
from threading import Thread

import requests
import docker
import socket
import sys
import BaseHTTPServer
import cgi

cwd = re_compile(".*\/").search(os_path.realpath(__file__)).group(0)
sys.path = [cwd, cwd + "../"] + sys.path

from params import parameters, test
from common import generate_oauth_links
from mica import go

class MyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_POST(self) :
        body = "it worked"
        url = urlparse(self.path)
        parameters = parse_qs(url.query)
        path = url.path.replace("/", "")
        print str(path) + ": " + str(parameters)
        ctype, pdict = cgi.parse_header(self.headers.getheader('content-type'))
        postvars = {}
        try:
            if ctype == 'application/x-www-form-urlencoded':
                length = int(self.headers.getheader('content-length'))
                postvars = parse_qs(self.rfile.read(length), keep_blank_values=1)

            self.send_response(200)
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
        parameters = parse_qs(url.query)
        path = url.path.replace("/", "")
        print str(path) + ": " + str(parameters)

        body = "hello world"
        if path == "foo" :
            body = "bar"

        self.send_response(200, 'OK')
        self.send_header('Content-type', 'html')
        self.end_headers()
        self.wfile.write(u"<html><head><title></title></head><body>" + body + "</body></html>")

class TimeoutServer(BaseHTTPServer.HTTPServer):
    def get_request(self):
        result = self.socket.accept()
        result[0].settimeout(10)
        return result

def oauth_responder(httpd_server) :
    sa = httpd_server.socket.getsockname()
    print "Serving HTTP on", sa[0], "port", sa[1], "..."
    httpd_server.serve_forever()

def check_port(hostname, port, protocol = "TCP") :
    try :
        if protocol == "TCP" :
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        elif protocol == "UDP" :
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        sock.connect((hostname, port if port is None else port))
        sock.close()
        return True
    
    except socket.error, msg :
        print "Unable to connect to " + protocol + " port " + str(port) + " on host " + hostname + ": " + str(msg)
        sock.close()
        sock = None
        return False

def cleanup(name) :
    try :
        details = c.inspect_container(name)
        if details["State"]["Running"] :
            print "Stopping: " + name
            c.kill(name)
        print "Removing: " + name
        c.remove_container(name)
    except docker.errors.NotFound, e :
        print "No container to cleanup: " + name

def login(s) :
    print "Logging in..."
    r = s.post("http://localhost/connect", data=dict(human='0', username=test["username"], password=test["password"], remember='on', address='http://localhost:5984', connect='1'))
    assert(r.status_code == 200)
    assert(json_loads(r.text)['success'])

def run_tests() :
    try:
        for url in urls :
            print url["method"] + ": " + url["loc"]
            if url["method"] == "get" :
                r = s.get("http://localhost" + url["loc"])
            elif url["method"] == "post" :
                print "   Post data: " + str(url["data"])
                r = s.post("http://localhost" + url["loc"], data = url["data"])
            elif url["method"] == "login" :
                login(s)
            elif url["method"] == "logout" :
                print "Logging out..."
                r = s.get("http://localhost/disconnect")

            if url["method"] != "login" :
                assert(r.status_code == 200)
                if url["method"] != "logout" and "success" in url :
                    assert(json_loads(r.text)["success"] == url["success"])
    except KeyboardInterrupt:
        print "CTRL-C interrupt"

c = Client(base_url='unix://var/run/docker.sock')
s = requests.Session()

mica_options = dict(
        image = 'micadev7', 
        command = ['/home/mrhines/mica/restart.sh'], 
        name = 'couchdev',
        tty = True,
        ports = [22, 5984, 6984, 7984],
        host_config = c.create_host_config(port_bindings = {
                "22/tcp":   ("0.0.0.0", 2222),
                "5984/tcp": ("0.0.0.0", 5984),
                "6984/tcp": ("0.0.0.0", 6984),
                "7984/tcp": ("0.0.0.0", 7984),
        })
    )

options = [
    dict(
        image = 'micadev7', 
        command = ['/home/mrhines/mica/restart.sh'], 
        name = 'couchdev',
        tty = True,
        ports = [5984, 22, 6984, 7984],
        host_config = c.create_host_config(port_bindings = {
                "22/tcp":   ("0.0.0.0", 2222),
                "5984/tcp": ("0.0.0.0", 5984),
                "6984/tcp": ("0.0.0.0", 6984),
                "7984/tcp": ("0.0.0.0", 7984),
        })
    ),

    dict(
        image = 'jabber4',
        command = ['/home/mrhines/mica/restart.sh'],
        hostname = 'jabber',
        name = 'jabber',
        tty = True,
        ports = [5222, 22, 5280, 5223, 5281],
        host_config = c.create_host_config(port_bindings = {
                "22/tcp":   ("0.0.0.0", 4444),
                "5222/tcp": ("0.0.0.0", 5222),
                "5223/tcp": ("0.0.0.0", 5223),
                "5280/tcp": ("0.0.0.0", 5280),
                "5281/tcp": ("0.0.0.0", 5281),
        })
    ),
]

def wait_for_port_ready(name, hostname, port) : 
    print "Checking " + hostname + ": " + str(port)

    while True :
        if check_port(hostname, port) :
            try :
                r = s.get("http://" + hostname + ":" + str(port))
                print "Container " + name + " ready. Running tests."
                break
            except requests.exceptions.ConnectionError, e :
                print "Container " + name + " not ready: " + str(e) + ". Waiting..."
        else :
            print "Port not open yet. Waiting..."

        sleep(1)

for option in options :
    cleanup(option["name"])
    print "Creating container: " + option["name"]
    details = c.create_container(**option)
    print "Creation complete."
    c.start(option["name"])
    port = option["ports"][0]
    hostname = "localhost"

    wait_for_port_ready(option["name"], hostname, port)

urls = [    
            { "method" : "login", "loc" : "login" },
            { "loc" : "/api?human=0&alien=storylist&tzoffset=18000", "method" : "get", "success" :  True },
            { "loc" : "/api?human=0&alien=read&view=1&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb", "method" : "get", "success" :  True },
            { "loc" : "/api?human=0&alien=read&view=1&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&page=0", "method" : "get", "success" :  True },
            { "loc" : "/api?human=0&alien=read&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&memolist=1&page=0", "method" : "get", "success" :  True },
            { "loc" : "/api?human=0&alien=read&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&memorized=1&nb_unit=8&page=0", "method" : "get", "success" :  True },
            { "loc" : "/api?human=0&alien=read&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&memorized=0&nb_unit=3&page=0", "method" : "get", "success" :  True },
            { "loc" : "/api?human=0&alien=read", "method" : "get", "success" :  True },
            { "loc" : "/api?human=0&alien=read&view=1&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&page=0", "method" : "get", "success" :  True },
            { "loc" : "/api?human=0&alien=read&view=1&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&page=0&image=0", "method" : "get", "success" :  True },
            { "loc" : "/api?human=0&alien=read&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&memolist=1&page=0", "method" : "get", "success" :  True },
            { "loc" : "/api?human=0&alien=instant&source=%E7%82%8E%E7%83%AD&lang=en&source_language=zh-CHS&target_language=en", "method" : "get", "success" :  True },
            { "loc" : "/api?human=0&alien=home&view=1", "method" : "get", "success" :  True },
            { "loc" : "/api?human=0&alien=home&switchmode=text", "method" : "get", "success" :  True },
            { "loc" : "/api?human=0&alien=home&view=1&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&page=0", "method" : "get", "success" :  True },
            { "loc" : "/api?human=0&alien=read&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&reviewlist=1&page=0", "method" : "get", "success" :  True },
            { "loc" : "/api?human=0&alien=home&view=1&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&multiple_select=1&index=1&nb_unit=11&trans_id=9&page=0", "method" : "get", "success" :  True },
            { "loc" : "/api?human=0&alien=home&view=1&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&multiple_select=1&index=1&nb_unit=48&trans_id=42&page=0", "method" : "get", "success" :  True },
            { "loc" : "/api?human=0&alien=home", "method" : "post", "success" :  True, "data" : dict(retranslate = '1', page = '0', uuid = 'b220074e-f1a7-417b-9f83-e63cebea02cb') },
            # Assert that the default has changed and move multiple_select to actual JSON, then retry the request
            { "loc" : "/api?human=0&alien=edit&view=1", "method" : "get", "success" :  True },
            { "loc" : "/api?human=0&alien=edit&view=1&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&page=0", "method" : "get", "success" :  True },
            { "loc" : "/api?human=0&alien=edit&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&editslist=1&page=0", "method" : "get", "success" :  True },
            { "loc" : "/api?human=0&alien=edit", "method" : "post", "success" : True, "data" : dict(oprequest = '[{"operation":"split","uuid":"b220074e-f1a7-417b-9f83-e63cebea02cb","units":1,"failed":false,"chars":"小鸟","pinyin":"xiǎo+niǎo","nbunit":"8","uhash":"0b23c772194ef5a97aa23d5590105665","index":"-1","pagenum":"0","out":""},{"operation":"merge","uuid":"b220074e-f1a7-417b-9f83-e63cebea02cb","units":2,"failed":false,"chars":"跳","pinyin":"tiào","nbunit0":"45","uhash0":"0cdbc17e9ed386e3f3df2b26ed5b5187","index0":"-1","page0":"0","chars0":"跳","pinyin0":"tiào","nbunit1":"46","uhash1":"0cdbc17e9ed386e3f3df2b26ed5b5187","index1":"-1","page1":"0","chars1":"跳","pinyin1":"tiào","out":""}]', uuid = "b220074e-f1a7-417b-9f83-e63cebea02cb") },
           { "loc" : "/api?human=0&alien=edit", "method" : "post", "success" : True, "data" : dict(oprequest = '[{"operation":"split","uuid":"b220074e-f1a7-417b-9f83-e63cebea02cb","units":1,"failed":false,"chars":"山羊","pinyin":"shān+yáng","nbunit":"111","uhash":"fb7335cbba25395d3b9a867ddad630fd","index":"-1","pagenum":"0","out":""}]', uuid = "b220074e-f1a7-417b-9f83-e63cebea02cb") },
           { "loc" : "/api?human=0&alien=read&uuid=b2898b6c-83a8-4aaf-b39b-b6d919160dba&reviewlist=1&page=151", "method" : "get", "success" : True },
           { "loc" : "/api?human=0&alien=home", "method" : "post", "success" : True, "data" : dict(transid0 = 67, index0 = 1, nbunit0 = 75, page0 = 151, transid1 = 74, index1 = 1, nbunit1 = 84, page1 = 151, transid2 = 81, index2 = 1, nbunit2 = 93, page2 = 151, transid3 = 88, index3 = 1, nbunit3 = 102, page3 = 151, transid4 = 105, index4 = 1, nbunit4 = 123, page4 = 151, count = 5, bulkreview = 1) },
           { "loc" : "/api?human=0&alien=read&uuid=b2898b6c-83a8-4aaf-b39b-b6d919160dba&reviewlist=1&page=151", "method" : "get", "success" : True },

           # Switch to split view on sample
           { "loc" : "/api?human=0&alien=read&uuid=b2898b6c-83a8-4aaf-b39b-b6d919160dba&reviewlist=1&page=151", "method" : "get", "success" : True },
           { "loc" : "/api?human=0&alien=home&view=1&uuid=b2898b6c-83a8-4aaf-b39b-b6d919160dba&page=151", "method" : "get", "success" : True },
           { "loc" : "/api?human=0&alien=read&uuid=b2898b6c-83a8-4aaf-b39b-b6d919160dba&reviewlist=1&page=151", "method" : "get", "success" : True },
           { "loc" : "/api?human=0&alien=home&switchmode=both", "method" : "get", "success" : True },
           { "loc" : "/api?human=0&alien=home&view=1&uuid=b2898b6c-83a8-4aaf-b39b-b6d919160dba&page=151&image=0", "method" : "get", "success" : True },

            # Switch to image-only

           { "loc" : "/api?human=0&alien=home&switchmode=images", "method" : "get", "success" : True },
           { "loc" : "/api?human=0&alien=home&view=1&uuid=b2898b6c-83a8-4aaf-b39b-b6d919160dba&page=151&image=0", "method" : "get", "success" : True },
           { "loc" : "/api?human=0&alien=read&uuid=b2898b6c-83a8-4aaf-b39b-b6d919160dba&reviewlist=1&page=151", "method" : "get", "success" : True },

           # Switch back to text-only

#           { "loc" : "/api?human=0&alien=home&view=1&uuid=b2898b6c-83a8-4aaf-b39b-b6d919160dba&page=151", "method" : "get", "success" : True },
#           { "loc" : "/api?human=0&alien=read&uuid=b2898b6c-83a8-4aaf-b39b-b6d919160dba&reviewlist=1&page=151", "method" : "get", "success" : True },
#           { "loc" : "/api?human=0&alien=home&switchmode=text", "method" : "get", "success" : True },

            # Go to page 35
           { "loc" : "/api?human=0&alien=home&view=1&uuid=b2898b6c-83a8-4aaf-b39b-b6d919160dba&page=34", "method" : "get", "success" : True },
           { "loc" : "/api?human=0&alien=read&uuid=b2898b6c-83a8-4aaf-b39b-b6d919160dba&reviewlist=1&page=34", "method" : "get", "success" : True },

           # Go to last page
           { "loc" : "/api?human=0&alien=home&view=1&uuid=b2898b6c-83a8-4aaf-b39b-b6d919160dba&page=219", "method" : "get", "success" : True },
           { "loc" : "/api?human=0&alien=read&uuid=b2898b6c-83a8-4aaf-b39b-b6d919160dba&reviewlist=1&page=219", "method" : "get", "success" : True },

            # Go one page past the end
            # Javascript won't let us do this, but I might screw up
            # Will cause a replication error, requiring us to re-login
           { "loc" : "/api?human=0&alien=home&view=1&uuid=b2898b6c-83a8-4aaf-b39b-b6d919160dba&page=220", "method" : "get", "success" : False },

           # So, login again:
           { "method" : "login", "loc" : "login" },

            # Go one page before the beginning.
           { "loc" : "/api?human=0&alien=read&meaningmode=true", "method" : "get", "success" : True },
           { "loc" : "/api?human=0&alien=read&meaningmode=false", "method" : "get", "success" : True },

           # Muck with account
           { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "data" : dict(remove=1, tofrom='zh-CHS,en') },
           { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "data" : dict(remove=0, tofrom='zh-CHS,en') },
           { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "data" : dict(remove=1, tofrom='es,en') },
           { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "data" : dict(remove=0, tofrom='es,en') },
           { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "data" : dict(remove=1, tofrom='en,es') },
           { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "data" : dict(remove=0, tofrom='en,es') },
           { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "data" : dict(remove=1, tofrom='en,zh-CHS') },
           { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "data" : dict(remove=0, tofrom='en,zh-CHS') },

#           { "loc" : "/api?human=0&alien=account", "method" : "get", "success" : True, "data" : dict() },
#           { "loc" : "/api?human=0&alien=account", "method" : "get", "success" : True, "data" : dict() },
#           { "loc" : "/api?human=0&alien=account", "method" : "get", "success" : True, "data" : dict() },
#           { "loc" : "/api?human=0&alien=account", "method" : "get", "success" : True, "data" : dict() },
#           { "loc" : "/api?human=0&alien=account", "method" : "get", "success" : True, "data" : dict() },
#           { "loc" : "/api?human=0&alien=account", "method" : "get", "success" : True, "data" : dict() },
#           { "loc" : "/api?human=0&alien=account", "method" : "get", "success" : True, "data" : dict() },

        ]

links = generate_oauth_links(parameters["oauth"], slash = "/")

port = 9888

for link in links :
    url_parameters = link["href"].split("?", 1)[1]
    newhref = ":" + str(port) + "/" + link["title"] + "?" + url_parameters 
    print "Emulating: " + newhref
    urls.append({ "loc" : newhref, "method" : "get", "data" : dict() })

httpd = TimeoutServer(('127.0.0.1', port), MyHandler)
oresp = Thread(target=oauth_responder, args = [httpd])
oresp.daemon = True
oresp.start() 

mthread = Thread(target=go, args = [parameters])
mthread.daemon = True
mthread.start() 

wait_for_port_ready("mica", "localhost", parameters["port"])
r = s.get("http://localhost")
assert(r.status_code == 200)

sleep(3)

urls.append({ "method" : "logout", "loc" : "logout" })
#run_tests()

try:
    print "Done. Application left running..."
    mthread.join()
except KeyboardInterrupt:
    print "CTRL-C interrupt"

httpd.socket.close()

