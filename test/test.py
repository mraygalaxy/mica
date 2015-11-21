#!/usr/bin/env python
# coding: utf-8

from re import compile as re_compile, IGNORECASE as re_IGNORECASE, sub as re_sub
from os import path as os_path, getuid as os_getuid, urandom as os_urandom, remove as os_remove, makedirs as os_makedirs, environ
from docker import Client
from json import loads as json_loads, dumps as json_dumps
from time import sleep
from urlparse import urlparse, parse_qs
from SimpleHTTPServer import SimpleHTTPRequestHandler
from threading import Thread
from binascii import hexlify as binascii_hexlify

import requests
import docker
import socket
import sys
import BaseHTTPServer
import httplib
import logging

environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

'''
httplib.HTTPConnection.debuglevel = 2
logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True
'''

cwd = re_compile(".*\/").search(os_path.realpath(__file__)).group(0)
sys.path = [cwd, cwd + "../"] + sys.path

from params import parameters, test
from common import sdict
from mica import go
from pyquery import PyQuery as pq

server_port = 9888

'''
Post: https://accounts.google.com/o/oauth2/token

{u'code': u'4/sdRdEpg-UCxjF2bqlaFMIcXmzYcMqFfMZVUq1m3iDmE', u'client_secret': u'hIyf_eQqtPEbyMD7pLuKxejS', u'grant_type': u'authorization_code', u'client_id': u'195565572022-ogots3m7a0alrp6sbvm7a8i3458dc814.apps.googleusercontent.com', u'redirect_uri': u'http://localhost:20000/google'}

    "GoogleToken" :      [ dict(inp = {u'code': u'4/sdRdEpg-UCxjF2bqlaFMIcXmzYcMqFfMZVUq1m3iDmE', u'client_secret': u'hIyf_eQqtPEbyMD7pLuKxejS', u'grant_type': u'authorization_code', u'client_id': u'195565572022-ogots3m7a0alrp6sbvm7a8i3458dc814.apps.googleusercontent.com', u'redirect_uri': u'http://localhost:20000/google'}
'''

oauth = { "codes" : {}, "states" : {}, "tokens" : {}}

mock_rest = {
    "TranslatorAccess" : [ dict(inp = {"client_secret": "fge8PkcT/cF30AcBKOMuU9eDysKN/a7fUqH6Tq3M0W8=", "grant_type": "client_credentials", "client_id": "micalearning", "scope": "http://localhost:" + str(server_port) + "/TranslatorRequest"},
                               outp = {"token_type": "http://schemas.xmlsoap.org/ws/2009/11/swt-token-profile-1.0", "access_token": "http%3a%2f%2fschemas.xmlsoap.org%2fws%2f2005%2f05%2fidentity%2fclaims%2fnameidentifier=micalearning&http%3a%2f%2fschemas.microsoft.com%2faccesscontrolservice%2f2010%2f07%2fclaims%2fidentityprovider=https%3a%2f%2fdatamarket.accesscontrol.windows.net%2f&Audience=http%3a%2f%2fapi.microsofttranslator.com&ExpiresOn=1448071220&Issuer=https%3a%2f%2fdatamarket.accesscontrol.windows.net%2f&HMACSHA256=p2YmU56ljSJjtcQOpViQaKZ1JpEOZJiCGQJf5otxmpA%3d", "expires_in": "599", "scope": "http://api.microsofttranslator.com"}),
                         ],
    "TranslatorRequest" : [ dict(inp = {'texts': '["\\u708e\\u70ed", "\\u708e", "\\u70ed"]', 'from': 'zh-CHS', 'options': 'null', 'to': 'en'} ,
                                 outp = [{"TranslatedText": "Hot", "From": "zh-CHS", "OriginalTextSentenceLengths": [2], "TranslatedTextSentenceLengths": [3]}, {"TranslatedText": "Inflammation", "From": "zh-CHS", "OriginalTextSentenceLengths": [1], "TranslatedTextSentenceLengths": [12]}, {"TranslatedText": "It's hot", "From": "zh-CHS", "OriginalTextSentenceLengths": [1], "TranslatedTextSentenceLengths": [8]}]), ],

    #"" : [dict(inp = , outp = ),],
    #"" : [dict(inp = , outp = ),],
}
    

class MyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def my_parse(self, data) :
        url_parameters = {}
        parsed_data = parse_qs(data, keep_blank_values=1)
        for k, v in parsed_data.iteritems() :
            v = v[0] if (isinstance(v, list) and len(v) == 1) else v
            url_parameters[k] = v
        return url_parameters

    def check_mock_data(self, path, url_parameters) :
        body = ""

        for key in mock_rest.keys() : 
            found = False
            if path.count(key) :
                print "MOCKING: " + key
                for pair in mock_rest[key] :
                    if url_parameters == pair["inp"] :
                        found = True
                        body = json_dumps(pair["outp"])
                    else :
                        print "WARNING. NEVER Seen this input. =("
                    break
            if found :
                break

        return body 

    def do_POST(self) :
        body = ""
        url = urlparse(self.path)
        url_parameters = self.my_parse(url.query)
        path = url.path.replace("/", "")
        length = int(self.headers.getheader('content-length'))
        url_parameters.update(self.my_parse(self.rfile.read(length)))
        result = 200
        result_msg = "OK"

        print str(path) + ": " + str(url_parameters)

        body = sdict(success = True, test_success = True)

        if path == "foo" :
            body = "bar"
        elif path in parameters["oauth"].keys() :
            if "action" in url_parameters and url_parameters["action"] == "token" :
                print "TOKEN REQUEST from: " + path
                state = oauth["states"][path]
                code = oauth["states"][path]
                if url_parameters["code"] != code or url_parameters["client_secret"] != parameters["oauth"][path]["client_secret"] :
                    result = 401
                    result_msg = "Bad Things"
                    body = {"error" : "bad things"} 
                    
                oauth["tokens"][path] = binascii_hexlify(os_urandom(4))
                body = sdict(access_token = oauth["tokens"][path], token_type = "Bearer", expires_in = 3597)
        else :
            body = self.check_mock_data(path, url_parameters)

        try:
            self.send_response(result, result_msg)
            self.send_header('Content-type','text/html')
            self.send_header("Content-length", str(len(body)))
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
        url_parameters = self.my_parse(url.query)
        path = url.path.replace("/", "")
        print str(path) + ": " + str(url_parameters)

        result = 200
        result_msg = "OK"

        body = sdict(success = True, test_success = True)

        if path == "foo" :
            body = "bar"
        elif path in parameters["oauth"].keys() :
            if "action" in url_parameters and url_parameters["action"] == "lookup" :
                def getFromDict(dataDict, mapList):
                    return reduce(lambda d, k: d[k], mapList, dataDict)
                def setInDict(dataDict, mapList, value):
                    getFromDict(dataDict, mapList[:-1])[mapList[-1]] = value
                body_dict = {}

                if "email_key" in parameters["oauth"][path] and parameters["oauth"][path]["email_key"] :
                    setInDict(body_dict, parameters["oauth"][path]["email_key"].split(","), path + "@holymother.com")

                if "verified_key" in parameters["oauth"][path] and parameters["oauth"][path]["verified_key"] :
                    body_dict[parameters["oauth"][path]["verified_key"]] = True 
                    setInDict(body_dict, parameters["oauth"][path]["verified_key"].split(","), True)
                body = json_dumps(body_dict)
        else :
            body = self.check_mock_data(path, url_parameters)

        self.send_response(result, result_msg)
        self.send_header('Content-type', 'html')
        self.send_header("Content-length", str(len(body)) )
        self.end_headers()
        self.wfile.write(body)

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
    stop = False
    try:
        for url in urls :
            if "stop" in url and url["stop"] :
                print "Stop requested."
                stop = True
                break

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
                if url["method"] != "logout" :
                    # The difference between 'success' and 'test_success' is for errors
                    # that happen during tests which are tolerable in the user experience.
                    # For example, if the translation API can't reach the internet, the
                    # UI will just return that connectivity information to the user, but
                    # it does not mean there's a failure in the system. But, it is indeed
                    # a unit test failure, so we need to know about it and check for it.
                    try :
                        j = json_loads(r.text)
                    except ValueError, e :
                        print "Failed to parse JSON from: " + r.text
                        assert(False)

                    if "success" in url and url["success"] is not None :
                        assert("success" in j)
                        assert(j["success"] == url["success"])
                    if "test_success" in url and url["test_success"] is not None :
                        assert("test_success" in j)
                        assert(j["test_success"] == url["test_success"])

    except KeyboardInterrupt:
        print "CTRL-C interrupt"

    return stop

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
            { "loc" : "/api?human=0&alien=storylist&tzoffset=18000", "method" : "get", "success" :  True, "test_success" : True },
            { "loc" : "/api?human=0&alien=read&view=1&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb", "method" : "get", "success" :  True, "test_success" : True },
            { "loc" : "/api?human=0&alien=read&view=1&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&page=0", "method" : "get", "success" :  True, "test_success" : True },
            { "loc" : "/api?human=0&alien=read&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&memolist=1&page=0", "method" : "get", "success" :  True, "test_success" : True },
            { "loc" : "/api?human=0&alien=read&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&memorized=1&nb_unit=8&page=0", "method" : "get", "success" :  True, "test_success" : True },
            { "loc" : "/api?human=0&alien=read&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&memorized=0&nb_unit=3&page=0", "method" : "get", "success" :  True, "test_success" : True },
            { "loc" : "/api?human=0&alien=read", "method" : "get", "success" :  True, "test_success" : True },
            { "loc" : "/api?human=0&alien=read&view=1&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&page=0", "method" : "get", "success" :  True, "test_success" : True },
            { "loc" : "/api?human=0&alien=read&view=1&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&page=0&image=0", "method" : "get", "success" :  True },
            { "loc" : "/api?human=0&alien=read&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&memolist=1&page=0", "method" : "get", "success" :  True },
            { "loc" : "/api?human=0&alien=instant&source=%E7%82%8E%E7%83%AD&lang=en&source_language=zh-CHS&target_language=en", "method" : "get", "success" : True, "test_success" :  True },
#            { "stop" : True },
            { "loc" : "/api?human=0&alien=home&view=1", "method" : "get", "success" :  True, "test_success" :  True },
            { "loc" : "/api?human=0&alien=home&switchmode=text", "method" : "get", "success" :  True, "test_success" :  True },
            { "loc" : "/api?human=0&alien=home&view=1&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&page=0", "method" : "get", "success" :  True, "test_success" :  True },
            { "loc" : "/api?human=0&alien=read&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&reviewlist=1&page=0", "method" : "get", "success" :  True, "test_success" :  True },
            { "loc" : "/api?human=0&alien=home&view=1&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&multiple_select=1&index=1&nb_unit=11&trans_id=9&page=0", "method" : "get", "success" :  True, "test_success" :  True },
            { "loc" : "/api?human=0&alien=home&view=1&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&multiple_select=1&index=1&nb_unit=48&trans_id=42&page=0", "method" : "get", "success" :  True, "test_success" :  True },
            { "loc" : "/api?human=0&alien=home", "method" : "post", "success" :  True, "test_success" :  True, "data" : dict(retranslate = '1', page = '0', uuid = 'b220074e-f1a7-417b-9f83-e63cebea02cb') },
            # Assert that the default has changed and move multiple_select to actual JSON, then retry the request
            { "loc" : "/api?human=0&alien=edit&view=1", "method" : "get", "success" :  True, "test_success" :  True },
            { "loc" : "/api?human=0&alien=edit&view=1&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&page=0", "method" : "get", "success" :  True, "test_success" :  True },
            { "loc" : "/api?human=0&alien=edit&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&editslist=1&page=0", "method" : "get", "success" :  True, "test_success" :  True },
            { "loc" : "/api?human=0&alien=edit", "method" : "post", "success" : True, "test_success" :  True, "data" : dict(oprequest = '[{"operation":"split","uuid":"b220074e-f1a7-417b-9f83-e63cebea02cb","units":1,"failed":false,"chars":"小鸟","pinyin":"xiǎo+niǎo","nbunit":"8","uhash":"0b23c772194ef5a97aa23d5590105665","index":"-1","pagenum":"0","out":""},{"operation":"merge","uuid":"b220074e-f1a7-417b-9f83-e63cebea02cb","units":2,"failed":false,"chars":"跳","pinyin":"tiào","nbunit0":"45","uhash0":"0cdbc17e9ed386e3f3df2b26ed5b5187","index0":"-1","page0":"0","chars0":"跳","pinyin0":"tiào","nbunit1":"46","uhash1":"0cdbc17e9ed386e3f3df2b26ed5b5187","index1":"-1","page1":"0","chars1":"跳","pinyin1":"tiào","out":""}]', uuid = "b220074e-f1a7-417b-9f83-e63cebea02cb") },
           { "loc" : "/api?human=0&alien=edit", "method" : "post", "success" : True, "test_success" :  True, "data" : dict(oprequest = '[{"operation":"split","uuid":"b220074e-f1a7-417b-9f83-e63cebea02cb","units":1,"failed":false,"chars":"山羊","pinyin":"shān+yáng","nbunit":"111","uhash":"fb7335cbba25395d3b9a867ddad630fd","index":"-1","pagenum":"0","out":""}]', uuid = "b220074e-f1a7-417b-9f83-e63cebea02cb") },
           { "loc" : "/api?human=0&alien=read&uuid=b2898b6c-83a8-4aaf-b39b-b6d919160dba&reviewlist=1&page=151", "method" : "get", "success" : True, "test_success" :  True },
           { "loc" : "/api?human=0&alien=home", "method" : "post", "success" : True, "test_success" :  True, "data" : dict(transid0 = 67, index0 = 1, nbunit0 = 75, page0 = 151, transid1 = 74, index1 = 1, nbunit1 = 84, page1 = 151, transid2 = 81, index2 = 1, nbunit2 = 93, page2 = 151, transid3 = 88, index3 = 1, nbunit3 = 102, page3 = 151, transid4 = 105, index4 = 1, nbunit4 = 123, page4 = 151, count = 5, bulkreview = 1) },
           { "loc" : "/api?human=0&alien=read&uuid=b2898b6c-83a8-4aaf-b39b-b6d919160dba&reviewlist=1&page=151", "method" : "get", "success" : True, "test_success" :  True },

           # Switch to split view on sample
           { "loc" : "/api?human=0&alien=read&uuid=b2898b6c-83a8-4aaf-b39b-b6d919160dba&reviewlist=1&page=151", "method" : "get", "success" : True, "test_success" :  True },
           { "loc" : "/api?human=0&alien=home&view=1&uuid=b2898b6c-83a8-4aaf-b39b-b6d919160dba&page=151", "method" : "get", "success" : True, "test_success" :  True },
           { "loc" : "/api?human=0&alien=read&uuid=b2898b6c-83a8-4aaf-b39b-b6d919160dba&reviewlist=1&page=151", "method" : "get", "success" : True, "test_success" :  True },
           { "loc" : "/api?human=0&alien=home&switchmode=both", "method" : "get", "success" : True },
           { "loc" : "/api?human=0&alien=home&view=1&uuid=b2898b6c-83a8-4aaf-b39b-b6d919160dba&page=151&image=0", "method" : "get", "success" : True, "test_success" :  True },

            # Switch to image-only

           { "loc" : "/api?human=0&alien=home&switchmode=images", "method" : "get", "success" : True, "test_success" :  True },
           { "loc" : "/api?human=0&alien=home&view=1&uuid=b2898b6c-83a8-4aaf-b39b-b6d919160dba&page=151&image=0", "method" : "get", "success" : True, "test_success" :  True },
           { "loc" : "/api?human=0&alien=read&uuid=b2898b6c-83a8-4aaf-b39b-b6d919160dba&reviewlist=1&page=151", "method" : "get", "success" : True, "test_success" :  True },

           # Switch back to text-only

#           { "loc" : "/api?human=0&alien=home&view=1&uuid=b2898b6c-83a8-4aaf-b39b-b6d919160dba&page=151", "method" : "get", "success" : True, "test_success" :  True },
#           { "loc" : "/api?human=0&alien=read&uuid=b2898b6c-83a8-4aaf-b39b-b6d919160dba&reviewlist=1&page=151", "method" : "get", "success" : True, "test_success" :  True },
#           { "loc" : "/api?human=0&alien=home&switchmode=text", "method" : "get", "success" : True, "test_success" :  True },

            # Go to page 35
           { "loc" : "/api?human=0&alien=home&view=1&uuid=b2898b6c-83a8-4aaf-b39b-b6d919160dba&page=34", "method" : "get", "success" : True, "test_success" :  True },
           { "loc" : "/api?human=0&alien=read&uuid=b2898b6c-83a8-4aaf-b39b-b6d919160dba&reviewlist=1&page=34", "method" : "get", "success" : True, "test_success" :  True },

           # Go to last page
           { "loc" : "/api?human=0&alien=home&view=1&uuid=b2898b6c-83a8-4aaf-b39b-b6d919160dba&page=219", "method" : "get", "success" : True, "test_success" :  True },
           { "loc" : "/api?human=0&alien=read&uuid=b2898b6c-83a8-4aaf-b39b-b6d919160dba&reviewlist=1&page=219", "method" : "get", "success" : True, "test_success" :  True },

            # Go one page past the end
            # Javascript won't let us do this, but I might screw up
            # Will cause a replication error, requiring us to re-login
           { "loc" : "/api?human=0&alien=home&view=1&uuid=b2898b6c-83a8-4aaf-b39b-b6d919160dba&page=220", "method" : "get", "success" : False, "test_success" :  True },

           # So, login again:
           { "method" : "login", "loc" : "login" },

            # Go one page before the beginning.
           { "loc" : "/api?human=0&alien=read&meaningmode=true", "method" : "get", "success" : True, "test_success" :  True },
           { "loc" : "/api?human=0&alien=read&meaningmode=false", "method" : "get", "success" : True, "test_success" :  True },

           # Muck with account
           { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "test_success" :  True, "data" : dict(remove=1, tofrom='zh-CHS,en') },
           { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "test_success" :  True, "data" : dict(remove=0, tofrom='zh-CHS,en') },
           { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "test_success" :  True, "data" : dict(remove=1, tofrom='es,en') },
           { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "test_success" :  True, "data" : dict(remove=0, tofrom='es,en') },
           { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "test_success" :  True, "data" : dict(remove=1, tofrom='en,es') },
           { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "test_success" :  True, "data" : dict(remove=0, tofrom='en,es') },
           { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "test_success" :  True, "data" : dict(remove=1, tofrom='en,zh-CHS') },
           { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "test_success" :  True, "data" : dict(remove=0, tofrom='en,zh-CHS') },

#           { "loc" : "/api?human=0&alien=account", "method" : "get", "success" : True, "test_success" :  True, "data" : dict() },
#           { "loc" : "/api?human=0&alien=account", "method" : "get", "success" : True, "test_success" :  True, "data" : dict() },
#           { "loc" : "/api?human=0&alien=account", "method" : "get", "success" : True, "test_success" :  True, "data" : dict() },
#           { "loc" : "/api?human=0&alien=account", "method" : "get", "success" : True, "test_success" :  True, "data" : dict() },
#           { "loc" : "/api?human=0&alien=account", "method" : "get", "success" : True, "test_success" :  True, "data" : dict() },
#           { "loc" : "/api?human=0&alien=account", "method" : "get", "success" : True, "test_success" :  True, "data" : dict() },
#           { "loc" : "/api?human=0&alien=account", "method" : "get", "success" : True, "test_success" :  True, "data" : dict() },

        ]

if "test" not in parameters or not parameters["test"] :
    parameters["trans_scope"] = "http://localhost:" + str(server_port) + "/TranslatorRequest"
    parameters["trans_access_token_url"] = "http://localhost:" + str(server_port) + "/TranslatorAccess"

httpd = TimeoutServer(('127.0.0.1', server_port), MyHandler)
oresp = Thread(target=oauth_responder, args = [httpd])
oresp.daemon = True
oresp.start() 

mthread = Thread(target=go, args = [parameters])
mthread.daemon = True
mthread.start() 

wait_for_port_ready("mica", "localhost", parameters["port"])
r = s.get("http://localhost/disconnect")
assert(r.status_code == 200)
r = s.get("http://localhost")
assert(r.status_code == 200)

d = pq(r.text)

for who in parameters["oauth"].keys() :
    if who == "redirect" :
        continue

    print "Checking for: " + who + ": " + d("#oauth_" + who).html()
    for part in d("#oauth_" + who).attr("href").split("&") :
        if part.count("state") :
            state = part.split("=")[1]
            print "Need to test " + who + ", state: " + state
            oauth["states"][who] = state
            oauth["codes"][who] = binascii_hexlify(os_urandom(4))
            urls.append({ "method" : "logout", "loc" : "logout" })
            urls.append(dict(loc = "/" + who + "?connect=1&finish=1&state=" + state + "&code=" + oauth["codes"][who], method = "get", data = {}, success = True, test_success = True))
            parameters["oauth"][who]["token_url"] = "http://localhost:" + str(server_port) + "/" + who + "?action=token"
            parameters["oauth"][who]["lookup_url"] = "http://localhost:" + str(server_port) + "/" + who + "?action=lookup&"
            break
        
sleep(5)

urls.append({ "method" : "logout", "loc" : "logout" })
stop = run_tests()
#stop = False

if not stop :
    try:
        print "Done. Application left running..."
        mthread.join()
    except KeyboardInterrupt:
        print "CTRL-C interrupt"

httpd.socket.close()

