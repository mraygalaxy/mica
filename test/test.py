#!/usr/bin/env python
# coding: utf-8

from __future__ import print_function
from traceback import format_exc, print_stack
from re import compile as re_compile, IGNORECASE as re_IGNORECASE, sub as re_sub
from os import path as os_path, getuid as os_getuid, urandom as os_urandom, remove as os_remove, makedirs as os_makedirs, environ
from docker import Client
from json import loads as json_loads, dumps as json_dumps
from time import sleep, time
from urlparse import urlparse, parse_qs
from SimpleHTTPServer import SimpleHTTPRequestHandler
from threading import Thread
from binascii import hexlify as binascii_hexlify
from logging.handlers import RotatingFileHandler
from logging import getLogger, StreamHandler, Formatter, Filter, DEBUG, ERROR, INFO, WARN, CRITICAL
from copy import deepcopy

import requests
import docker
import socket
import sys
import BaseHTTPServer
import httplib
import logging

logger = getLogger("micatest")
logger.setLevel(level=DEBUG)
streamhandler = StreamHandler(sys.stderr)
logger.addHandler(streamhandler)

def tlog(*objs):
    logger.debug(*objs)

environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

start_time = int(time())
level = logging.WARN
'''
httplib.HTTPConnection.debuglevel = 2
'''
logging.basicConfig()
logging.getLogger().setLevel(level)
#requests_log = logging.getLogger("requests.packages.urllib3")
#requests_log.setLevel(level)
#requests_log.propagate = True
requests.packages.urllib3.disable_warnings()

cwd = re_compile(".*\/").search(os_path.realpath(__file__)).group(0)
sys.path = [cwd, cwd + "../"] + sys.path

record = open(cwd + "../logs/test.log", 'w')

from params import parameters, test
from common import sdict, recursiveSetInDict, timest, getFromDict
from mica import go
from pyquery import PyQuery as pq
from sys import argv
import couch_adapter

server_port = 9888
target = test["target_proto"] + "://" + test["target"] + ":" + str(test["target_port"])
couch = parameters["couch_proto"] + "://" + parameters["couch_server"] + ":" + str(parameters["couch_port"]) + ((parameters["couch_path"] + "/") if "couch_path" in parameters else "")
target_verify = True if test["target_proto"] == "http" else False
couch_verify = True if parameters["couch_proto"] == "http" else False

test_timeout = 5

oauth = { "codes" : {}, "states" : {}, "tokens" : {}}

mock_rest = {
    "TranslatorAccess" : [ dict(inp = {"client_secret": "fge8PkcT/cF30AcBKOMuU9eDysKN/a7fUqH6Tq3M0W8=", "grant_type": "client_credentials", "client_id": "micalearning", "scope": "http://localhost:" + str(server_port) + "/TranslatorRequest"},
                               outp = {"token_type": "http://schemas.xmlsoap.org/ws/2009/11/swt-token-profile-1.0", "access_token": "http%3a%2f%2fschemas.xmlsoap.org%2fws%2f2005%2f05%2fidentity%2fclaims%2fnameidentifier=micalearning&http%3a%2f%2fschemas.microsoft.com%2faccesscontrolservice%2f2010%2f07%2fclaims%2fidentityprovider=https%3a%2f%2fdatamarket.accesscontrol.windows.net%2f&Audience=http%3a%2f%2fapi.microsofttranslator.com&ExpiresOn=1448071220&Issuer=https%3a%2f%2fdatamarket.accesscontrol.windows.net%2f&HMACSHA256=p2YmU56ljSJjtcQOpViQaKZ1JpEOZJiCGQJf5otxmpA%3d", "expires_in": "599", "scope": "http://api.microsofttranslator.com"}),
                         ],
    "TranslatorRequest" : [
                {"outp": [{"TranslatedText": "Baise", "From": "zh-CHS", "OriginalTextSentenceLengths": [2], "TranslatedTextSentenceLengths": [5]}], "inp": {"texts": "[\"\\u767e\\u8272\"]", "from": "zh-CHS", "options": "null", "to": "en"}},
                {"outp": [{"TranslatedText": "Business", "From": "zh-CHS", "OriginalTextSentenceLengths": [2], "TranslatedTextSentenceLengths": [8]}], "inp": {"texts": "[\"\\u751f\\u610f\"]", "from": "zh-CHS", "options": "null", "to": "en"}},
                {"outp": [{"TranslatedText": "Centimetre", "From": "zh-CHS", "OriginalTextSentenceLengths": [2], "TranslatedTextSentenceLengths": [10]}], "inp": {"texts": "[\"\\u5398\\u7c73\"]", "from": "zh-CHS", "options": "null", "to": "en"}},
                {"outp": [{"TranslatedText": "Cheap", "From": "zh-CHS", "OriginalTextSentenceLengths": [2], "TranslatedTextSentenceLengths": [5]}], "inp": {"texts": "[\"\\u4fbf\\u5b9c\"]", "from": "zh-CHS", "options": "null", "to": "en"}},
                {"outp": [{"TranslatedText": "Collection", "From": "zh-CHS", "OriginalTextSentenceLengths": [2], "TranslatedTextSentenceLengths": [10]}], "inp": {"texts": "[\"\\u6c47\\u96c6\"]", "from": "zh-CHS", "options": "null", "to": "en"}},
                {"outp": [{"TranslatedText": "Come out", "From": "zh-CHS", "OriginalTextSentenceLengths": [2], "TranslatedTextSentenceLengths": [8]}], "inp": {"texts": "[\"\\u51fa\\u6765\"]", "from": "zh-CHS", "options": "null", "to": "en"}},
                {"outp": [{"TranslatedText": "Fair", "From": "zh-CHS", "OriginalTextSentenceLengths": [2], "TranslatedTextSentenceLengths": [4]}], "inp": {"texts": "[\"\\u516c\\u9053\"]", "from": "zh-CHS", "options": "null", "to": "en"}},
                {"outp": [{"TranslatedText": "Family", "From": "zh-CHS", "OriginalTextSentenceLengths": [2], "TranslatedTextSentenceLengths": [6]}], "inp": {"texts": "[\"\\u4eba\\u5bb6\"]", "from": "zh-CHS", "options": "null", "to": "en"}},
                {"outp": [{"TranslatedText": "Get up", "From": "zh-CHS", "OriginalTextSentenceLengths": [2], "TranslatedTextSentenceLengths": [6]}], "inp": {"texts": "[\"\\u8d77\\u6765\"]", "from": "zh-CHS", "options": "null", "to": "en"}},
                {"outp": [{"TranslatedText": "Hot", "From": "zh-CHS", "OriginalTextSentenceLengths": [2], "TranslatedTextSentenceLengths": [3]}, {"TranslatedText": "Inflammation", "From": "zh-CHS", "OriginalTextSentenceLengths": [1], "TranslatedTextSentenceLengths": [12]}, {"TranslatedText": "It's hot", "From": "zh-CHS", "OriginalTextSentenceLengths": [1], "TranslatedTextSentenceLengths": [8]}], "inp": {"texts": "[\"\\u708e\\u70ed\", \"\\u708e\", \"\\u70ed\"]", "from": "zh-CHS", "options": "null", "to": "en"}},
                {"outp": [{"TranslatedText": "How", "From": "zh-CHS", "OriginalTextSentenceLengths": [2], "TranslatedTextSentenceLengths": [3]}], "inp": {"texts": "[\"\\u600e\\u4e48\"]", "from": "zh-CHS", "options": "null", "to": "en"}},
                {"outp": [{"TranslatedText": "Husband", "From": "zh-CHS", "OriginalTextSentenceLengths": [2], "TranslatedTextSentenceLengths": [7]}], "inp": {"texts": "[\"\\u8001\\u516c\"]", "from": "zh-CHS", "options": "null", "to": "en"}},
                {"outp": [{"TranslatedText": "Internet", "From": "zh-CHS", "OriginalTextSentenceLengths": [2], "TranslatedTextSentenceLengths": [8]}], "inp": {"texts": "[\"\\u7f51\\u7edc\"]", "from": "zh-CHS", "options": "null", "to": "en"}},
                {"outp": [{"TranslatedText": "King", "From": "zh-CHS", "OriginalTextSentenceLengths": [2], "TranslatedTextSentenceLengths": [4]}], "inp": {"texts": "[\"\\u5927\\u738b\"]", "from": "zh-CHS", "options": "null", "to": "en"}},
                {"outp": [{"TranslatedText": "Modern", "From": "zh-CHS", "OriginalTextSentenceLengths": [2], "TranslatedTextSentenceLengths": [6]}], "inp": {"texts": "[\"\\u73b0\\u4ee3\"]", "from": "zh-CHS", "options": "null", "to": "en"}},
                {"outp": [{"TranslatedText": "Nausea", "From": "zh-CHS", "OriginalTextSentenceLengths": [2], "TranslatedTextSentenceLengths": [6]}], "inp": {"texts": "[\"\\u6076\\u5fc3\"]", "from": "zh-CHS", "options": "null", "to": "en"}},
                {"outp": [{"TranslatedText": "Promise", "From": "zh-CHS", "OriginalTextSentenceLengths": [2], "TranslatedTextSentenceLengths": [7]}], "inp": {"texts": "[\"\\u51fa\\u606f\"]", "from": "zh-CHS", "options": "null", "to": "en"}},
                {"outp": [{"TranslatedText": "Relationship", "From": "zh-CHS", "OriginalTextSentenceLengths": [2], "TranslatedTextSentenceLengths": [12]}], "inp": {"texts": "[\"\\u5173\\u7cfb\"]", "from": "zh-CHS", "options": "null", "to": "en"}},
                {"outp": [{"TranslatedText": "Reporting", "From": "zh-CHS", "OriginalTextSentenceLengths": [2], "TranslatedTextSentenceLengths": [9]}], "inp": {"texts": "[\"\\u6c47\\u62a5\"]", "from": "zh-CHS", "options": "null", "to": "en"}},
                {"outp": [{"TranslatedText": "Review", "From": "zh-CHS", "OriginalTextSentenceLengths": [2], "TranslatedTextSentenceLengths": [6]}], "inp": {"texts": "[\"\\u590d\\u4e60\"]", "from": "zh-CHS", "options": "null", "to": "en"}},
                {"outp": [{"TranslatedText": "Story", "From": "zh-CHS", "OriginalTextSentenceLengths": [2], "TranslatedTextSentenceLengths": [5]}], "inp": {"texts": "[\"\\u6545\\u4e8b\"]", "from": "zh-CHS", "options": "null", "to": "en"}},
                {"outp": [{"TranslatedText": "Take care of", "From": "zh-CHS", "OriginalTextSentenceLengths": [2], "TranslatedTextSentenceLengths": [12]}], "inp": {"texts": "[\"\\u7167\\u5e94\"]", "from": "zh-CHS", "options": "null", "to": "en"}},
                {"outp": [{"TranslatedText": "Things", "From": "zh-CHS", "OriginalTextSentenceLengths": [2], "TranslatedTextSentenceLengths": [6]}], "inp": {"texts": "[\"\\u4e1c\\u897f\"]", "from": "zh-CHS", "options": "null", "to": "en"}},
                {"outp": [{"TranslatedText": "View", "From": "zh-CHS", "OriginalTextSentenceLengths": [2], "TranslatedTextSentenceLengths": [4]}], "inp": {"texts": "[\"\\u8bf4\\u6cd5\"]", "from": "zh-CHS", "options": "null", "to": "en"}},
                {"outp": [{"TranslatedText": "Where", "From": "zh-CHS", "OriginalTextSentenceLengths": [2], "TranslatedTextSentenceLengths": [5]}], "inp": {"texts": "[\"\\u54ea\\u91cc\"]", "from": "zh-CHS", "options": "null", "to": "en"}},
                {"outp": [{"TranslatedText": "Wonder", "From": "zh-CHS", "OriginalTextSentenceLengths": [2], "TranslatedTextSentenceLengths": [6]}], "inp": {"texts": "[\"\\u7422\\u78e8\"]", "from": "zh-CHS", "options": "null", "to": "en"}},
                {"outp": [{"TranslatedText": "Woods", "From": "zh-CHS", "OriginalTextSentenceLengths": [2], "TranslatedTextSentenceLengths": [5]}], "inp": {"texts": "[\"\\u6811\\u6797\"]", "from": "zh-CHS", "options": "null", "to": "en"}},
                {"outp": [{"TranslatedText": "\u4e08\u592b", "From": "en", "OriginalTextSentenceLengths": [7], "TranslatedTextSentenceLengths": [2]}], "inp": {"texts": "[\"Husband\"]", "from": "en", "options": "null", "to": "zh-CHS"}},
                {"outp" : [{"TranslatedText": "\u4e0d\u77e5\u9053", "From": "en", "OriginalTextSentenceLengths": [6], "TranslatedTextSentenceLengths": [3]}], "inp": {"texts": "[\"Wonder\"]", "from": "en", "options": "null", "to": "zh-CHS"}},
                {"outp": [{"TranslatedText": "\u4e0d\u77e5\u9053", "From": "en", "OriginalTextSentenceLengths": [6], "TranslatedTextSentenceLengths": [3]}], "inp": {"texts": "[\"Wonder\"]", "from": "en", "options": "null", "to": "zh-CHS"}},
                {"outp": [{"TranslatedText": "\u4e1a\u52a1", "From": "en", "OriginalTextSentenceLengths": [8], "TranslatedTextSentenceLengths": [2]}], "inp": {"texts": "[\"Business\"]", "from": "en", "options": "null", "to": "zh-CHS"}},
                {"outp": [{"TranslatedText": "\u4e8b\u60c5", "From": "en", "OriginalTextSentenceLengths": [6], "TranslatedTextSentenceLengths": [2]}], "inp": {"texts": "[\"Things\"]", "from": "en", "options": "null", "to": "zh-CHS"}},
                {"outp": [{"TranslatedText": "\u4e92\u8054\u7f51", "From": "en", "OriginalTextSentenceLengths": [8], "TranslatedTextSentenceLengths": [3]}], "inp": {"texts": "[\"Internet\"]", "from": "en", "options": "null", "to": "zh-CHS"}},
                {"outp": [{"TranslatedText": "\u4ece\u524d\u6709\u4e2a\u5c0f\u5b69", "From": "en", "OriginalTextSentenceLengths": [6], "TranslatedTextSentenceLengths": [6]}], "inp": {"texts": "[\"\\u4ece\\u524d\\u6709\\u4e2a\\u5c0f\\u5b69\"]", "from": "en", "options": "null", "to": "zh-CHS"}},
                {"outp": [{"TranslatedText": "\u4f0d\u5179", "From": "en", "OriginalTextSentenceLengths": [5], "TranslatedTextSentenceLengths": [2]}], "inp": {"texts": "[\"Woods\"]", "from": "en", "options": "null", "to": "zh-CHS"}},
                {"outp": [{"TranslatedText": "\u4fbf\u5b9c", "From": "en", "OriginalTextSentenceLengths": [5], "TranslatedTextSentenceLengths": [2]}], "inp": {"texts": "[\"Cheap\"]", "from": "en", "options": "null", "to": "zh-CHS"}},
                {"outp": [{"TranslatedText": "\u516c\u5e73", "From": "en", "OriginalTextSentenceLengths": [4], "TranslatedTextSentenceLengths": [2]}], "inp": {"texts": "[\"Fair\"]", "from": "en", "options": "null", "to": "zh-CHS"}},
                {"outp": [{"TranslatedText": "\u5173\u7cfb", "From": "en", "OriginalTextSentenceLengths": [12], "TranslatedTextSentenceLengths": [2]}], "inp": {"texts": "[\"Relationship\"]", "from": "en", "options": "null", "to": "zh-CHS"}},
                {"outp": [{"TranslatedText": "\u5398\u7c73", "From": "en", "OriginalTextSentenceLengths": [10], "TranslatedTextSentenceLengths": [2]}], "inp": {"texts": "[\"Centimetre\"]", "from": "en", "options": "null", "to": "zh-CHS"}},
                {"outp": [{"TranslatedText": "\u56fd\u738b", "From": "en", "OriginalTextSentenceLengths": [4], "TranslatedTextSentenceLengths": [2]}], "inp": {"texts": "[\"King\"]", "from": "en", "options": "null", "to": "zh-CHS"}},
                {"outp": [{"TranslatedText": "\u5728\u54ea\u91cc", "From": "en", "OriginalTextSentenceLengths": [5], "TranslatedTextSentenceLengths": [3]}], "inp": {"texts": "[\"Where\"]", "from": "en", "options": "null", "to": "zh-CHS"}},
                {"outp": [{"TranslatedText": "\u5982\u4f55", "From": "en", "OriginalTextSentenceLengths": [3], "TranslatedTextSentenceLengths": [2]}], "inp": {"texts": "[\"How\"]", "from": "en", "options": "null", "to": "zh-CHS"}},
                {"outp": [{"TranslatedText": "\u5ba1\u67e5", "From": "en", "OriginalTextSentenceLengths": [6], "TranslatedTextSentenceLengths": [2]}], "inp": {"texts": "[\"Review\"]", "from": "en", "options": "null", "to": "zh-CHS"}},
                {"outp": [{"TranslatedText": "\u5bb6\u5ead", "From": "en", "OriginalTextSentenceLengths": [6], "TranslatedTextSentenceLengths": [2]}], "inp": {"texts": "[\"Family\"]", "from": "en", "options": "null", "to": "zh-CHS"}},
                {"outp": [{"TranslatedText": "\u6076\u5fc3", "From": "en", "OriginalTextSentenceLengths": [6], "TranslatedTextSentenceLengths": [2]}], "inp": {"texts": "[\"Nausea\"]", "from": "en", "options": "null", "to": "zh-CHS"}},
                {"outp": [{"TranslatedText": "\u627f\u8bfa", "From": "en", "OriginalTextSentenceLengths": [7], "TranslatedTextSentenceLengths": [2]}], "inp": {"texts": "[\"Promise\"]", "from": "en", "options": "null", "to": "zh-CHS"}},
                {"outp": [{"TranslatedText": "\u62a5\u544a", "From": "en", "OriginalTextSentenceLengths": [9], "TranslatedTextSentenceLengths": [2]}], "inp": {"texts": "[\"Reporting\"]", "from": "en", "options": "null", "to": "zh-CHS"}},
                {"outp": [{"TranslatedText": "\u6545\u4e8b", "From": "en", "OriginalTextSentenceLengths": [5], "TranslatedTextSentenceLengths": [2]}], "inp": {"texts": "[\"Story\"]", "from": "en", "options": "null", "to": "zh-CHS"}},
                {"outp": [{"TranslatedText": "\u6765\u5427", "From": "en", "OriginalTextSentenceLengths": [4], "TranslatedTextSentenceLengths": [2]}, {"TranslatedText": "\u51fa", "From": "en", "OriginalTextSentenceLengths": [3], "TranslatedTextSentenceLengths": [1]}], "inp": {"texts": "[\"Come\", \"out\"]", "from": "en", "options": "null", "to": "zh-CHS"}},
                {"outp": [{"TranslatedText": "\u73b0\u4ee3", "From": "en", "OriginalTextSentenceLengths": [6], "TranslatedTextSentenceLengths": [2]}], "inp": {"texts": "[\"Modern\"]", "from": "en", "options": "null", "to": "zh-CHS"}},
                {"outp": [{"TranslatedText": "\u767e\u8272", "From": "en", "OriginalTextSentenceLengths": [5], "TranslatedTextSentenceLengths": [2]}], "inp": {"texts": "[\"Baise\"]", "from": "en", "options": "null", "to": "zh-CHS"}},
                {"outp": [{"TranslatedText": "\u83b7\u53d6", "From": "en", "OriginalTextSentenceLengths": [3], "TranslatedTextSentenceLengths": [2]}, {"TranslatedText": "\u5411\u4e0a", "From": "en", "OriginalTextSentenceLengths": [2], "TranslatedTextSentenceLengths": [2]}], "inp": {"texts": "[\"Get\", \"up\"]", "from": "en", "options": "null", "to": "zh-CHS"}},
                {"outp": [{"TranslatedText": "\u89c6\u56fe", "From": "en", "OriginalTextSentenceLengths": [4], "TranslatedTextSentenceLengths": [2]}], "inp": {"texts": "[\"View\"]", "from": "en", "options": "null", "to": "zh-CHS"}},
                {"outp": [{"TranslatedText": "\u91c7\u53d6", "From": "en", "OriginalTextSentenceLengths": [4], "TranslatedTextSentenceLengths": [2]}, {"TranslatedText": "\u4fdd\u5065", "From": "en", "OriginalTextSentenceLengths": [4], "TranslatedTextSentenceLengths": [2]}, {"TranslatedText": "\u7684", "From": "en", "OriginalTextSentenceLengths": [2], "TranslatedTextSentenceLengths": [1]}], "inp": {"texts": "[\"Take\", \"care\", \"of\"]", "from": "en", "options": "null", "to": "zh-CHS"}},
                {"outp": [{"TranslatedText": "\u96c6\u5408", "From": "en", "OriginalTextSentenceLengths": [10], "TranslatedTextSentenceLengths": [2]}], "inp": {"texts": "[\"Collection\"]", "from": "en", "options": "null", "to": "zh-CHS"}},
              ],

    #"" : [dict(inp = , outp = ),],
    #"" : [dict(inp = , outp = ),],
}

class MyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    email_count = 1

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
            if not path.count(key) :
                continue

            found = False
            for pair in mock_rest[key] :
                if url_parameters != pair["inp"] :
                    #tlog("  " + str(url_parameters) + " != " + str(pair["inp"]))
                    continue

                #tlog("  MOCKING: " + key + ": " + str(url_parameters))
                found = True
                body = json_dumps(pair["outp"])
                break

            if not found :
                tlog("  WARNING. NEVER Seen this input: " + str(url_parameters))
                continue

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

        #tlog("  " + str(path) + ": " + str(url_parameters))

        body = sdict(success = True, test_success = True)

        if path in parameters["oauth"].keys() :
            #tlog("  TOKEN REQUEST from: " + path)
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
            tlog("  Error")

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
        #tlog("  " + str(path) + ": " + str(url_parameters))

        result = 200
        result_msg = "OK"

        body = sdict(success = True, test_success = True)

        if path in parameters["oauth"].keys() :
            body_dict = {}

            if "email_key" in parameters["oauth"][path] and parameters["oauth"][path]["email_key"] :
                recursiveSetInDict(body_dict, parameters["oauth"][path]["email_key"].split(","), path + str(MyHandler.email_count) + "@holymother.com")
                MyHandler.email_count += 1

            if "verified_key" in parameters["oauth"][path] and parameters["oauth"][path]["verified_key"] :
                body_dict[parameters["oauth"][path]["verified_key"]] = True
                recursiveSetInDict(body_dict, parameters["oauth"][path]["verified_key"].split(","), True)
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

def change_timeout(timeout) :
    tlog("Changing timeout to " + str(timeout))
    s = requests.Session()
    r = s.post(couch + "/_session", data = {"name" : parameters["admin_user"], "password" : parameters["admin_pass"]}, verify = couch_verify)
    if r.status_code not in [200, 201] :
        raise Exception("Failed to login for timeout change")

    r = s.get(couch + "/_config", verify = couch_verify)

    if r.status_code not in [200, 201] :
        raise Exception("Failed to lookup configuration")

    config = r.json()

    r = s.put(couch + "/_config/couch_httpd_auth/timeout", data = "\"" + str(timeout) + "\"", verify = couch_verify)

    if r.status_code not in [200, 201] :
        raise Exception("Failed to change timeout to " + str(timeout) + " seconds" + ": " + str(r.status_code) + ": " + r.text)

    # Old timeout is returned
    return r.text

def oauth_responder(httpd_server) :
    sa = httpd_server.socket.getsockname()
    tlog("Serving HTTP on", sa[0], "port", sa[1], "...")
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
        tlog("Unable to connect to " + protocol + " port " + str(port) + " on host " + hostname + " => " + str(msg))
        sock.close()
        sock = None
        return False

def cleanup(name) :
    try :
        details = c.inspect_container(name)
        if details["State"]["Running"] :
            tlog("Stopping: " + name)
            c.kill(name)
        tlog("Removing: " + name)
        c.remove_container(name)
    except docker.errors.NotFound, e :
        tlog("No container to cleanup: " + name)

def move_data_to_url(url) :
    temp_url = url["loc"]
    first = True
    if "data" in url :
        for key in url["data"].keys() :
            temp_url += ("&" if not first else "?" ) + key + "=" +  str(url["data"][key])
            if first :
                first = False

    return temp_url

def flatten(head_url) :
    flat_urls = []
    if isinstance(head_url, list) :
        for sub_url in head_url :
            flat_urls.append(sub_url)
    else :
        flat_urls.append(head_url)
    return flat_urls

def run_tests(test_urls) :
    # Flatten the nested test groups into a single list of tests
    flat_urls = []
    for head_url in test_urls :
        flatcount = 1

        if "repeat" in head_url :
            for x in range(0, head_url["repeat"]) :
                for sub_url in flatten(head_url["urls"]) :
                    flat_urls += flatten(sub_url)
        else :
            flat_urls += flatten(head_url)


    tlog("Tests: " + str(len(flat_urls)))
    stop_test = False
    last_json = {}
    try:
        for tidx in range(0, len(flat_urls)) :
            url = flat_urls[tidx]
            if "stop" in url and url["stop"] :
                tlog("Stop requested.")
                stop_test = True
                break

            start = timest()

            job_was_running = False

            if "data" in url :
                fkeys = ["uuid"] if "upload" not in url else []
                if "forward_keys" in url :
                    for key in url["forward_keys"] :
                        if key not in fkeys :
                            fkeys.append(key)

                for key in fkeys :
                    dest_key = key
                    if key.count("/") :
                        dest_key = key.split("/")[1]
                        key = key.split("/")[0]

                    if key in last_json and key not in url["data"] :
                        if key != "uuid" :
                            tlog("  Updating key " + str(dest_key) + " in data with value: " + last_json[key])
                        url["data"][dest_key] = last_json[key]

            finaldest = target if ("couch" not in url or not url["couch"]) else couch
            verify = target_verify if ("couch" not in url or not url["couch"]) else couch_verify
            secs = int(time()) - start_time
            tlogmsg = "Test (@" + str(secs) + ") " + str(tidx) + "/" + str(len(flat_urls)) + ": " + url["method"].upper() + ": " + (url["loc"].replace("/api?human=0&alien=", "").replace("&", ", ").replace("=", " = ").replace("&", ", ") if "loc" in url else "nowhere") + ", data: " + (str(url["data"]) if "data" in url else "none")
            tlog(tlogmsg)

            record.write(tlogmsg + "\n")
            record.flush()

            retry_attempts = 0
            until_attempts = 0

            while retry_attempts < 3 and until_attempts < 30 :
                if "sleep" in url :
                    tlog("  Sleeping for " + str(url["sleep"]) + " seconds...")
                    sleep(url["sleep"])
                    break

                if url["method"] == "get" :
                    udest = finaldest + move_data_to_url(url)
                    r = s.get(udest, verify = verify)
                elif url["method"] == "post" :
                    udest = finaldest + url["loc"]
                    r = s.post(udest, data = url["data"], verify = verify)
                elif url["method"] == "put" :
                    if "upload" in url :
                        fname = cwd + 'example_stories/' + url["upload"]
                        tlog("  Uploading file: " + fname)
                        udest = finaldest + move_data_to_url(url)
                        r = s.put(udest, headers = {'content-type': url["upload_type"]}, data = open(fname, 'rb').read(), verify = verify)
                    else :
                        udest = finaldest + url["loc"]
                        r = s.put(udest, data = json_dumps(url["data"]), verify = verify)
                stop = timest()

                if r.status_code not in [200, 201] :

                    if r.status_code == 504 :
                        tlog("  Gateway timeout to: " + udest + ", Try the request again...")
                        retry_attempts += 1
                        run_tests(common_urls["relogin"])
                        continue

                    if r.status_code == 401 :
                        tlog("  Our token may have expired. Login again and retry the test.")
                        if "retry_action" in url :
                            run_tests(common_urls[url["retry_action"]])
                        else :
                            run_tests(common_urls["relogin"])
                        retry_attempts += 1

                        continue

                    tlog("  Bad status code: " + str(r.status_code) + ": " + r.text)
                    assert(False)
                else :
                    retry_attempts = 0
                    until_attempts = 0

                # The difference between 'success' and 'test_success' is for errors
                # that happen during tests which are tolerable in the user experience.
                # For example, if the translation API can't reach the internet, the
                # UI will just return that connectivity information to the user, but
                # it does not mean there's a failure in the system. But, it is indeed
                # a unit test failure, so we need to know about it and check for it.
                try :
                    j = json_loads(r.text)
                    last_json = j
                except ValueError, e :
                    #tlog("  Failed to parse JSON from: " + r.text)
                    tlog("  Failed to parse JSON.")
                    assert(False)

                if "job_running" in j and j["job_running"] and ("check_job_running" not in url or url["check_job_running"]):
                    if not job_was_running :
                        tlog("  There is a job running. Come back later.")
                    job_was_running = True
                    sleep(5)
                    continue

                if "until" in url :
                    v = getFromDict(j, url["until"]["path"])
                    if v != url["until"]["equals"] :
                        tlog("  Until " + str(v) + " != " + url["until"]["equals"])
                        sleep(5)
                        until_attempts += 1
                        continue

                diff = stop - start
                #tlog("  Time: " + str(int(diff)) + " secs.")

                if "success" in url and url["success"] is not None :
                    assert("success" in j)
                    if j["success"] != url["success"] :
                        tlog("Success failed. Requested: " + str(url["success"]) + ", Got: " + str(j["success"]))
                        assert(False)
                if "test_success" in url and url["test_success"] is not None :
                    assert("test_success" in j)
                    if j["test_success"] != url["test_success"] :
                        tlog("  Test Success failed. Requested: " + str(url["test_success"]) + ", Got: " + str(j["test_success"]))
                        assert(False)

                break

            if retry_attempts >= 3 :
                tlog(" Failed to retry last run after 3 attempts.")
                assert(False)

            if until_attempts >= 30 :
                tlog(" Failed to retry last run after 3 attempts.")
                stop_test = True
                assert(False)

    except KeyboardInterrupt:
        tlog("CTRL-C interrupt")

    return stop_test

c = Client(base_url = test["docker_base_url"], version = test["docker_api_version"])
s = requests.Session()

options = []

if test["start_jabber"] :
    options.append(
    dict(
        image = test["jabber_container"],
        command = ['/home/mrhines/mica/restart.sh'],
        hostname = 'jabber',
        name = test["jabber_name"],
        tty = True,
        ports = [5280, 22, 5222, 5223, 5281],
        host_config = c.create_host_config(port_bindings = {
                "22/tcp":   ("0.0.0.0", 4444),
                "5222/tcp": ("0.0.0.0", 5222),
                "5223/tcp": ("0.0.0.0", 5223),
                "5280/tcp": ("0.0.0.0", 5280),
                "5281/tcp": ("0.0.0.0", 5281),
        })
    )
)

options.append(
    dict(
        image = test["couch_container"],
#        command = ['couchdb'],
        command = ["/bin/bash", "-c", "(/home/mrhines/mica/restart.sh &); bash"],
        name = test["couch_name"],
        tty = True,
        ports = [5984, 22, 6984, 7984],
        volumes = [ "/usr/local/var/log/couchdb" ],
        host_config = c.create_host_config(port_bindings = {
                "5984/tcp": ("0.0.0.0", 5985),
                "22/tcp":   ("0.0.0.0", 6222),
                #"6984/tcp": ("0.0.0.0", 6984),
                #"7984/tcp": ("0.0.0.0", 7984),
        }, binds = [
                cwd + "../logs:/usr/local/var/log/couchdb",
            ]
        )
    )
)

def wait_for_port_ready(name, proto, hostname, port) :
    targ = proto + "://" + hostname
    tlog("Checking " + hostname + ":" + str(port))

    while True :
        if check_port(hostname, port) :
            try :
                r = s.get(targ + ":" + str(port), verify = True if proto == "http" else False)
                tlog("Container " + name + " ready.")
                break
            except requests.exceptions.ConnectionError, e :
                tlog("Container " + name + " not ready: " + str(e) + ". Waiting...")
        else :
            tlog("Port not open yet. Waiting...")

        sleep(1)

    tlog("Check complete.")

for option in options :
    cleanup(option["name"])
    tlog("Creating container: " + option["name"])
    details = c.create_container(**option)
    tlog("Creation complete.")
    c.start(option["name"])
    port = option["ports"][0]
    hostname = c.inspect_container(option["name"])["NetworkSettings"]["IPAddress"]
    #hostname = parameters["couch_server"]

    wait_for_port_ready(option["name"], "http", hostname, port)

if len(sys.argv) > 1 and sys.argv[1] == "stop" :
    tlog("Containers are created. Stopping now.")
    exit(0)

urls = []
if "test" not in parameters or not parameters["test"] :
    parameters["trans_scope"] = "http://localhost:" + str(server_port) + "/TranslatorRequest"
    parameters["trans_access_token_url"] = "http://localhost:" + str(server_port) + "/TranslatorAccess"

httpd = TimeoutServer(('127.0.0.1', server_port), MyHandler)
oresp = Thread(target=oauth_responder, args = [httpd])
oresp.daemon = True
oresp.start()

parameters["timeout"] = test_timeout * 2

#parameters["multipliers"] = { "days" : 7, "weeks" : 4, "months" : 12, "years" : 10, "decades" : 10 }
#parameters["counts"] = { "days" : 1, "weeks" : 7, "months" : 30, "years" : 365, "decades" : 3650 }
#parameters["seconds_in_day"] = 60*60*24

mthread = Thread(target=go, args = [parameters])
mthread.daemon = True
mthread.start()

wait_for_port_ready("mica", test["target_proto"], test["target"], test["target_port"])
tlog("Waiting for startup...")
sleep(10)
r = s.get(target + "/disconnect", verify = target_verify)
assert(r.status_code == 200)
r = s.get(target, verify = target_verify)
assert(r.status_code == 200)

d = pq(s.get(target, verify = target_verify).text)

def add_oauth_tests_from_micadev10() :
    for who in parameters["oauth"].keys() :
        if who == "redirect" :
            continue

        #tlog("Checking for: " + who + ": " + d("#oauth_" + who).html())
        for part in d("#oauth_" + who).attr("href").split("&") :
            if part.count("state") :
                state = part.split("=")[1]
                #tlog("Need to test " + who + ", state: " + state)
                oauth["states"][who] = state
                oauth["codes"][who] = binascii_hexlify(os_urandom(4))
                urls.append(common_urls["logout"])
                urls.append(dict(loc = "/api?human=0&alien=" + who + "&connect=1&finish=1&state=" + state + "&code=" + oauth["codes"][who], method = "get", data = {}, success = True, test_success = True, retry_action = "logout"))
                parameters["oauth"][who]["token_url"] = "http://localhost:" + str(server_port) + "/" + who
                parameters["oauth"][who]["lookup_url"] = "http://localhost:" + str(server_port) + "/" + who
                urls.append(common_urls["logout"])
                break


common_urls = {
                "storylist" :
                    { "loc" : "/api?human=0&alien=storylist&tzoffset=18000", "method" : "get", "success" :  True, "test_success" : True },

                "storylist_rotate" :
                    { "loc" : "/api?human=0&alien=storylist&tzoffset=18000&force_rotate=1", "method" : "get", "success" :  True, "test_success" : True },

                "storylist_triple" : [
                    { "loc" : "/api?human=0&alien=storylist&tzoffset=18000", "method" : "get", "success" :  True, "test_success" : True },
                    { "loc" : "/api?human=0&alien=storylist&tzoffset=18000", "method" : "get", "success" :  True, "test_success" : True },
                    { "loc" : "/api?human=0&alien=storylist&tzoffset=18000", "method" : "get", "success" :  True, "test_success" : True },
                ],

                "logout" :
                    { "loc" : "/api?human=0&alien=disconnect", "method" : "get", "success" : True, "test_success" :  True },

                "login" :
                    { "loc" : "/connect", "method" : "post", "success" :  True, "test_success" : True, "data" : dict(human='0', username=test["username"], password=test["password"], remember='on', address=parameters["couch_proto"] + "://" + parameters["couch_server"] + ":" + str(parameters["couch_port"]), connect='1') },

                "relogin" : [
                    { "loc" : "/api?human=0&alien=disconnect", "method" : "get", "success" : True, "test_success" :  True },
                    { "loc" : "/connect", "method" : "post", "success" :  True, "test_success" : True, "data" : dict(human='0', username=test["username"], password=test["password"], remember='on', address=parameters["couch_proto"] + "://" + parameters["couch_server"] + ":" + str(parameters["couch_port"]), connect='1') },
                ],
                "account" :
                    { "loc" : "/api?human=0&alien=account", "method" : "get", "success" : True, "test_success" :  True },
            }


def init_and_translate(storyname) :
    return [
        # Need to retrieve the UUID again for the story initialization.
        { "loc" : "/mica/MICA:family@hinespot.com:stories:" + storyname, "method" : "get", "success" : None, "test_success" :  None, "couch" : True},
        { "loc" : "/api", "method" : "get", "success" : True, "test_success" : True, "data" : dict(human = 0, alien = "home", storyinit = 1, name = storyname), "check_job_running" : False},
    ] + common_urls["storylist_triple"] + [
        # This get is only to retrieve the UUID again for the story initialization.
        { "loc" : "/mica/MICA:family@hinespot.com:stories:" + storyname, "method" : "get", "success" : None, "test_success" :  None, "couch" : True},
        { "loc" : "/api", "method" : "get", "success" : True, "test_success" : True, "data" : dict(human = 0, alien = "home", translate = 1, name = storyname), "check_job_running" : False},
        { "loc" : "/api", "method" : "get", "success" : True, "test_success" : True, "data" : dict(human = 0, alien = "read", tstatus = 1), "check_job_running" : False, "until" : { "path" : ["translated", "translating"], "equals" : "no"}},
        { "loc" : "/api", "method" : "get", "success" : True, "test_success" : True, "data" : dict(human = 0, alien = "read", tstatus = 1), "check_job_running" : False},
        { "loc" : "/api", "method" : "get", "success" : True, "test_success" : True, "data" : dict(human = 0, alien = "home", reviewed = 1), "check_job_running" : False},
        { "loc" : "/api", "method" : "get", "success" : True, "test_success" : True, "data" : dict(human = 0, alien = "home", reviewed = 0), "check_job_running" : False},
        { "loc" : "/api", "method" : "get", "success" : True, "test_success" : True, "data" : dict(human = 0, alien = "home", reviewed = 1), "check_job_running" : False},
        { "loc" : "/api", "method" : "get", "success" : True, "test_success" : True, "data" : dict(human = 0, alien = "home", finished = 1), "check_job_running" : False},
        { "loc" : "/api", "method" : "get", "success" : True, "test_success" : True, "data" : dict(human = 0, alien = "home", finished = 0), "check_job_running" : False},
        { "loc" : "/api", "method" : "get", "success" : True, "test_success" : True, "data" : dict(human = 0, alien = "home", finished = 1), "check_job_running" : False},
    ] + common_urls["storylist_triple"]

def file_story(filename, languagetype, filetype, mimetype) :
    return [
           { "loc" : "/api?human=0&alien=home", "method" : "post", "success" : True, "test_success" :  True, "data" : dict(filetype = filetype, filename = filename, languagetype = languagetype, uploadfile = "1") },

           { "loc" : "/mica/MICA:family@hinespot.com:stories:" + filename, "method" : "get", "success" : None, "test_success" :  None, "couch" : True},

           { "loc" : "/mica/MICA:family@hinespot.com:stories:" + filename + "/" + filename, "method" : "put", "success" : None, "test_success" :  None, "upload" : filename, "upload_type" : mimetype, "forward_keys" : ["_rev/rev"], "data" : {}, "couch" : True},

        ] + common_urls["storylist_triple"]

def txt_story(storyname, languagetype, source) :

    return [
        { "loc" : "/api?human=0&alien=home", "method" : "post", "success" : True, "test_success" :  True, "data" : dict(storyname = storyname, languagetype = languagetype, uploadtext = "1") },
        { "loc" : "/mica/MICA:family@hinespot.com:stories:" + storyname, "method" : "get", "success" : None, "test_success" :  None , "couch" : True},
        { "loc" : "/mica/MICA:family@hinespot.com:stories:" + storyname + "?authorization=false", "method" : "put", "success" : None, "test_success" :  None, "data" : {"_id" : "MICA:family@hinespot.com:stories:" + storyname, "format" : 2, "filetype" : "txt", "source_language" : languagetype.split(",")[1], "reviewed": False, "date" : 1449946344.440684, "nb_pages" : 0, "name" : storyname, "translated": False, "new" : True, "target_language" : languagetype.split(",")[0], "txtsource" : "从前有个小孩，爸爸死了，妈妈病了，日子可不好过了。"}, "forward_keys" : ["_rev"], "couch" : True},

    ] + common_urls["storylist_triple"]


try :
    tests_from_micadev10 = [
                common_urls["logout"],

                { "loc" : "/connect", "method" : "post", "success" : False, "test_success" : False, "data" : dict(human='0', username=test["username"], password="wrongpassword", remember='on', address=couch, connect='1') },

                common_urls["login"],
                common_urls["storylist"],
                common_urls["storylist_rotate"],
                { "repeat" : 40, "urls" : [
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
                    { "loc" : "/api?human=0&alien=home&view=1", "method" : "get", "success" :  True, "test_success" :  True },
                    { "loc" : "/api?human=0&alien=home&switchmode=text", "method" : "get", "success" :  True, "test_success" :  True },
                    { "loc" : "/api?human=0&alien=home&view=1&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&page=0", "method" : "get", "success" :  True, "test_success" :  True },
                    { "loc" : "/api?human=0&alien=read&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&reviewlist=1&page=0", "method" : "get", "success" :  True, "test_success" :  True },
                    { "loc" : "/api?human=0&alien=home&view=1&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&multiple_select=1&index=1&nb_unit=12&trans_id=10&page=0", "method" : "get", "success" :  True, "test_success" :  True },
                    { "loc" : "/api?human=0&alien=home&view=1&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&multiple_select=1&index=1&nb_unit=48&trans_id=42&page=0", "method" : "get", "success" :  True, "test_success" :  True },
                    { "loc" : "/api?human=0&alien=home", "method" : "post", "success" :  True, "test_success" :  True, "data" : dict(retranslate = '1', page = '0', uuid = 'b220074e-f1a7-417b-9f83-e63cebea02cb') },
                # Assert that the default has changed and move multiple_select to actual JSON, then retry the request
                    { "loc" : "/api?human=0&alien=edit&view=1", "method" : "get", "success" :  True, "test_success" :  True },
                    { "loc" : "/api?human=0&alien=edit&view=1&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&page=0", "method" : "get", "success" :  True, "test_success" :  True },
                    { "loc" : "/api?human=0&alien=edit&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&editslist=1&page=0", "method" : "get", "success" :  True, "test_success" :  True },
                    ]
                },

                { "loc" : "/api?human=0&alien=edit", "method" : "post", "success" : True, "test_success" :  True, "data" : dict(oprequest = '[{"operation":"split","uuid":"b220074e-f1a7-417b-9f83-e63cebea02cb","units":1,"failed":false,"chars":"小鸟","pinyin":"xiǎo+niǎo","nbunit":"8","uhash":"0b23c772194ef5a97aa23d5590105665","index":"-1","pagenum":"0","out":""},{"operation":"merge","uuid":"b220074e-f1a7-417b-9f83-e63cebea02cb","units":2,"failed":false,"chars":"跳","pinyin":"tiào","nbunit0":"45","uhash0":"0cdbc17e9ed386e3f3df2b26ed5b5187","index0":"-1","page0":"0","chars0":"跳","pinyin0":"tiào","nbunit1":"46","uhash1":"0cdbc17e9ed386e3f3df2b26ed5b5187","index1":"-1","page1":"0","chars1":"跳","pinyin1":"tiào","out":""}]', uuid = "b220074e-f1a7-417b-9f83-e63cebea02cb") },
               { "loc" : "/api?human=0&alien=edit", "method" : "post", "success" : True, "test_success" :  True, "data" : dict(oprequest = '[{"operation":"split","uuid":"b220074e-f1a7-417b-9f83-e63cebea02cb","units":1,"failed":false,"chars":"山羊","pinyin":"shān+yáng","nbunit":"111","uhash":"fb7335cbba25395d3b9a867ddad630fd","index":"-1","pagenum":"0","out":""}]', uuid = "b220074e-f1a7-417b-9f83-e63cebea02cb") },

               # Bulk review: not tested
               #{ "loc" : "/api?human=0&alien=read&uuid=37d4bcbb-752f-4a83-8ded-336554d503b9&reviewlist=1&page=128", "method" : "get", "success" : True, "test_success" :  True },
               #{ "loc" : "/api?human=0&alien=home", "method" : "post", "success" : True, "test_success" :  True, "data" : dict(transid0 = 67, index0 = 1, nbunit0 = 75, page0 = 151, transid1 = 74, index1 = 1, nbunit1 = 84, page1 = 151, transid2 = 81, index2 = 1, nbunit2 = 93, page2 = 151, transid3 = 88, index3 = 1, nbunit3 = 102, page3 = 151, transid4 = 105, index4 = 1, nbunit4 = 123, page4 = 151, count = 5, bulkreview = 1) },
               #{ "loc" : "/api?human=0&alien=read&uuid=37d4bcbb-752f-4a83-8ded-336554d503b9&reviewlist=1&page=151", "method" : "get", "success" : True, "test_success" :  True },
               { "repeat" : 40, "urls" : [
                   # Switch to split view on sample
                   { "loc" : "/api?human=0&alien=read&uuid=37d4bcbb-752f-4a83-8ded-336554d503b9&reviewlist=1&page=151", "method" : "get", "success" : True, "test_success" :  True },
                   { "loc" : "/api?human=0&alien=home&view=1&uuid=37d4bcbb-752f-4a83-8ded-336554d503b9&page=151", "method" : "get", "success" : True, "test_success" :  True },
                   { "loc" : "/api?human=0&alien=read&uuid=37d4bcbb-752f-4a83-8ded-336554d503b9&reviewlist=1&page=151", "method" : "get", "success" : True, "test_success" :  True },
                   { "loc" : "/api?human=0&alien=home&switchmode=both", "method" : "get", "success" : True },
                   { "loc" : "/api?human=0&alien=home&view=1&uuid=37d4bcbb-752f-4a83-8ded-336554d503b9&page=151&image=0", "method" : "get", "success" : True, "test_success" :  True },

                    # Switch to image-only

                   { "loc" : "/api?human=0&alien=home&switchmode=images", "method" : "get", "success" : True, "test_success" :  True },
                   { "loc" : "/api?human=0&alien=home&view=1&uuid=37d4bcbb-752f-4a83-8ded-336554d503b9&page=151&image=0", "method" : "get", "success" : True, "test_success" :  True },
                   { "loc" : "/api?human=0&alien=read&uuid=37d4bcbb-752f-4a83-8ded-336554d503b9&reviewlist=1&page=151", "method" : "get", "success" : True, "test_success" :  True },

                   # Switch back to text-only

                   { "loc" : "/api?human=0&alien=home&view=1&uuid=37d4bcbb-752f-4a83-8ded-336554d503b9&page=151", "method" : "get", "success" : True, "test_success" :  True },
                   { "loc" : "/api?human=0&alien=read&uuid=37d4bcbb-752f-4a83-8ded-336554d503b9&reviewlist=1&page=151", "method" : "get", "success" : True, "test_success" :  True },
                   { "loc" : "/api?human=0&alien=home&switchmode=badviewmode", "method" : "get", "success" : False, "test_success" :  False },
                   { "loc" : "/api?human=0&alien=home&switchmode=text", "method" : "get", "success" : True, "test_success" :  True },

                    # Go to page 35
                   { "loc" : "/api?human=0&alien=home&view=1&uuid=37d4bcbb-752f-4a83-8ded-336554d503b9&page=34", "method" : "get", "success" : True, "test_success" :  True },
                   { "loc" : "/api?human=0&alien=read&uuid=37d4bcbb-752f-4a83-8ded-336554d503b9&reviewlist=1&page=34", "method" : "get", "success" : True, "test_success" :  True },

                   # Go to last page
                   { "loc" : "/api?human=0&alien=home&view=1&uuid=37d4bcbb-752f-4a83-8ded-336554d503b9&page=239", "method" : "get", "success" : True, "test_success" :  True },
                   { "loc" : "/api?human=0&alien=read&uuid=37d4bcbb-752f-4a83-8ded-336554d503b9&reviewlist=1&page=239", "method" : "get", "success" : True, "test_success" :  True },

                    # Go one page past the end
                    # Javascript won't let us do this, but I might screw up
                    # Will cause a replication error, requiring us to re-login
                   { "loc" : "/api?human=0&alien=home&view=1&uuid=37d4bcbb-752f-4a83-8ded-336554d503b9&page=240", "method" : "get", "success" : False, "test_success" :  False },

                    common_urls["login"],

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

                   { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : False, "test_success" :  False, "data" : dict(remove=0, tofrom='nosuchdictionary') },

                   { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "test_success" :  False, "data" : dict(email = "whoops2@whoops.com", username = "whoops2@whoops.com", password = "short", confirm = "short", newaccount = "password") },
                   { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "test_success" :  False, "data" : dict(email = "whoops2@whoops.com", username = "whoops2@whoops.com", password = "verylongpass", confirm = "notsame", newaccount = "password") },
                   { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "test_success" :  False, "data" : dict(email = "whoops2@whoops.com", username = "whoops2@whoops.com", password = "verylongpass", confirm = "notsame", newaccount = "password") },
                   { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "test_success" :  False, "data" : dict(email = "whoop2@whoops.com", username = "bad:username", password = "verylongpass", confirm = "verylongpass", newaccount = "password") },

                   { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "test_success" :  True, "data" : dict(email = "whoops2@whoops.com", username = "whoops2@whoops.com", password = "verylongpass", confirm = "verylongpass", newaccount = "password") },

                   { "loc" : "/api?human=0&alien=account&deleteaccount=1&username=nosuchaccount", "method" : "get", "success" : False, "test_success" :  True },

                   { "loc" : "/api?human=0&alien=account&deleteaccount=1&username=whoops2@whoops.com", "method" : "get", "success" : True, "test_success" :  True },
                   ]
               # end of repeated section
               },

               { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "test_success" :  True, "data" : dict(email = "whoops3@whoops.com", username = "whoops3@whoops.com", password = "verylongpass", confirm = "verylongpass", newaccount = "password") },

               { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "test_success" :  False, "data" : dict(email = "whoops3@whoops.com", username = "whoops3@whoops.com", password = "verylongpass", confirm = "verylongpass", newaccount = "password") },

               { "loc" : "/api?human=0&alien=account&pack=1", "method" : "get", "success" : True, "test_success" :  True },

               { "loc" : "/api?human=0&alien=account", "method" : "get", "success" : True, "test_success" :  True },

               { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "test_success" :  False, "data" : dict(oldpassword = test["password"], password = "short", confirm = "short", changepassword = "1") },

               { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "test_success" :  False, "data" : dict(oldpassword = test["password"], password = "notthesame", confirm = "foobarbaz", changepassword = "1") },

               { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "test_success" :  False, "data" : dict(oldpassword = "wrongoldpassword", password = "foobarbaz", confirm = "foobarbaz", changepassword = "1") },

               { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "test_success" :  True, "data" : dict(oldpassword = test["password"], password = "foobarbaz", confirm = "foobarbaz", changepassword = "1") },

               { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "test_success" :  True, "data" : dict(oldpassword = "foobarbaz", password = test["password"], confirm = test["password"], changepassword = "1") },

               { "loc" : "/api?human=0&alien=account&resetpassword=1", "method" : "get", "success" : True, "test_success" :  True },

               { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "test_success" :  True, "data" : dict(password = test["password"], confirm = test["password"], changepassword = "1"), "forward_keys" : ["oldpassword"] },

               { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : False, "test_success" :  False, "data" : dict(language = 'badlanguage', changelanguage = '1') },

               { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "test_success" :  True, "data" : dict(language = 'en', changelanguage = '1') },

               { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : False, "test_success" :  False, "data" : dict(learnlanguage = 'badlanguage', changelearnlanguage = '1') },

               { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "test_success" :  True, "data" : dict(learnlanguage = 'py', changelearnlanguage = '1') },

               { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "test_success" :  True, "data" : dict(learnlanguage = 'zh', changelearnlanguage = '1') },

               { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "test_success" :  False, "data" : dict(email = 'waaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaytoolong@email.com', changeemail = '1') },

               { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "test_success" :  False, "data" : dict(email = 'email withspace@email.com', changeemail = '1') },

               { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "test_success" :  False, "data" : dict(email = 'emailwithoutatsymbol', changeemail = '1') },

               { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "test_success" :  True, "data" : dict(email = 'normal@email.com', changeemail = '1') },

               { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "test_success" :  False, "data" : dict(setappchars = '1001') },
               { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "test_success" :  False, "data" : dict(setappchars = '1') },
               { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : False, "test_success" :  False, "data" : dict(setappchars = 'notanumber') },
               { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "test_success" :  True, "data" : dict(setappchars = '70') },

               { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "test_success" :  False, "data" : dict(setwebchars = '1001') },
               { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "test_success" :  False, "data" : dict(setwebchars = '1') },
               { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : False, "test_success" :  False, "data" : dict(setwebchars = 'notanumber') },
               { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "test_success" :  True, "data" : dict(setwebchars = '70') },

               { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "test_success" :  False, "data" : dict(setwebzoom = '3.1') },
               { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "test_success" :  False, "data" : dict(setwebzoom = '0.4') },
               { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : False, "test_success" :  False, "data" : dict(setwebzoom = 'notanumber') },
               { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "test_success" :  True, "data" : dict(setwebzoom = '1.0') },

               { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "test_success" :  False, "data" : dict(setappzoom = '3.1') },
               { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "test_success" :  False, "data" : dict(setappzoom = '0.4') },
               { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : False, "test_success" :  False, "data" : dict(setappzoom = 'notanumber') },
               { "loc" : "/api?human=0&alien=account", "method" : "post", "success" : True, "test_success" :  True, "data" : dict(setappzoom = '1.0') },

               common_urls["account"],

               { "repeat" : 10, "urls" : [
                   { "sleep" : test_timeout * 2,  "loc" : "sleep", "method" : "none" },
                   common_urls["login"],
                   ]
               },


               txt_story("chinese_test", "zh-CHS,en", "从前有个小孩，爸爸死了，妈妈病了，日子可不好过了。"),
               init_and_translate("chinese_test"),

               txt_story("english_test", "en,zh-CHS", "this is a test"),
               init_and_translate("english_test"),

               file_story("asample1.pdf", "zh-CHS,en", "pdf", "application/pdf"),
               init_and_translate("asample1.pdf"),

               file_story("family.txt", "zh-CHS,en", "txt", "text/plain"),
               init_and_translate("family.txt"),

               file_story("asample2.txt", "zh-CHS,en", "txt", "text/plain"),
               init_and_translate("asample2.txt"),

               file_story("bao.txt", "zh-CHS,en", "txt", "text/plain"),
               init_and_translate("bao.txt"),

               file_story("book1234.txt", "zh-CHS,en", "txt", "text/plain"),
               init_and_translate("book1234.txt"),

               file_story("little_bear.txt", "zh-CHS,en", "txt", "text/plain"),
               init_and_translate("little_bear.txt"),

               file_story("little_bird.txt", "zh-CHS,en", "txt", "text/plain"),
               init_and_translate("little_bird.txt"),

               # Tests that cause purges and long map reduces.
               { "loc" : "/api?human=0&alien=home&forget=1&uuid=5989087e-6896-4653-b91e-d6422d6b369a", "method" : "get", "success" : True, "test_success" :  True, "check_job_running" : False },

               common_urls["storylist_triple"],

               { "loc" : "/api?human=0&alien=home&delete=1&uuid=5989087e-6896-4653-b91e-d6422d6b369a&name=bao_gong_interrogates_a_rock.txt", "method" : "get", "success" : True, "test_success" :  True, "check_job_running" : False },

               common_urls["storylist_triple"],

               common_urls["relogin"],

               { "repeat" : 2, "urls" : [
                   { "sleep" : test_timeout * 2,  "loc" : "sleep", "method" : "none" },
                   common_urls["login"],
                   ]
               },

               # Long-running, but excellent test to delete a large story:
               { "loc" : "/api?human=0&alien=home&forget=1&uuid=37d4bcbb-752f-4a83-8ded-336554d503b9", "method" : "get", "success" : True, "test_success" :  True, "check_job_running" : False },

               common_urls["storylist_triple"],

               { "loc" : "/api?human=0&alien=home&delete=1&uuid=37d4bcbb-752f-4a83-8ded-336554d503b9&name=301_book1.pdf", "method" : "get", "success" : True, "test_success" :  True, "check_job_running" : False },

               common_urls["storylist_triple"],
               common_urls["relogin"],

               { "repeat" : 2, "urls" : [
                   { "sleep" : test_timeout * 2,  "loc" : "sleep", "method" : "none" },
                   common_urls["login"],
                   ]
               },

               # TODO:
               # Test bulk edits
               # Test parallel requests of everything
               # Audit usage of "success"
               # Test quotas

           #   { "stop" : True },
            ]
except Exception, e :
    tlog(str(e))

def add_chat_tests_from_micadev10() :
    chatfname = cwd + 'chats.txt'
    chatfd = open(chatfname, 'r')
    tlog("Reading in chat tests...")
    #urls.append(common_urls["relogin"])
    while True :
        line = chatfd.readline().strip()
        if not line :
            break
        if line == "storylist" :
            urls.append(common_urls["storylist_rotate"])
        elif line.count("source=") :
            urls.append({"loc" : "/api?" + line, "method" : "get", "success" : None, "test_success" : True})
        else :
            urls.append({"loc" : "/api?" + line, "method" : "get", "success" : True, "test_success" : True})

    chatfd.close()
    urls.append(common_urls["storylist_rotate"])
    #urls.append(common_urls["logout"])
    #urls.append({ "stop" : True })


try :
    for x in range(0, 100) :
        add_oauth_tests_from_micadev10()
    urls += tests_from_micadev10
    add_chat_tests_from_micadev10()
    sleep(5)

    urls.append(common_urls["logout"])
    urls.append({ "stop" : True })

    old_timeout = int(change_timeout(6)[1:-2])
except Exception, e :
    tlog(str(e))

stop = True
good = True
try :
    stop = run_tests(urls)
except AssertionError, e :
    good = False
except Exception, e :
    for line in format_exc().splitlines() :
        tlog(line)
    #pass

change_timeout(604800)
#change_timeout(old_timeout)

record.close()
httpd.socket.close()

if not stop :
    try:
        secs = int(time()) - start_time
        tlog("Done in " + str(secs) + " secs. Application left running...")
        while True :
            sleep(10)
    except KeyboardInterrupt:
        tlog("CTRL-C interrupt")

exit(0 if good else 1)
