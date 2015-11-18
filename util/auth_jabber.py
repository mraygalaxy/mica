#!/usr/bin/python
# coding: utf-8

import sys, os, fcntl
from os import path as os_path
from re import compile as re_compile, IGNORECASE as re_IGNORECASE, sub as re_sub
from struct import *
from subprocess import *
from urllib2 import quote as urllib2_quote, Request as urllib2_Request, urlopen as urllib2_urlopen, URLError as urllib2_URLError, HTTPError as urllib2_HTTPError, unquote as urllib2_unquote
from urllib import urlencode as urllib_urlencode
from time import sleep
from sys import getdefaultencoding

cwd = re_compile(".*\/").search(os_path.realpath(__file__)).group(0)
import sys
sys.path = [cwd, cwd + "../"] + sys.path

from params import parameters
from crypticle import *

log = open("/var/log/ejabberd/auth-filter.log",'a+b',0)

try :
    jabber_crypt = Crypticle(parameters["jabber_auth"])
except Exception, e :
    log.write("Goddamnit: " + str(e))
    exit(1)

if getdefaultencoding() != "utf-8" :
    log.write("Correcting the default encoding back to UTF-8 from " + getdefaultencoding() + "\n")
    reload(sys).setdefaultencoding("utf-8")

def myquote(val):
    if isinstance(val, unicode) :
        val_unquoted = urllib2_quote(val.encode("utf-8"))
    else :
        val_unquoted = urllib2_quote(val)

    if isinstance(val_unquoted, str) :
        val_unquoted = val_unquoted.decode("utf-8")

    return val_unquoted

def from_ejabberd():
    input_length = sys.stdin.read(2)
    (size,) = unpack('>h', input_length)
    return sys.stdin.read(size)

def to_ejabberd(answer):
    token = pack('>hh', 2, answer)
    sys.stdout.write(token)
    sys.stdout.flush()

def authenticate(username, password, auth_url) :
    try :
        output_dict = jabber_crypt.dumps({"username" : username, "password" : password})
        url = auth_url + "/auth"
        log.write("URL: " + url + "\n")

	up = { "exchange" : myquote(output_dict) }
        req = urllib2_Request(url, urllib_urlencode(up))
        res = jabber_crypt.loads(urllib2_unquote(urllib2_urlopen(req).read().encode("utf-8")))

        if res == "good" :
            return 1, False
        elif res == "bad" :
            return 0, "Unauthorized"
        else :
            return 0, "error"

    except urllib2_HTTPError, e : 
        if e.code == 401 :
            return 0, _("Invalid credentials. Please try again") + "."
        error = "(HTTP code: " + str(e.code) + ")"
    except urllib2_URLError, e :
        error = "(URL error: " + str(e.reason) + ")"
    except Exception, e :
        error = "(Unknown error: " + str(e) + ")"

    log.write("Authenticate result: " + error + "\n")
    return 0, error


while True:
    try :
        request = from_ejabberd()
        size = pack('>h', len(request))
        #log.write("Request start: " + request + "\n")

        values = request.split(":")
        action = values[0]
        domain = values[2]
        if parameters["sslport"] != -1 :
            location = "https://" 
            port = int(parameters["sslport"])
        else :
            location = "http://" 
            port = int(parameters["port"])
        location += domain + ":" + str(port)
        if action == "auth" :
            user = values[1]
            pw = values[3]
            log.write("Request: " + action + " user " + user + " domain " + domain + "\n")
            result, reason = authenticate(user, pw, location)
            log.write("Authenticated to location " + location + ": " + user + " result: " + str(result) + " reason: " + str(reason) + "\n")
        elif action == "isuser" :
            result = 1
        else :
            result = 0

        to_ejabberd(result)
    except Exception, e :
        log.write("Bad things: " + str(e) + "\n")
        to_ejabberd(0)
        sleep(1)
