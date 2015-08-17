#!/usr/bin/python

import sys, os, fcntl
from os import path as os_path
from re import compile as re_compile, IGNORECASE as re_IGNORECASE, sub as re_sub
from struct import *
from subprocess import *
from urllib2 import quote as urllib2_quote, Request as urllib2_Request, urlopen as urllib2_urlopen, URLError as urllib2_URLError, HTTPError as urllib2_HTTPError

cwd = re_compile(".*\/").search(os_path.realpath(__file__)).group(0)
import sys
sys.path = [cwd, cwd + "../"] + sys.path

from params import parameters

def from_ejabberd():
    input_length = sys.stdin.read(2)
    (size,) = unpack('>h', input_length)
    return sys.stdin.read(size)

def to_ejabberd(answer):
    token = pack('>hh', 2, answer)
    sys.stdout.write(token)
    sys.stdout.flush()

log = open("/var/log/ejabberd/auth-filter.log",'a+b',0)

def authenticate(username, password, auth_url) :
    try :
        url = auth_url + "/auth?username=" + username + "&password=" + password
        req = urllib2_Request(url)
        res = urllib2_urlopen(req).read()

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

    return 0, error


while True:
    request = from_ejabberd()
    size = pack('>h', len(request))
    log.write("Request start: " + request + "\n")

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
    log.write("Location: " + location + "\n")
    if action == "auth" :
        user = values[1]
 	pw = values[3]
        log.write("Request: " + action + " user " + user + " domain " + domain + "\n")
        result, reason = authenticate(user, pw, location)
        log.write("Authenticate to location " + location + ": " + user + " result: " + str(result) + " reason: " + str(reason) + "\n")
    elif action == "isuser" :
        result = 1
    else :
        result = 0

    to_ejabberd(result)
