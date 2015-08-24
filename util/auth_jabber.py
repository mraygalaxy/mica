#!/usr/bin/python
# coding: utf-8

import sys, os, fcntl
from os import path as os_path
from re import compile as re_compile, IGNORECASE as re_IGNORECASE, sub as re_sub
from struct import *
from subprocess import *
from urllib2 import quote as urllib2_quote, Request as urllib2_Request, urlopen as urllib2_urlopen, URLError as urllib2_URLError, HTTPError as urllib2_HTTPError
from time import sleep

cwd = re_compile(".*\/").search(os_path.realpath(__file__)).group(0)
import sys
sys.path = [cwd, cwd + "../"] + sys.path

from params import parameters
from common import myquote

log = open("/var/log/ejabberd/auth-filter.log",'a+b',0)

def from_ejabberd():
    input_length = sys.stdin.read(2)
    log.write("From ejabberd length: " + str(input_length) + " " + str(len(input_length)) + "\n")
    (size,) = unpack('>h', input_length)
    return sys.stdin.read(size)

def to_ejabberd(answer):
    log.write("Ready to write back\n")
    token = pack('>hh', 2, answer)
    log.write("Packed\n")
    sys.stdout.write(token)
    log.write("Written\n")
    sys.stdout.flush()
    log.write("Flushed\n")


def authenticate(username, password, auth_url) :
    try :
        log.write(u"unquoting values\n")
        username_unquoted = myquote(username)
        password_unquoted = myquote(password)
        log.write(u"unquoted\n")
        #url = auth_url + u"/auth?username=" + username_unquoted + u"&password=" + password_unquoted
        url = auth_url + u"/auth?username=" + username + u"&password=" + password
        log.write(u"making request\n")
        req = urllib2_Request(url)
        res = urllib2_urlopen(req).read()
        log.write(u"request returned\n")

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
            log.write("Authenticated to location " + location + ": " + user + " result: " + str(result) + " reason: " + str(reason) + "\n")
        elif action == "isuser" :
            result = 1
        else :
            result = 0

        log.write("Sending back response: " + str(result) + "\n")
        to_ejabberd(result)
        log.write("Sent.\n")
    except Exception, e :
        log.write("Bad things: " + str(e) + "\n")
        to_ejabberd(0)
        sleep(1)
