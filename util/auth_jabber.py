#!/usr/bin/python

import sys, os, fcntl
from struct import *
from subprocess import *
from urllib2 import quote as urllib2_quote, Request as urllib2_Request, urlopen as urllib2_urlopen, URLError as urllib2_URLError, HTTPError as urllib2_HTTPError

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

        req = urllib2_Request(auth_url + "/auth?username=" + username + "&password=" + password)
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

    #log.write("Request: ")
    #log.write(request)
    #log.write('\n')

    auth, user, domain, pw = request.split(":")

    result, reason = authenticate(user, pw, "http://localhost:20000")

    log.write("Authenticate: " + user + " result: " + str(result) + " reason: " + str(reason) + "\n")
    
    to_ejabberd(result)
