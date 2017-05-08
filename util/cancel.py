#!/usr/bin/env python

from urllib2 import quote as urllib2_quote, Request as urllib2_Request, urlopen as urllib2_urlopen, URLError as urllib2_URLError, HTTPError as urllib2_HTTPError
from threading import Thread, Lock, current_thread, Timer, local as threading_local
from time import sleep

print "Request start"
req = urllib2_Request("https://security.hinespot.com/file.tgz")
print "Opening..."
fdurl = urllib2_urlopen(req, timeout = 60)
print "Grabbing socket"
realsock = fdurl.fp._sock.fp._sock

def get(f) :
    try :
        while True :
            print "Reading 1MB"
            f.read(1194304)
            print "Finished 1MB"
    except AttributeError, e :
        print "Socket closed"

print "Creating thread"
t = Thread(target = get, args = [fdurl])
t.daemon = True
print "Starting thread"
t.start()

print "Sleeping"
sleep(30)
print "Slept"

realsock.close() 
fdurl.close()

print "Joining"

t.join()
