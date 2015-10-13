#!/usr/bin/env python

from re import compile as re_compile, IGNORECASE as re_IGNORECASE, sub as re_sub
from os import path as os_path, getuid as os_getuid, urandom as os_urandom, remove as os_remove, makedirs as os_makedirs
from docker import Client
from json import loads as json_loads, dumps as json_dumps
from time import sleep
import requests
import docker
import socket
import sys


cwd = re_compile(".*\/").search(os_path.realpath(__file__)).group(0)
sys.path = [cwd, cwd + "../"] + sys.path

from params import parameters, test

c = Client(base_url='unix://var/run/docker.sock')
s = requests.Session()

options = dict(
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
        cbinfo("Unable to connect to " + protocol + " port " + str(port) + " on host " + hostname + ": " + str(msg))
        return False
        sock.close()
        sock = None

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

cleanup(options["name"])

print "Creating container: " + options["name"]
details = c.create_container(**options)

print "Creation complete."

c.start(options["name"])

print "Started. Waiting for couch ready..."

port = 5984
hostname = "localhost"
print "Checking " + hostname + ": " + str(port)
while True :
    if check_port(hostname, port) :
        try :
            r = s.get("http://" + hostname + ":" + str(port))
            print "Container ready. Running tests."
            break
        except requests.exceptions.ConnectionError, e :
            print "Container not ready: " + str(e) + ". Waiting..."
    else :
        print "Port not open yet. Waiting..."

    sleep(1)

print "Logging in..."
r = s.get("http://localhost")
assert(r.status_code == 200)

r = s.post("http://localhost/connect", data=dict(human='0', username=test["username"], password=test["password"], remember='on', address='http://localhost:5984', connect='1'))
assert(r.status_code == 200)
assert(json_loads(r.text)['success'])

urls = [    "api?human=0&alien=storylist&tzoffset=18000",
            "api?human=0&alien=read&view=1&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb",
            "api?human=0&alien=read&view=1&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&page=0",
            "api?human=0&alien=read&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&memolist=1&page=0",
            "api?human=0&alien=read&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&memorized=1&nb_unit=8&page=0",
            "api?human=0&alien=read&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&memorized=0&nb_unit=3&page=0",
            "api?human=0&alien=read",
            "api?human=0&alien=read&view=1&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&page=0",
            "api?human=0&alien=read&view=1&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&page=0&image=0",
            "api?human=0&alien=read&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&memolist=1&page=0",
            "api?human=0&alien=instant&source=%E7%82%8E%E7%83%AD&lang=en&source_language=zh-CHS&target_language=en",
#            "",
#            "",
#            "",
#            "",
#            "",
#            "",
#            "",
#            "",
#            "",
        ]

for url in urls :
    print "Testing url: " + url
    r = s.get("http://localhost/" + url)
    assert(r.status_code == 200)
    assert(json_loads(r.text)['success'])


print "Logging out..."
r = s.get("http://localhost/disconnect")
assert(r.status_code == 200)
print "Done."
