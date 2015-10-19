#!/usr/bin/env python
# coding: utf-8

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

urls = [    { "loc" : "api?human=0&alien=storylist&tzoffset=18000", "method" : "get" },
            { "loc" : "api?human=0&alien=read&view=1&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb", "method" : "get" },
            { "loc" : "api?human=0&alien=read&view=1&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&page=0", "method" : "get" },
            { "loc" : "api?human=0&alien=read&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&memolist=1&page=0", "method" : "get" },
            { "loc" : "api?human=0&alien=read&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&memorized=1&nb_unit=8&page=0", "method" : "get" },
            { "loc" : "api?human=0&alien=read&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&memorized=0&nb_unit=3&page=0", "method" : "get" },
            { "loc" : "api?human=0&alien=read", "method" : "get" },
            { "loc" : "api?human=0&alien=read&view=1&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&page=0", "method" : "get" },
            { "loc" : "api?human=0&alien=read&view=1&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&page=0&image=0", "method" : "get" },
            { "loc" : "api?human=0&alien=read&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&memolist=1&page=0", "method" : "get" },
            { "loc" : "api?human=0&alien=instant&source=%E7%82%8E%E7%83%AD&lang=en&source_language=zh-CHS&target_language=en", "method" : "get" },
            { "loc" : "api?human=0&alien=home&view=1", "method" : "get" },
            { "loc" : "api?human=0&alien=home&switchmode=text", "method" : "get" },
            { "loc" : "api?human=0&alien=home&view=1&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&page=0", "method" : "get" },
            { "loc" : "api?human=0&alien=read&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&reviewlist=1&page=0", "method" : "get" },
            { "loc" : "api?human=0&alien=home&view=1&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&multiple_select=1&index=1&nb_unit=11&trans_id=9&page=0", "method" : "get" },
            { "loc" : "api?human=0&alien=home&view=1&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&multiple_select=1&index=1&nb_unit=48&trans_id=42&page=0", "method" : "get" },
            { "loc" : "api?human=0&alien=home", "method" : "post", "data" : dict(retranslate = '1', page = '0', uuid = 'b220074e-f1a7-417b-9f83-e63cebea02cb') },
            # Assert that the default has changed and move multiple_select to actual JSON, then retry the request
            { "loc" : "api?human=0&alien=edit&view=1", "method" : "get" },
            { "loc" : "api?human=0&alien=edit&view=1&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&page=0", "method" : "get" },
            { "loc" : "api?human=0&alien=edit&uuid=b220074e-f1a7-417b-9f83-e63cebea02cb&editslist=1&page=0", "method" : "get" },
            { "loc" : "api?human=0&alien=edit", "data" : { "oprequest" : '[{"operation":"split","uuid":"b220074e-f1a7-417b-9f83-e63cebea02cb","units":1,"failed":false,"chars":"小鸟","pinyin":"xiǎo+niǎo","nbunit":"8","tid":"0b23c772194ef5a97aa23d5590105665","index":"-1","pagenum":"0","out":""},{"operation":"merge","uuid":"b220074e-f1a7-417b-9f83-e63cebea02cb","units":2,"failed":false,"chars":"跳","pinyin":"tiào","nbunit0":"45","tid0":"0cdbc17e9ed386e3f3df2b26ed5b5187","index0":"-1","page0":"0","chars0":"跳","pinyin0":"tiào","nbunit1":"46","tid1":"0cdbc17e9ed386e3f3df2b26ed5b5187","index1":"-1","page1":"0","chars1":"跳","pinyin1":"tiào","out":""}]', "uuid" : "b220074e-f1a7-417b-9f83-e63cebea02cb"}, "method" : "post" },
           { "loc" : "api?human=0&alien=edit", "method" : "post", "data" : { "oprequest" : '[{"operation":"split","uuid":"b220074e-f1a7-417b-9f83-e63cebea02cb","units":1,"failed":false,"chars":"山羊","pinyin":"shān+yáng","nbunit":"111","tid":"fb7335cbba25395d3b9a867ddad630fd","index":"-1","pagenum":"0","out":""}]', "uuid" : "b220074e-f1a7-417b-9f83-e63cebea02cb" } },
#           { "loc" : "", "method" : "get" },
#           { "loc" : "", "method" : "get" },
#           { "loc" : "", "method" : "get" },
#           { "loc" : "", "method" : "get" },
#           { "loc" : "", "method" : "get" },
#           { "loc" : "", "method" : "get" },
        ]


def run_tests() :
    for url in urls :
        print url["method"] + ": " + url["loc"]
        if url["method"] == "get" :
            r = s.get("http://localhost/" + url["loc"])
        else :
            print "   Post data: " + str(url["data"])
            r = s.post("http://localhost/" + url["loc"], data = url["data"])
        assert(r.status_code == 200)
        assert(json_loads(r.text)['success'])


run_tests()

print "Logging out..."
r = s.get("http://localhost/disconnect")
assert(r.status_code == 200)
print "Done."
