#!/usr/bin/env python
# coding: utf-8

from re import compile as re_compile, IGNORECASE as re_IGNORECASE, sub as re_sub
from os import path as os_path, getuid as os_getuid, urandom as os_urandom, remove as os_remove, makedirs as os_makedirs
from time import sleep
from json import dumps
from sys import argv

cwd = re_compile(".*\/").search(os_path.realpath(__file__)).group(0)
import sys
sys.path = [cwd, cwd + "../"] + sys.path

from couch_adapter import *
from params import parameters
from common import myquote

url = credentials(parameters) 
s = MicaServerCouchDB(url, parameters["admin_user"], parameters["admin_pass"], refresh = True)
usersdb = s["_users"]

   #"_id": "_design/readonly",
readonly = { "validate_doc_update": "function(newDoc, oldDoc, userCtx, secObj) {if (userCtx.roles.length != 0 && userCtx.roles[0] != '_admin') throw({forbidden : 'read-only for ' + userCtx.roles});}" }

if len(argv) != 2 :
    print "Need filename from inotify."
    exit(1)

filename = argv[1]

if not filename.count(".couch") and not filename.count(".compact") :
    print "This is not a couch file: " + filename
    exit(1)

if filename[-6:] != ".couch" and filename[-8:] != ".compact" :
    print "This is still not a couch file: " + filename
    exit(1)

if len(filename) <= 11 :
    print "This is really still not a couch file: " + filename
    exit(1)

if len(filename) > 8 and filename[-8:] == ".compact" :
    filename = filename[:-8]

print "Filename: " + filename
dbname = ".".join(filename.split(".")[:-1])
userdb = s[dbname]
usersecurity = userdb.get_security()

roles = usersecurity["members"]["roles"]

admin = False
username = False
if len(roles) == 0 :
    admin = True
    username = usersecurity["admins"]["names"][1]
else :
    assert(len(roles) >= 1)
    for role in roles :
        if role.count("_master") and role[-7:] == "_master" and role[:-7] != "" :
            username = role[:-7]

user = usersdb["org.couchdb.user:" + username] 

if "quota" not in user :
    if username != "demo" and username != "files" :
        user["quota"] = -1 if admin else 300
        print "Installing quota for user: " + username
        usersdb["org.couchdb.user:" + username] = user
        user = usersdb["org.couchdb.user:" + username]
        users[username] = user
    else :
        user["quota"] = -1

quota = user["quota"]
main = s[user["mica_database"]]
disk_size = main.info()["disk_size"] / 1024 / 1024

if username not in ["demo", "files"] and not admin :
    if quota != -1 and disk_size >= quota :
        if not main.doc_exist("_design/readonly") :
            print "setting readonly: " + user["name"] + ", quota: " + str(user["quota"]) + ", current: " + str(disk_size)
            main["_design/readonly"] = readonly
        else :
            print "already readonly: " + user["name"] + ", quota: " + str(user["quota"]) + ", current: " + str(disk_size)
    else :
        if main.doc_exist("_design/readonly") :
            print "removing readonly: " + user["name"] + ", quota: " + str(user["quota"]) + ", current: " + str(disk_size)
            del main["_design/readonly"]
        else :
            print "stable: " + user["name"] + ", quota: " + str(user["quota"]) + ", current: " + str(disk_size)
