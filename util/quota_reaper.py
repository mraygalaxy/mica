#!/usr/bin/env python
# coding: utf-8

from re import compile as re_compile, IGNORECASE as re_IGNORECASE, sub as re_sub
from os import path as os_path, getuid as os_getuid, urandom as os_urandom, remove as os_remove, makedirs as os_makedirs
from time import sleep, time
from json import dumps

cwd = re_compile(".*\/").search(os_path.realpath(__file__)).group(0)
import sys
sys.path = [cwd, cwd + "../"] + sys.path

from couch_adapter import *
from params import parameters

url = credentials(parameters) 
s = MicaServerCouchDB(url, parameters["admin_user"], parameters["admin_pass"], refresh = True)
userdb = s["_users"]

   #"_id": "_design/readonly",
readonly = { "validate_doc_update": "function(newDoc, oldDoc, userCtx, secObj) {if (userCtx.roles.length != 0 && userCtx.roles[0] != '_admin') throw({forbidden : 'read-only for ' + userCtx.roles});}" }

while True :
    users = {}
    for result in userdb.view('accounts/all') :
        user = result["key"]
        users[user["name"]] = user

    for username in users :
        user = users[username]
        admin = True if len(user["roles"]) == 0 else False
        if "quota" not in user :
            if username != "demo" and username != "files" :
                user["quota"] = -1 if admin else 300
                print "Installing quota for user: " + username
                userdb["org.couchdb.user:" + username] = user
                user = userdb["org.couchdb.user:" + username]
                users[username] = user
            else :
                user["quota"] = -1

        quota = user["quota"]
        main = s[user["mica_database"]]
        disk_size = main.info()["disk_size"] / 1024 / 1024

        if username in ["demo", "files"] or admin :
            continue

        if quota != -1 and disk_size >= quota :
            if not main.doc_exist("_design/readonly") :
                print "setting readonly: " + user["name"] + ", quota: " + str(user["quota"]) + ", current: " + str(disk_size)
                readonly["updated_at"] = time()
                main["_design/readonly"] = readonly
            else :
                print "already readonly: " + user["name"] + ", quota: " + str(user["quota"]) + ", current: " + str(disk_size)
        else :
            if main.doc_exist("_design/readonly") :
                print "removing readonly: " + user["name"] + ", quota: " + str(user["quota"]) + ", current: " + str(disk_size)
                del main["_design/readonly"]
            else :
                print "stable: " + user["name"] + ", quota: " + str(user["quota"]) + ", current: " + str(disk_size)

    sleep(10)
