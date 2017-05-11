#!/usr/bin/env python
# coding: utf-8

from re import compile as re_compile, IGNORECASE as re_IGNORECASE, sub as re_sub
from os import path as os_path, getuid as os_getuid, urandom as os_urandom, remove as os_remove, makedirs as os_makedirs
from time import sleep, time
from json import dumps
from sys import argv, getdefaultencoding

cwd = re_compile(".*\/").search(os_path.realpath(__file__)).group(0)
import sys
sys.path = [cwd, cwd + "../"] + sys.path

from couch_adapter import *
from params import parameters
from common import myquote
from inotify import adapters
from threading import Thread, Lock, current_thread, Timer, local as threading_local
from traceback import format_exc, print_stack

reload(sys).setdefaultencoding("utf-8")

url = credentials(parameters)
print "Going to: " + url
s = MicaServerCouchDB(url, parameters["admin_user"], parameters["admin_pass"], refresh = True)
usersdb = s["_users"]
readonly = { "validate_doc_update": "function(newDoc, oldDoc, userCtx, secObj) {if (userCtx.roles.length != 0 && userCtx.roles[0] != '_admin') throw({forbidden : 'read-only for ' + userCtx.roles});}" }
holders = {}
holdermutex = Lock()

if len(argv) != 2 :
    print "Need path to monitor for inotify."
    exit(1)

monitorpath = argv[1]

def valid_filename(filename) :
    if not filename.count(".couch") and not filename.count(".compact") :
        print "This is not a couch file: " + filename
        return False

    if filename.count("_global_changes.") or filename.count("_dbs.") :
        print "Ignoring system database: " + filename
        return False

    if filename.count("mica_admin") or filename.count("files") or filename.count("_users") :
        print "Ignoring MLL system database: " + filename
        return False

    if filename[-6:] != ".couch" and filename[-8:] != ".compact" :
        print "This is still not a couch file: " + filename
        return False

    if len(filename) <= 11 and filename != "mica.couch" :
        print "This is really still not a couch file: " + filename
        return False

    if len(filename) > 8 and filename[-8:] == ".compact" :
        print "Compaction file. Renaming."
        filename = filename[:-8]
        print "Filename: " + filename

    return filename

def reap(filename) :
    try :
        print "Reap STARTING: " + filename
        holdermutex.acquire()
        if filename.count(".") == 2 :
            # CouchDB 2.0?
            dbname = ".".join(filename.split(".")[:-2])
        else :
            # CouchDB 1.6
            dbname = ".".join(filename.split(".")[:-1])
        userdb = s[dbname]
        usersecurity = userdb.get_security()

        if "members" in usersecurity :
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
                    print "Reap INSTALLING quota for user: " + username
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
                        print "Reap SETTING readonly: " + user["name"] + ", quota: " + str(user["quota"]) + ", current: " + str(disk_size)
                        readonly["updated_at"] = time()
                        main["_design/readonly"] = readonly
                    else :
                        print "Reap ALREADY readonly: " + user["name"] + ", quota: " + str(user["quota"]) + ", current: " + str(disk_size)
                else :
                    if main.doc_exist("_design/readonly") :
                        print "Reap REMOVING readonly: " + user["name"] + ", quota: " + str(user["quota"]) + ", current: " + str(disk_size)
                        del main["_design/readonly"]
                    else :
                        print "Reap STABLE: " + str(user["name"]) + ", quota: " + str(user["quota"]) + ", current: " + str(disk_size)

            print "Reap COMPLETE: " + filename
        else :
            print "Reap FAILED: " + dbname + " does not have valid security roles. ERROR."
    except Exception, e :
        for line in format_exc().splitlines() :
            print(line)
        print "Failed to reap file: " + filename + ": " + str(e)
        try :
            print "Failed to get members from usersecurity: " + str(usersecurity)
        except Exception, e :
            print "Failed to show user security: " + str(e)

    try :
        del holders[filename]
        holdermutex.release()
    except Exception, e :
        print "Failed to cleanup: " + str(e)

i = adapters.InotifyTree(monitorpath)

for event in i.event_gen():
    if event is not None:
        (header, type_names, watch_path, filename) = event
        #print "WD=(%d) MASK=(%d) COOKIE=(%d) LEN=(%d) MASK->NAMES=%s WATCH-PATH=[%s] FILENAME=[%s]" % (header.wd, header.mask, header.cookie, header.len, type_names,
        #                 watch_path.decode('utf-8'), filename.decode('utf-8'))
        if "IN_MODIFY" in type_names :
            filename = valid_filename(filename)
            if not filename :
                continue

            holdermutex.acquire()
            if filename in holders :
                print "Modification queued: " + filename
                pass
            else :
                t = Timer(10.0, reap, args = [filename])
                holders[filename] = t
                t.start()
                print "New modification queued: " + filename
            holdermutex.release()
