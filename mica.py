#!/usr/bin/env python
# coding: utf-8

from pwd import getpwuid
from sys import path
from time import sleep, time as timest
from threading import Thread, Lock, current_thread
from copy import deepcopy
from cStringIO import StringIO

'''
def tracefunc(frame, event, arg, indent=[0]):
    if event == "call":
        indent[0] += 2
        mdebug("-" * indent[0] + "> call function: " + frame.f_code.co_name)
    elif event == "return":
        mdebug("<" + "-" * indent[0] + " exit function: " + frame.f_code.co_name)
        indent[0] -= 2

    return tracefunc
#sys.settrace(tracefunc)
'''

import traceback
import os
import re
import shutil
import urllib
import urllib2
import copy
import codecs
import uuid as uuid4
import inspect
import hashlib
import errno
import json
import base64
import __builtin__
import sys
import socket
import Queue
import string 


global_processors = {}
texts = {}

from common import *
from processors import * 
from translator import *
from templates import *
import processors

import couch_adapter

mdebug("Initial imports complete")

cwd = re.compile(".*\/").search(os.path.realpath(__file__)).group(0)
sys.path = [cwd, cwd + "mica/"] + sys.path

#Non-python-core
from zope.interface import Interface, Attribute, implements
from twisted.python.components import registerAdapter
from twisted.web.server import Session
from twisted.web.wsgi import WSGIResource
from twisted.internet import reactor
from twisted.web.static import File
from twisted.web.resource import Resource
from twisted.web.server import Site
from twisted.web import proxy, server
from twisted.python import log
from twisted.python.logfile import DailyLogFile
import twisted

from webob import Request, Response, exc

try :
    from pdfminer.pdfinterp import PDFResourceManager, PDFPageInterpreter
    from pdfminer.converter import PDFPageAggregator
    from pdfminer.layout import LAParams, LTPage, LTTextBox, LTTextLine, LTImage
    from pdfminer.pdfpage import PDFPage
except ImportError, e :
    mdebug("Could not import pdfminer. Full translation will not work.")
    pass

mobile = True 
try :
    from jnius import autoclass
    String = autoclass('java.lang.String')
except ImportError, e :
    try :
        from pyobjus import autoclass, objc_f, objc_str as String, objc_l as Long, objc_i as Integer
    except ImportError, e :
        mdebug("pyjnius and pyobjus not available. Probably on a server.")
        mobile = False

mdebug("Imports complete.")

deeper = "<br/><br/></br></br></br></br></br><br/><br/>"
pdf_punct = ",卜「,\,,\\,,【,\],\[,>,<,】,〈,@,；,&,*,\|,/,-,_,—,,,，,.,。,?,？,:,：,\:,\：,：,\：,\、,\“,\”,~,`,\",\',…,！,!,（,\(,）,\),口,」,了,丫,㊀,。,门,X,卩,乂,一,丁,田,口,匕,《,》,化,*,厂,主,竹,-,人,八,七,，,、,闩,加,。,』,〔,飞,『,才,廿,来,兀,〜,\.,已,I,幺,去,足,上,円,于,丄,又,…,〉".decode("utf-8")

for letter in (string.ascii_lowercase + string.ascii_uppercase) :
    pdf_punct += letter.decode("utf-8")

pdf_expr = r"([" + pdf_punct + "][" + pdf_punct + "]|[\x00-\x7F][\x00-\x7F]|[\x00-\x7F][" + pdf_punct + "]|[" + pdf_punct + "][\x00-\x7F])"

mdebug("Punctuation complete.")

def parse_lt_objs (lt_objs, page_number):
    text_content = [] 
    images = [] 

    for lt_obj in lt_objs:
        if isinstance(lt_obj, LTTextBox) or isinstance(lt_obj, LTTextLine):
            text_content.append(lt_obj.get_text().strip())
        elif isinstance(lt_obj, LTImage):
            images.append(lt_obj.stream.get_data())
        elif isinstance(lt_obj, LTFigure):
            sub_text, sub_images = parse_lt_objs(lt_obj._objs(), page_number)
            text_content.append(sub_text)
            images.append(sub_images)

    return (text_content, images)

                
def repeat(func, args, kwargs):
    success = False
    while not success :
        ret = func(*args, **kwargs)
        success = True
   
    return [success] + ret 

def filter_lines(data2) :
    new_page = []

    for line in data2 : 
        if line == "" :
            continue

        for match in re.compile(r'[0-9]+ +[0-9, ]+', flags=re.IGNORECASE).findall(line) :
            line = line.replace(match, match.replace(" ", ""))

        temp_line = line.strip().decode("utf-8") if isinstance(line, str) else line.strip()
        if len(temp_line) == 3 and temp_line[0] == "(" and temp_line[-1] == ")" :
            matches = re.compile(u'\(.\)', flags=re.IGNORECASE).findall(temp_line)

            if len(matches) == 1 :
                continue

        line = re.sub(r'( *82303.*$|[0-9][0-9][0-9][0-9][0-9]+ *)', '', line)
        test_all = re.sub(r'([\x00-\x7F]| )+', '', line)

        if test_all == "" :
            continue

        no_numbers = re.sub(r"([0-9]| )+", "", line)
        if isinstance(no_numbers, str) :
            no_numbers = no_numbers.decode("utf-8")
        while len(re.compile(pdf_expr).findall(no_numbers)) :
            no_numbers = re.sub(pdf_expr, '', no_numbers)
            continue

        if len(no_numbers) <= 1 :
            continue

        new_page.append(line)

    return new_page

def itemhelp(pairs) :
    story = pairs[1]
    total_memorized = story["total_memorized"] if "total_memorized" in story else 0
    total_unique = story["total_unique"] if "total_unique" in story else 0
    pr = int((float(total_memorized) / float(total_unique)) * 100) if total_unique else 0
    story["pr"] = str(pr)
    return pr

mdebug("Setting up prefixes.")

username = getpwuid(os.getuid())[0]
relative_prefix_suffix = "serve"
relative_prefix = "/" + relative_prefix_suffix

def prefix(uri) :
    result = re.compile("[^/]*\:\/\/([^/]*)(\/(.*))*").search(uri)
    address = result.group(1)
    path = result.group(3)
    if path is None :
        path = ""
    return (address, path)

class Params(object) :
    def __init__(self, environ, session):
        self.pid = "none"
        self.http = Request(environ)  
        self.action = self.http.path[1:] if len(self.http.path) > 0 else None
        if self.action is None or self.action == "":
            self.action = "index"

        self.session = session
        
        if 'connected' not in self.session.value :
            self.session.value['connected'] = False
                
        self.session.save()
        self.unparsed_uri = self.http.url
        self.uri = self.http.path
        self.active = None 
        self.skip_show = False

        if self.action == "index" :
            self.mpath = self.uri + relative_prefix_suffix
            self.bootstrappath = self.uri + relative_prefix_suffix + "/bootstrap"
        else :
            self.mpath = self.uri + "/.." + relative_prefix
            self.bootstrappath = self.uri + "/.." + relative_prefix + "/bootstrap"

        minfo("Request: " + self.unparsed_uri + " action: " + self.action)


class MICA(object):
    def authenticate(self, username, password, auth_url) :
        try :
            mdebug("Authenticating to: " + auth_url)
            username_unquoted = urllib2.quote(username)
            userData = "Basic " + (username + ":" + password).encode("base64").rstrip()
            req = urllib2.Request(auth_url + "/_users/org.couchdb.user:" + username_unquoted)
            req.add_header('Accept', 'application/json')
            req.add_header("Content-type", "application/x-www-form-urlencoded")
            req.add_header('Authorization', userData)
            res = urllib2.urlopen(req)
            mdebug("Authentication success with username: " + username)
            return json.loads(res.read())
        except urllib2.URLError, e :
            mdebug("Invalid username or password: " + username + " " + str(e))
            return False

    def verify_db(self, req, dbname, password = False, cookie = False, users = False) :
        username = req.session.value["username"]

        if username not in self.dbs or not self.dbs[username] : 
            mdebug("Database not set. Requesting object.")
            if mobile :
                mdebug("Setting mobile db to prexisting object.")
                self.dbs[username] = self.db
            else :
                address = req.session.value["address"] if "address" in req.session.value else self.credentials()
                cs = self.db_adapter(address, username, password, cookie)
                req.session.value["cookie"] = cs.cookie
                req.session.save()
                self.dbs[username] = cs[dbname]

            mdebug("Installing view counter.")
            self.views_ready[username] = 0

        req.db = self.dbs[username]

        mdebug("Testing translation credentials.")
        if req.db.doc_exist(self.acct(username)) :
            user = req.db[self.acct(username)]

            mdebug("Account found for credentials, checking.")
            if user and "translator_credentials" in user :
                if username not in self.client :
                    mdebug("Recreating credentials.")
                    self.client[username] = Translator(user["translator_credentials"]["id"], user["translator_credentials"]["secret"])
                    mdebug("Loaded translation credentials for user " + username + ": " + str(self.client[username]))
        mdebug("DB verification complete.")

    def acct(self, name) :
        return "MICA:accounts:" + name

    def story(self, req, key) :
        ret = "MICA:" + req.session.value['username'] + ":stories:" + key
        return ret 

    def index(self, req, key) :
        return "MICA:" + req.session.value['username'] + ":story_index:" + key 
    
    def merge(self, req, key) :
        return "MICA:" + req.session.value['username'] + ":mergegroups:" + key 
    
    def splits(self, req, key) :
        return "MICA:" + req.session.value['username'] + ":splits:" + key 
    
    def tones(self, req, key) :
        return "MICA:" + req.session.value['username'] + ":tonechanges:" + key 
    
    def memorized(self, req, key):
        return "MICA:" + req.session.value['username'] + ":memorized:" + key 
    
    def credentials(self) :
        return params["couch_proto"] + "://" + params["couch_server"] + ":" + str(params["couch_port"])

    def install_language(self, language) :
        mdebug("Setting language to: " + language)
        texts[language].install()
        mdebug("Language set.")
        
    def __init__(self, db_adapter):
        self.mutex = Lock()
        self.transmutex = Lock()
        self.heromsg = "<div class='jumbotron' style='padding: 5px'>"
        self.pid = "none"
        self.dbs = {}
        self.userdb = False
        self.db_adapter = db_adapter 
        if mobile :
            self.cs = self.db_adapter(params["couch"])
        else :
            if params["admin_user"] and params["admin_pass"] :
                self.cs = self.db_adapter(self.credentials(), params["admin_user"], params["admin_pass"])
                self.userdb = self.cs["_users"]

        self.first_request = {}

        self.client = {}

        # Replacements must be in this order
        
        self.views_ready = {}
        self.view_runs = [ #name , #startend key or regular keys
                ('accounts/all', True),
                ('memorized/allcount', True),
                ('stories/original', True),
                ('stories/pages', True),
                ('stories/allpages', True),
                ('stories/all', True),
                ('stories/translating', True),
                ('stories/upgrading', True),
                ('stories/alloriginal', True),
                ('memorized/all', False), 
                ('tonechanges/all', False),
                ('mergegroups/all', False),
                ('splits/all', False),
               ]

        try :
            mdebug("Checking database access")
            if mobile :
                self.db = self.cs[params["local_database"]]
            else :
                if self.userdb :
                    self.db = self.userdb
                    self.view_check(self, "accounts")

                    if "mica_admin" not in self.cs :
                        self.make_account(self, "mica_admin", "password", [ 'admin', 'normal' ], admin = True, dbname = "mica_admin")
                else :
                    mwarn("Admin credentials ommitted. Skipping administration setup.")
                                   
        except TypeError, e :
            mwarn("Account documents don't exist yet. Probably they are being replicated." + str(e))
        except couch_adapter.ResourceNotFound, e :
            mwarn("Account document @ " + self.acct('mica_admin') + " not found: " + str(e))
        except Exception, e :
            mwarn("Database not available yet: " + str(e))

        mdebug("INIT Testing cjk thread")
        ct = threading.Thread(target=self.test_cjk)
        ct.daemon = True
        ct.start()

        if mobile :
            mdebug("INIT Launching runloop timer")
            threading.Timer(5, self.runloop_sched).start()

        mdebug("Starting view runner thread")
        vt = threading.Thread(target=self.view_runner_sched)
        vt.daemon = True
        vt.start()

        self.cd = {}

        mdebug("Building tone file")
        dpfh = open(params["tonefile"])
        for line in dpfh.readlines() :
            k, v = line.split('\t')
            self.cd[k] = v

        dpfh.close()


    def make_account(self, req, username, password, mica_roles, admin = False, dbname = False, language = "en") :
        if not dbname :
            new_uuid = str(uuid4.uuid4())
            dbname = "mica_" + new_uuid

        if not self.userdb.doc_exist("org.couchdb.user:" + username) :
            mdebug("Creating user in _user database...")
            user_doc = { "name" : username,
                           "password" : password,
                           "roles": [] if admin else [username + "_master"],
                           "type": "user",
                           "mica_database" : dbname,
                           "language" : language,
                           "date" : timest()
                          }
            self.userdb["org.couchdb.user:" + username] = user_doc 
        else :
            dbname = self.userdb["org.couchdb.user:" + username]["mica_database"]

        mdebug("Retrieving new database: " + dbname)
        newdb = self.cs[dbname]
        new_security = newdb.get_security()

        if len(new_security) == 0 :
            mdebug("Installing security on admin database.")
            new_security = {"admins" : 
                            { 
                              "names" : ["mica_admin"], 
                              "roles" : [] if admin else [username + "_master"] 
                            },
                        "members" :
                            { 
                              "names" : ["mica_admin" if admin else "nobody"], 
                              "roles" : [] 
                            }
                        }
            newdb.set_security(new_security)

        if not newdb.doc_exist(self.acct(username)) :
            mdebug("Making initial account parameters.")
            newdb[self.acct(username)] = { 'roles' : mica_roles, 
                                           'app_chars_per_line' : 70,
                                           'web_chars_per_line' : 70,
                                           'default_app_zoom' : 1.2,
                                           'default_web_zoom' : 1.0 } 

        self.check_all_views(req)

    def view_runner_common(self) :
        # This only primes views for logged-in users.
        # Scaling the backgrounding for all users will need more thought.

        # FIXME: If the session expires, the backgrounding continues. Should we
        # leave it that way?

        for username, db in self.dbs.iteritems() :
            mdebug("Priming views for user: " + username)
            self.views_ready[username] = 0

            for (name, startend) in self.view_runs :
                if not db.doc_exist("_design/" + name.split("/")[0]) :
                    mdebug("View " + name + " does not yet exist. Skipping priming.")
                    continue

                mdebug("Priming view for user: " + username + " db " + name)

                if startend :
                    for unused in db.view(name, startkey=["foo", "bar"], endkey=["foo", "bar", "baz"]) :
                        pass
                else :
                    for unused in db.view(name, keys = ["foo"], username = "bar") :
                        pass

                self.views_ready[username] += 1

    def view_runner(self) :
        if params["serialize_couch_on_mobile"] :
            (unused, rq) = (yield)

        self.view_runner_common()

        if params["serialize_couch_on_mobile"] :
            rq.put(None)
            rq.task_done()

    def view_runner_sched(self) :
        while True :
            if params["serialize_couch_on_mobile"] :
                rq = Queue.Queue()
                co = self.view_runner()
                co.next()
                params["q"].put((co, None, rq))
                resp = rq.get()
            else :
                self.view_runner_common()

            mdebug("View runner complete. Waiting until next time...")
            sleep(1800)

    def run_common(self, req) :
        try:
            if "connected" in req.session.value and req.session.value["connected"] :
                username = req.session.value["username"]
                cookie = False
                if username not in self.dbs :
                    if mobile :
                        # Couchbase mobile can do cookie authentication, we're just not using it yet....
                        # FIXME to use cookies for replication instead of saving the user's
                        # password in the session file
                        # This is OK for now since we're running on a phone....
                        mdebug("Trying to restart replication...")
                        if not self.db.replicate(req.session.value["address"], username, req.session.value["password"], req.session.value["database"], params["local_database"]) :
                            mdebug("Refreshing session failed to restart replication: Although you have authenticated successfully, we could not start replication successfully. Please try again")
                    else :
                        # On the server, use cookies to talk to CouchDB
                        cookie = req.session.value["cookie"]
                        mdebug("Reusing old cookie: " + str(cookie) + " for user " + username)

                    if "language" in req.session.value :
                        self.install_language(req.session.value["language"])

                try :
                    self.verify_db(req, req.session.value["database"], cookie = cookie)
                    resp = self.common(req)
                except couch_adapter.CommunicationError, e :
                    merr("Must re-login: " + str(e))
                    self.disconnect(req.session)
                    resp = self.bootstrap(req, self.heromsg + "\n<h4>" + _("Disconnected from MICA") + "</h4></div>")
            else :
                resp = self.common(req)

        except exc.HTTPTemporaryRedirect, e :
            resp = e
            resp.location = req.dest + resp.location
        except exc.HTTPException, e:
            resp = e
        except couch_adapter.ResourceNotFound, e :
            resp = "<h4>" + self.warn_not_replicated(req, bootstrap = False) + "</h4>"
        except Exception, e :
#            exc_type, exc_value, exc_traceback = sys.exc_info()
            resp = "<h4>" + _("Exception") + ":</h4>"
            for line in traceback.format_exc().splitlines() :
                resp += "<br>" + line
            resp += "<h2>" + _("Please report the exception above to the author. Thank you.") + "</h2>"
            if "connected" in req.session.value and req.session.value["connected"] :
                req.session.value["connected"] = False
                req.session.save()

        return resp
            
    # Only used on iOS
    def serial_common(self) :
        if params["serialize_couch_on_mobile"] :
            (req, rq) = (yield)

        resp = self.run_common(req)

        if params["serialize_couch_on_mobile"] :
            rq.put(resp)
            rq.task_done()

    def runloop(self) :
        if params["serialize_couch_on_mobile"] :
            (unused, rq) = (yield)
            self.db.runloop()
            rq.put(None)
            rq.task_done()
        else :
            self.db.runloop()

    def runloop_sched(self) :
        rq = Queue.Queue()
        co = self.runloop()
        co.next()
        params["q"].put((co, None, rq))
        resp = rq.get()
        threading.Timer(1, self.runloop_sched).start()

    def __call__(self, environ, start_response):
        # Hack to make WebOb work with Twisted
        setattr(environ['wsgi.input'], "readline", environ['wsgi.input']._wrapped.readline)

        req = Params(environ, start_response.im_self.request.session)
        req.db = False
        req.dest = ""#prefix(req.unparsed_uri)
        
        if params["serialize_couch_on_mobile"] :
            rq = Queue.Queue()
            co = self.serial_common()
            co.next()
            params["q"].put((co, req, rq))
            resp = rq.get()
        else :
            resp = self.run_common(req)

        r = None

        try :
            if isinstance(resp, str) or isinstance(resp, unicode):
                r = Response(resp)(environ, start_response)
            else :
                r = resp(environ, start_response)
        except Exception, e :
            merr("RESPONSE MICA ********\nException:")
            for line in traceback.format_exc().splitlines() :
                merr("RESPONSE MICA ********\n" + line)

        return r
    
    def sidestart(self, req, name, username, story, reviewed, finished) :
        rname = name.replace(".txt","").replace("\n","").replace("_", " ")
        sideout = ""
        sideout += "\n<tr>"
        sideout += "<td style='font-size: x-small; width: 100px'>" 
        if mobile :
            sideout += "<b>" + rname + "</b>"
        else :
            sideout += "\n<a title='" + _("Download Original") + "' href=\"/stories?type=original&#38;uuid="
            sideout += story["uuid"]
            sideout += "\">"
            sideout += rname
            sideout += "</a>"
        
        if (finished or reviewed or story["translated"]) and "pr" in story :
            pr = story["pr"]
            sideout += "<br/>\n<div class='progress progress-success progress-striped'><div class='progress-bar' style='width: "
            sideout += pr + "%;'> (" + pr + "%)</div></div>"
            
        sideout += "</td><td>"
        if not mobile :
            if finished or reviewed :
                sideout += "\n<a title='" + _("Download Romanization") + "' class='btn-default btn-xs' href=\"/stories?type=pinyin&#38;uuid=" + story["uuid"]+ "\">"
                sideout += "<i class='glyphicon glyphicon-download-alt'></i></a>"
    
        return sideout

    def template(self, template_prefix) :
        contents_fh = open(cwd + relative_prefix + "/" + template_prefix + "_template.html", "r")
        contents = contents_fh.read()
        contents_fh.close()
        return contents

    def bootstrap(self, req, body, now = False, pretend_disconnected = False, nodecode = False) :

        if isinstance(body, str) and not nodecode :
            body = body.decode("utf-8")

        if not mobile and "username" in req.session.value and req.session.value["username"] == "demo" :
            body = self.heromsg + "\n<h4>" + _("Demo Account is readonly. You must install the mobile application for interactive use of the demo account.") + "</h4></div>" + body

        if now :
            contents = body
        else :
            if req.session.value["connected"] :
                req.view_percent = '{0:.1f}'.format(float(self.views_ready[req.session.value['username']]) / float(len(self.view_runs)) * 100.0)
            else :
                req.view_percent = "0.0"
            req.pretend_disconnected = pretend_disconnected
            req.mobile = mobile
            req.address = req.session.value["address"] if "address" in req.session.value else self.credentials()

            if req.session.value['connected'] and not pretend_disconnected :
                req.user = req.db.__getitem__(self.acct(req.session.value['username']), false_if_not_found = True)

            contents = load_template(req, HeadElement)

        if not nodecode :
            contents = contents.replace("BOOTBODY", body)
            fh = open(cwd + 'serve/head.js')
            contents = contents.replace("BOOTSCRIPTHEAD", fh.read())
            fh.close()
    
        return contents

    def get_polyphome_hash(self, correct, source) :
        return hashlib.md5(str(correct).lower() + "".join(source).encode("utf-8").lower()).hexdigest()

    def rehash_correct_polyphome(self, unit):
        unit["hash"] = self.get_polyphome_hash(unit["multiple_correct"], unit["source"])

    def get_cjk_handle_common(self) :
        try :
            if not os.path.isfile(params["cjklib"]) :
                self.db.get_attachment_to_path("MICA:filelisting", "cjklib.db", params["cjklib"])
                mdebug("Exported cjklib.")
            if not os.path.isfile(params["cedict"]) :
                self.db.get_attachment_to_path("MICA:filelisting", "cedict.db", params["cedict"])
                mdebug("Exported cedict.")
        except couch_adapter.CommunicationError, e :
            mdebug("CJKLIB Not fully replicated yet. Waiting..." + str(e))
        except couch_adapter.ResourceNotFound, e :
            mdebug("CJKLIB Not fully replicated yet. Waiting..." + str(e))

    def get_cjk_handle_serial(self) :
        if params["serialize_couch_on_mobile"] :
            (unused, rq) = (yield)

        self.get_cjk_handle_common()

        if params["serialize_couch_on_mobile"] :
            rq.put(None)
            rq.task_done()

    def test_cjk(self) :
        for fn in ["cedict.db", "cjklib.db"] :
            mdebug("Searching for instances of " + fn)
            for f in os.walk(cwd) :
                 if ("" + str(f)).count(fn) :
                     if f[0][-1] != "/" :
                         fnd = f[0] + "/" + fn 
                     else :
                         fnd = f[0] + fn 
                     mdebug("Found: " + fnd)
                     mdebug("Size: " + str(os.path.getsize(fnd)))
                     if fnd != params["cedict"] and fnd != params["cjklib"] :
                         mwarn("This file should not be here. Blowing away...")
                         os.unlink(fnd)

        mdebug("Moving on with test.")

        if mobile :
            while True :
                if not os.path.isfile(params["cedict"]) or not os.path.isfile(params["cjklib"]):
                    mdebug("One of " + params["cedict"] + " or " + params["cjklib"] + " is missing. Exporting...")

                    if params["serialize_couch_on_mobile"] :
                        rq = Queue.Queue()
                        co = self.get_cjk_handle_serial()
                        co.next()
                        params["q"].put((co, None, rq))
                        resp = rq.get()
                    else :
                        self.get_cjk_handle_common()

                    sleep(5)

        cjksize = os.path.getsize(params["cjklib"])
        cesize = os.path.getsize(params["cedict"])

        mdebug("CJKLIB Size: " + str(cjksize))
        mdebug("CEDICT Size: " + str(cesize))

        assert(cjksize != 0)
        assert(cesize != 0)

        cjk, d = get_cjk_handle(params)

        for x in d.getFor(u'白鹭'.decode('utf-8')) :
            mdebug(str(x))
        for x in cjk.getReadingForCharacter(u'白','Pinyin') :
            mdebug(str(x))

        cjk.db.connection.close()
        d.db.connection.close()

        if mobile :
            # We are in a thread, but because of this bug, we cannot exit by ourselves:
            # https://github.com/kivy/pyjnius/issues/107
            # So, we have to run forever
            while True :
                mdebug("CJK test infinite sleep.")
                sleep(100000)

    def store_error(self, req, name, msg) :
        merr(msg)
        if name :
            self.transmutex.acquire()
            try :
                tmpstory = req.db[self.story(req, name)]
                if "last_error" not in tmpstory or isinstance(tmpstory["last_error"], str) :
                    tmpstory["last_error"] = []
                tmpstory["last_error"] = [msg] + tmpstory["last_error"]
                req.db[self.story(req, name)] = tmpstory
            except couch_adapter.ResourceConflict, e :
                mdebug("Failure to sync error message. No big deal: " + str(e))
            finally :
                self.transmutex.release()

    def progress(self, req, story, progress_idx, grouplen, page) :
        if progress_idx % 10 == 0 :
            self.transmutex.acquire()
            try :
                tmpstory = req.db[self.story(req, story['name'])]
                tmpstory["translating_current"] = progress_idx 
                tmpstory["translating_page"] = int(page)
                tmpstory["translating_total"] = grouplen 
                req.db[self.story(req, story['name'])] = tmpstory
            except couch_adapter.ResourceConflict, e :
                mdebug("Failure to sync translating_current. No big deal: " + str(e))
            finally :
                self.transmutex.release()

    def parse(self, req, story, page = False) :
        name = story['name']
        mdebug("Ready to translate: " + name + ". Counting pages...")

        assert("source_language" in story)

        Processor = getattr(processors, processor_map[story["source_language"]])

        processor = Processor(self, params)
    
        page_inputs = 0
        if "filetype" not in story or story["filetype"] == "txt" :
            page_inputs = 1
        else :
            mdebug("Counting now...")
            for result in req.db.view('stories/original', startkey=[req.session.value['username'], name], endkey=[req.session.value['username'], name, {}]) :
                mdebug("Got count.")
                page_inputs = result['value']
       
        mdebug("Page inputs: " + str(page_inputs))
        assert(int(page_inputs) != 0) 
             
        if page :
            page_start = int(page)
            mdebug("Translating single page starting at " + str(page))
            page_inputs = page_start + 1 
        else :  
            page_start = 0
        
        self.transmutex.acquire()
        try :
            tmpstory = req.db[self.story(req, name)]
            if "last_error" in tmpstory :
                del tmpstory["last_error"]

            tmpstory["translating"] = True 
            if not page :
                tmpstory["translated"] = False
                tmpstory["translating_pages"] = page_inputs
            tmpstory["translating_current"] = 0
            tmpstory["translating_total"] = 100
            req.db[self.story(req, name)] = tmpstory
        except Exception, e :
            mdebug("Failure to sync: " + str(e))
        finally :
            self.transmutex.release()

        opaque = processor.parse_page_start() 

        for iidx in range(page_start, page_inputs) :
            page_key = self.story(req, name) + ":pages:" + str(iidx)

            if req.db.doc_exist(page_key) :
                if page :
                    mwarn("WARNING: page " + str(iidx) + " of story " + name + " already exists. Deleting for re-translation.")
                    del req.db[page_key]
                else :
                    mwarn("WARNING: page " + str(iidx) + " of story " + name + " already exists. Not going to re-create.")
                    continue

            if "filetype" not in story or story["filetype"] == "txt" :
                page_input = req.db[self.story(req, name) + ":original"]["value"]
            else :
                page_input = eval(req.db.get_attachment(self.story(req, name) + ":original:" + str(iidx), "attach"))["contents"]
                
            mdebug("Parsing...")

            parsed = processor.pre_parse_page(opaque, page_input)

            mdebug("Parsed result: " + parsed + " for page: " + str(iidx) + " type: " + str(type(parsed)))

            lines = parsed.split("\n")
            groups = []

            for line in lines :
                temp_groups = []
                save_char_group = "" 
                for char_group in line.split(" ") :
                    if char_group not in processor.punctuation_without_newlines :
                        if save_char_group != "" :
                            groups.append(save_char_group)
                            save_char_group = ""
                        groups.append(char_group)
                    else :
                        save_char_group += char_group
                        
                if save_char_group != "" :
                    groups.append(save_char_group)
                    
                groups.append("\n")
            
            self.transmutex.acquire()
            try :
                tmpstory = req.db[self.story(req, name)]
                tmpstory["translating_total"] = len(groups)
                tmpstory["translating_current"] = 1
                tmpstory["translating_page"] = iidx 
                req.db[self.story(req, name)] = tmpstory
            except Exception, e :
                self.store_error(req, name, "Failure to initiate translation variables on page: " + str(iidx) + " " + str(e))
                raise e
            finally :
                self.transmutex.release()

            try :
                processor.parse_page(opaque, req, story, groups, str(iidx), progress = self.progress)
                online = 0
                offline = 0
                for unit in story["pages"][str(iidx)]["units"] :
                    if not unit["punctuation"] :
                        if unit["online"] :
                            online += 1
                        else :
                            offline += 1 
                mdebug("Translating page " + str(iidx) + " complete. Online: " + str(online) + ", Offline: " + str(offline))
                req.db[page_key] = story["pages"][str(iidx)]
                del story["pages"][str(iidx)]
            except Exception, e :
                msg = ""
                for line in traceback.format_exc().splitlines() :
                    msg += line + "\n"
                merr(msg)
                tmpstory = req.db[self.story(req, name)]
                tmpstory["translating"] = False 
                req.db[self.story(req, name)] = tmpstory
                self.store_error(req, name, msg)
                processor.parse_page_stop(opaque)
                raise e

        self.transmutex.acquire()
        try :
            tmpstory = req.db[self.story(req, name)]
            tmpstory["translating"] = False 
            tmpstory["translated"] = True 
            req.db[self.story(req, name)] = tmpstory
        except Exception, e :
            mdebug("Failure to sync: " + str(e))
        finally :
            self.transmutex.release()

        self.transmutex.acquire()
        try :
            tmpstory = req.db[self.story(req, name)]
            if "translated" not in tmpstory or not tmpstory["translated"] :
                self.flush_pages(req, name)
                    
        except Exception, e :
            mdebug("Failure to sync: " + str(e))
        finally :
            self.transmutex.release()

        minfo("Translation complete.")
        processor.parse_page_stop(opaque)

    def get_parts(self, unit, source_language) :
        py = ""
        target = ""
        if unit["multiple_correct"] == -1 :
            gp = global_processors[source_language]
            if not gp.already_romanized :
                for widx in range(0, len(unit["sromanization"])) :
                    word = unit["sromanization"][widx]
                    if word == u'\n' or word == '\n':
                        py += word
                    elif py != "\n" and py not in gp.punctuation_without_letters :
                        py += word + " "

                if py != u'\n' and py != "\n" :
                    py = py.strip()

            if py == u'' or py == "":
#                mdebug("Not useful: " + py + " and " + target + " len: " + str(len(unit["sromanization"])))
                if not global_processors[source_language].already_romanized :
                    return False
                else :
                    if len(unit["source"]) > 0 :
                        py = u' ' 
            if unit["trans"] :
                target = " ".join(unit["target"])
        else :
            if unit["trans"] :
                if len(unit["multiple_sromanization"]) :
                    py = u" ".join(unit["multiple_sromanization"][unit["multiple_correct"]])

                if py == "" :
                    if not global_processors[source_language].already_romanized :
                        return False
                    else :
                        if len(unit["source"]) > 0 :
                            py = u' ' 
                target = " ".join(unit["multiple_target"][unit["multiple_correct"]])

        return py, target 


    def get_polyphome_percentage(self, x, total_changes, changes, unit):
        percent = 0

        if total_changes :
            hcode = self.get_polyphome_hash(x, unit["source"])
            if hcode in changes["record"] :
                percent = int(float(changes["record"][hcode]["total_selected"]) / total_changes * 100.0)

        return percent

    def polyphomes(self, req, story, uuid, unit, nb_unit, trans_id, page) :
        gp = global_processors[story["source_language"]]
        out = ""
        out += "\n" + _("This character") + " ("
        if gp.already_romanized : 
            out += "".join(unit["source"])
        else :
            out += " ".join(unit["source"])
        out += ") " + _("is polyphonic: (has more than one pronunciation") + "):<br>"
        out += "<table class='table table-hover table-striped' style='font-size: x-small'>"
        out += "<tr>"
        if len(unit["multiple_sromanization"]) :
            out += "<td>" + _("Pinyin") + "</td>"
        out += "<td>" + _("Definition") + "</td>"
        out += "<td>" + _("Default?") + "</td></tr>"
        source = "".join(unit["source"])

        total_changes = 0.0
        changes = req.db.__getitem__(self.tones(req, source), false_if_not_found = True)
        
        if changes :
            total_changes = float(changes["total"])

        for x in range(0, len(unit["multiple_target"])) :
            percent = self.get_polyphome_percentage(x, total_changes, changes, unit) 
            out += "<tr>"

            if len(unit["multiple_sromanization"]) :
                spy = " ".join(unit["multiple_sromanization"][x])
                out += "<td>" + spy + " (" + str(percent) + " %) </td>"
            else :
                spy = " ".join(unit["multiple_target"][x])

            out += "<td>" + " ".join(unit["multiple_target"][x]).replace("\"", "\\\"").replace("\'", "\\\"").replace("/", " /<br/>") + "</td>"
            if unit["multiple_correct"] != -1 and x == unit["multiple_correct"] :
                out += "<td>" + _("Default") + "</td>"
            else :
                out += "<td><a style='font-size: x-small' class='btn-default btn-xs' " + \
                       "onclick=\"multiselect('" + uuid + "', '" + str(x) + "', '" + \
                       str(nb_unit) + "','" + str(trans_id) + "', '" + spy + "', '" + page + "')\">" + _("Select") + "</a></td>"

            out += "</tr>"

        out += "</table>"

        return out

    def view_keys(self, req, name, _units, source_queries = False) :
        sources = []

        if source_queries :
            sources = source_queries

        if _units :
            mdebug("Input units: " + str(len(_units)))
            for unit in _units :
                if name == "memorized" :
                    if "hash" in unit :
                        sources.append(unit["hash"])
                else :
                    sources.append("".join(unit["source"]))
            
        if len(sources) == 0 :
            return {} 

        keys = {}
        mdebug("Generating query for view: " + name + " with " + str(len(sources)) + " keys.")
        
        # android sqllite has a query limit of 1000 values in a prepared sql statement,
        # so let's do 500 at a time.
        inc = 500
        start = 0
        stop = inc 
        total = len(sources)
        finished = False

        while not finished :
            if stop >= total :
                stop = total 
                finished = True

            mdebug("Issuing query for indexes: start " + str(start) + " stop " + str(stop) + " total " + str(total) )
            for result in req.db.view(name + "/all", keys = sources[start:(stop)], username = req.session.value['username']) :
                keys[result['key'][1]] = result['value']

            if not finished :
                start += inc 
                stop += inc 
        
        return keys
        
    def history(self, req, story, uuid, page) :
        history = []
        found = {}
        tid = 0
        online = 0
        offline = 0
        page_dict = req.db[self.story(req, story['name']) + ":pages:" + str(page)]
        units = page_dict["units"]

        tone_keys = self.view_keys(req, "tonechanges", units) 
        
        for unit in units :
            char = "".join(unit["source"])
            if char not in found :
                if "punctuation" not in unit or not unit["punctuation"] :
                    if "online" in unit and unit["online"] :
                        online += 1
                    else :
                        offline += 1
                        
            changes = False if char not in tone_keys else tone_keys[char]
            
            if not changes :
                continue
            if unit["hash"] not in changes["record"] :
                continue
            record = changes["record"][unit["hash"]]
            if char not in found :
                found[char] = True
                history.append([char, str(changes["total"]), " ".join(record["sromanization"]), " ".join(record["target"]), tid])
                        
            tid += 1
        
        # Add sort options here
        def by_total( a ):
            return int(float(a[1]))

        history.sort( key=by_total, reverse = True )
        req.history = history
        req.onlineoffline = _("Breakdown") + ": " + _("Online") + ": " + str(online) + ", " + _("Offline") + ": " + str(offline)
        return load_template(req, HistoryElement)

    def edits(self, req, story, uuid, page, list_mode) :
        if list_mode :
            history = []
            found = {}
            tid = 0
            page_dict = req.db[self.story(req, story['name']) + ":pages:" + str(page)]
            units = page_dict["units"]

            merge_keys = self.view_keys(req, "mergegroups", units) 
            split_keys = self.view_keys(req, "splits", units) 
                
            for unit in units :
                char = "".join(unit["source"])
                if char in global_processors[story["source_language"]].punctuation_without_letters or len(char.strip()) == 0:
                    continue
                if char in found :
                    continue

                changes = False if char not in split_keys else split_keys[char]
                
                if changes :
                    if unit["hash"] not in changes["record"] :
                        continue
                    record = changes["record"][unit["hash"]]
                    history.append([char, str(record["total_splits"]), " ".join(record["sromanization"]), " ".join(record["target"]), tid, "SPLIT"])
                else: 
                    changes = False if char not in merge_keys else merge_keys[char]
                    
                    if changes : 
                        if "hash" not in unit :
                            continue
                        if unit["hash"] not in changes["record"] :
                            continue
                        record = changes["record"][unit["hash"]]
                        memberlist = []
                        nb_singles = 0
                        for key, member in record["members"].iteritems() :
                            if len(key) == 1 :
                                nb_singles += 1
                                continue
                            memberlist.append((member["romanization"], key))
                        if nb_singles == len(record["members"]) :
                            continue
                        history.append([char, str(changes["total"]), " ".join(record["sromanization"]), memberlist, tid, "MERGE"])
                    else :
                        continue

                if char not in found :
                    found[char] = True
                tid += 1
            
            # Add sort options here
            def by_total( a ):
                return int(float(a[1]))

            history.sort( key=by_total, reverse = True )

        req.process_edits = "process_edits('" + uuid + "', 'all', true)"
        req.retrans = "/" + req.action + "?retranslate=1&uuid=" + uuid + "&page=" + str(page)
        req.list_mode = list_mode
        if list_mode :
            req.history = history

        return load_template(req, EditElement)

    def view(self, req, uuid, name, story, start_page, view_mode, meaning_mode) :
        if not story["translated"] :
            return _("Untranslated story! Ahhhh!")

        upgrade_needed = 0

        if "format" not in story or story["format"] == 1 :
            out = self.heromsg + "\n<h4>" + _("The database for this story") + " (<b>" + name + "</b>) " + _("needs to be upgraded to version 2") + "."
            upgrade_needed = 2

        # Future upgrade numbers go here...

        if upgrade_needed > 0 :
            if mobile :
                out += _("Unfortunately, this can only be performed with the online version. Please login to your account online to perform the upgrade. The changes will then be replicated to all your devices. Thank you.")
            else :
                out += "<br/><a class='btn btn-default btn-primary' href='/" + req.action + "?storyupgrade=1&uuid=" + uuid + "&version=" + str(upgrade_needed) + "'>" + _("Start Upgrade") + "</a>" 

            if "last_error" in story and not isinstance(story["last_error"], str) :
                out + "Last upgrade Exception:<br/>"
                for err in story["last_error"] :
                    out += "<br/>" + err.replace("\n", "<br/>")

            out += "</h4></div>"
            return out

        req.gp = global_processors[story["source_language"]]
        req.story_name = story["name"]
        req.install_pages = "install_pages('" + req.action + "', " + str(self.nb_pages(req, name)) + ", '" + uuid + "', " + start_page + ", '" + view_mode + "', true, '" + meaning_mode + "');"
        output = load_template(req, ViewElement)

        return output

    def nb_pages(self, req, name):
        for result in req.db.view('stories/pages', startkey=[req.session.value['username'], name], endkey=[req.session.value['username'], name, {}]) :
            return result['value']
        return 0
    
    def roman_holder(self, source, color) :
        holder = "<div class='roman" + color + "'>"
        
        for x in range(0, len(source)) :
            holder += "&#160;"
            
        holder += "</div>"
        return holder
    
    def view_page(self, req, uuid, name, story, action, output, page, chars_per_line, meaning_mode, disk = False) :
        gp = global_processors[story["source_language"]]
        mdebug("View Page " + str(page) + " story " + name + " start...")
        page_dict = req.db[self.story(req, name) + ":pages:" + str(page)]
        mdebug("View Page " + str(page) + " story " + name + " fetched...")
        units = page_dict["units"]
        words = len(units)
        lines = [] 
        line = [] 

        trans_id = 0
        chars = 0
        batch = -1

        mdebug("View Page " + str(page) + " story " + name + " building...")
            
        sources = {}

        if action == "edit" :
            sources['mergegroups'] = self.view_keys(req, "mergegroups", units) 
            sources['splits'] = self.view_keys(req, "splits", units) 

        if action == "home" :
            sources['tonechanges'] = self.view_keys(req, "tonechanges", units) 
        if action == "read" :
            sources['memorized'] = self.view_keys(req, "memorized", units) 
        
        mdebug("View Page " + str(page) + " story " + name + " querying...")

        for x in range(0, len(units)) :
            unit = units[x]

            source = "".join(unit["source"])

            ret = self.get_parts(unit, story["source_language"])

            if ret == False :
                continue

            py, target = ret

            if py not in gp.punctuation_without_letters and chars >= chars_per_line :
               lines.append(line)
               line = []
               chars = 0

            if py in gp.punctuation_without_letters and py not in ['\n', u'\n'] :
                if py != u'\n' and py != "\n":
                    line.append([py, False, trans_id, [], x, source])
                    chars += 1
                else :
                    lines.append(line)
                    line = []
                    chars = 0
            else :
                chars += len(py)
                p = [target, py, trans_id, unit, x, source]
                line.append(p)

            trans_id += 1

        if len(line) :
            lines.append(line)

        mdebug("View Page " + str(page) + " story " + name + " grouped...")
        
        # TODO: The rest of the code involed in viewing a page is just a bunch of
        # loops. We have already finished querying the database and are simply
        # splicing together content.
        # 
        # Nevertheless, putting together this content, even purely in memory
        # is by far the largest source of overhead that we have. I definitely
        # think the next optimization would be to cache this content and
        # build it offline during translation time and then refresh the rendered
        # page each time we perform edits.
        #
        # But even during the edit process, the time to perform individual
        # page renders here is incredibly slow if we have to render each page again.
        #
        # The final solution may be to abandon building the page altogether
        # and just send json to the client browser, but that's a problem to
        # be solved for another day.....
        # 
        # Anothers solution may be to incrementally update portions of
        # the page instead of the whole page.
        #
        # Another solution may be to attach HTML elements to the individual
        # units of the page without re-generating them from scratch as each
        # unit changes, but the problem there is that pages are not yet
        # grouped into lines (nor can they be statically if we're dealing
        # with free-flowing text.
        #
        # But at a minimum, we may at least be able to attach the unique
        # HTML for those modified units into the page dictionary and then
        # worry about line-groupings later....
        # 
        # Each unit would need to have a rendered HTML chunk for all three
        # modes for which the unit could be viewed.
        
        spacer = "<td style='margin-right: 20px'></td>"
        merge_spacer = "<td class='mergetop mergebottom' style='margin-right: 20px'></td>"
        merge_end_spacer = "<td class='mergeleft' style='margin-right: 20px'></td>"


        for line in lines :
            disk_out = ""
            line_out = ""

            if not disk :
                line_out += "\n<table>"
                line_out += "\n<tr>"

                prev_merge = False
                for word_idx in range(0, len(line)) :
                    word = line[word_idx]
                    target = word[0].replace("\"", "\\\"").replace("\'", "\\\"")
                    py = word[1]
                    trans_id = str(word[2])
                    unit = word[3]
                    tid = unit["hash"] if py else trans_id 
                    nb_unit = str(word[4])
                    source = word[5]
                    curr_merge = False
                    merge_end = False
                    use_batch = False
                    skip_prev_merge = False

                    line_out += "\n<td style='vertical-align: top; text-align: center; font-size: small' "

                    if action == "edit" :
                        if py :
                            sourcegroup = False if source not in sources['mergegroups'] else sources['mergegroups'][source]
                            
                            if sourcegroup and unit["hash"] in sourcegroup["record"] :
                                curr_merge = True

                                if word_idx < (len(line) - 1) :
                                    endword = line[word_idx + 1]
                                    if endword[1] :
                                        endunit = endword[3]
                                        endchars = "".join(endunit["source"])
                                        #endgroup = req.db[self.merge(req, endchars)]
                                        endgroup = False if endchars not in sources['mergegroups'] else sources['mergegroups'][endchars]
                                        if not endgroup or (endunit["hash"] not in endgroup["record"]) :
                                            merge_end = True
                                        else :
                                            end_members = endgroup["record"][endunit["hash"]]["members"]
                                            curr_members = sourcegroup["record"][unit["hash"]]["members"]
                                            source_found = False
                                            end_found = False
                                            for mchars, member in end_members.iteritems() :
                                                if source in mchars :
                                                    source_found = True
                                            for mchars, member in curr_members.iteritems() :
                                                if endchars in mchars :
                                                    end_found = True
                                                    
                                            if not end_found or not source_found :
                                                #mdebug(source + " (" + str(py) + ") and " + endchars + " are not related to each other!")
                                                merge_end = True
                                                skip_prev_merge = True
                                                
                                    else :
                                        merge_end = True
                        else :
                            prev_merge = False

                    if py and action == "edit" :
                        if curr_merge :
                            if (word_idx == (len(line) - 1)) or (curr_merge and not prev_merge and merge_end ): 
                                merge_end = False
                                prev_merge = False
                                curr_merge = False

                        if curr_merge :
                            line_out += "class='mergetop mergebottom"
                            if not prev_merge : 
                                batch += 1
                                line_out += " mergeleft"
                            line_out += "'"
                            use_batch = "merge" 
                        else :
                            if not curr_merge :
                                sourcesplits = False if source not in sources['splits'] else sources['splits'][source]
                                if sourcesplits and unit["hash"] in sourcesplits["record"] :
                                    batch += 1
                                    use_batch = "split" 
                                    line_out += "class='splittop splitbottom splitleft splitright'"

                        prev_merge = curr_merge if not skip_prev_merge else False

                    line_out += ">"
                    line_out += "<span id='spanselect_" + trans_id + "' class='"
                    line_out += "batch" if use_batch else "none"
                    line_out += "'>"
                    if gp.already_romanized :
                        line_out += "<a class='transroman'"
                    else :
                        line_out += "<a class='trans'"
                    line_out += " uniqueid='" + tid + "' "
                    line_out += " nbunit='" + nb_unit + "' "
                    line_out += " transid='" + trans_id + "' "
                    line_out += " batchid='" + (str(batch) if use_batch else "-1") + "' "
                    line_out += " operation='" + (str(use_batch) if use_batch else "none") + "' "
                    line_out += " page='" + page + "' "
                    line_out += " pinyin=\"" + (py if py else target) + "\" "
                    line_out += " index='" + (str(unit["multiple_correct"]) if py else '-1') + "' "
                    line_out += " style='color: black; font-weight: normal"
                    if not unit["punctuation"] :
                        line_out += "; cursor: pointer"
                    line_out += "' "
                    line_out += " onclick=\"select_toggle('" + trans_id + "')\">"
                    line_out += source if py else target 
                    line_out += "</a>"
                    line_out += "</span>"
                    line_out += "</td>"

                    if py :
                        if action == "edit" and merge_end :
                            # mergeright
                            line_out += merge_end_spacer 
                        elif action == "edit" and curr_merge :
                            line_out += merge_spacer 
                        else :
                            line_out += spacer 

                line_out += "</tr>\n<tr>"

            for word in line :
                target = word[0].replace("\"", "\\\"").replace("\'", "\\\"")
                py = word[1]
                unit = word[3]
                trans_id = str(word[2])
                tid = unit["hash"] if py else trans_id 
                nb_unit = str(word[4])
                source = word[5]
                line_out += "\n<td style='vertical-align: top; text-align: center; font-size: small; "
                if not unit["punctuation"] :
                    line_out += "cursor: pointer"

                line_out += "'>"
                if py and (py not in gp.punctuation) :
                    if not disk :
                        if gp.already_romanized :
                            line_out += "<a class='transroman' "
                        else :
                            line_out += "<a class='trans' "

                        add_count = ""
                        if action == "home" :
                            color = "lightgrey" if not unit["punctuation"] else "white"
                            if py and len(unit["multiple_target"]) :
                                color = "green"

                            changes = False if source not in sources['tonechanges'] else sources['tonechanges'][source]
                            
                            if changes :
                                if unit["hash"] in changes["record"] :
                                    color = "black"
                                    add_count = " (" + str(int(changes["total"])) + ")"

                            if color != "black" and py and len(unit["multiple_sromanization"]) :
                                fpy = " ".join(unit["multiple_sromanization"][0])
                                for ux in range(1, len(unit["multiple_sromanization"])) :
                                     upy = " ".join(unit["multiple_sromanization"][ux])
                                     if upy != fpy :
                                         color = "red"
                                         break

                            if color != "" :
                                line_out += " style='color: " + color + "' "
                        elif py :
                            line_out += " style='color: black' "
                            color = "lightgrey" if not unit["punctuation"] else "white"

                        line_out += " id='ttip" + trans_id + "'"

                        if action in ["read","edit"] or not(len(unit["multiple_target"])) :
                            line_out += " onclick=\"toggle('" + tid + "', "
                            line_out += ("0" if action == "read" else "1") + ")\""

                        line_out += ">"
                        
                        
                        if gp.already_romanized :
                            if color not in [ "lightgrey", "white" ] :
                                line_out += target
                            else :
                                line_out += self.roman_holder(source, color)
                        else :
                            if py == u' ' :
                                line_out += self.roman_holder(source, color)
                            elif py :
                                line_out += py
                            else :
                                line_out += target.lower()
        
                        line_out += add_count
                        line_out += "</a>"
                    else :
                        disk_out += (("hold" if py == u' ' else py) if py else target).lower()
                else :
                    if disk :
                        disk_out += (("hold" if py == u' ' else py) if py else target).lower()
                    else :
                        line_out += (("hold" if py == u' ' else py) if py else target).lower()

                if not disk :
                    line_out += "<br/>"

                    if action == "home" and py and len(unit["multiple_target"]) :
                        line_out += "<div style='display: none' id='pop" + str(trans_id) + "'>"
                        line_out += self.polyphomes(req, story, uuid, unit, nb_unit, trans_id, page)
                        line_out += "</div>"
                        line_out += "<script>"
                        line_out += "multipopinstall('" + str(trans_id) + "', 0);\n"
                        line_out += "</script>"

                    line_out += "</td>"

                    if py :
                        line_out += spacer
                else :
                    disk_out += " "

            if disk :
                disk_out += "\n"
            else :
                line_out += "</tr>"
                line_out += "<tr>"

            if not disk :
                for word in line :
                    target = word[0]
                    if len(target) and target[0] == '/' :
                        target = target[1:-1]
                    unit = word[3]
                    nb_unit = str(word[4])
                    py = word[1]
                    source = word[5]
                    memorized = False
                    
                    if py and action == 'read' :
                        if unit["hash"] in sources['memorized'] :
                            memorized = True
                            
                    tid = unit["hash"] if py else str(word[2])
                    line_out += "\n<td style='vertical-align: top; text-align: center'>"
                    line_out += "<table><tr>"
                    line_out += "<td><div style='display: none' class='memory" + tid + "'>"
                    line_out += "<img src='" + req.mpath + "/spinner.gif' width='15px'/>&#160;"
                    line_out += "</div></td>"
                    line_out += "</tr><tr><td>"
                    if gp.already_romanized :
                        line_out += "<div class='transroman "
                    else :
                        line_out += "<div class='trans "
                        
                    line_out += " trans" + tid + "' style='display: "
                    line_out += "block" if (action == "read" and not memorized) else "none"
                    line_out += "' id='trans" + tid + "'>"
                    if py and not unit["punctuation"] :
                        if not memorized :
                            line_out += "<div revealid='" + tid + "' "
                            line_out += "class='reveal reveal" + tid + "'"
                            if meaning_mode == "true":
                                line_out += "style='display: none'"
                            line_out += "><a class='reveal' onclick=\"reveal('" + tid + "', false)\"><i class='glyphicon glyphicon-expand'></i>&#160;" + _("open") + "</a></div>"
                            line_out += "<div class='definition definition" + tid + "' "
                            if meaning_mode == "false":
                                line_out += "style='display: none'"
                            line_out += ">"
                        if action in ["read", "edit"] :
                            if gp.already_romanized :
                                line_out += "<a class='transroman' "
                            else :
                                line_out += "<a class='trans' "
                            line_out += "onclick=\"memorize('" + \
                                        tid + "', '" + uuid + "', '" + str(nb_unit) + "', '" + page + "')\">"

                        line_out += target.replace("/"," /<br/>")

                        if action in [ "read", "edit" ] :
                            line_out += "</a>"

                        if not memorized :
                            line_out += "</div>"

                    line_out += "<br/>"
                    line_out += "</div>"
                    line_out += "<div style='display: "
                    line_out += "none" if (action in ["read", "edit"] and not memorized) else "block"
                    if gp.already_romanized :
                        line_out += "' class='transroman"
                    else :
                        line_out += "' class='trans"
                    
                    line_out += " blank" + tid + "'>"
                    line_out += "&#160;</div>"
                    line_out += "</td>"
                    line_out += "</tr></table>"
                    line_out += "</td>"
                    if py :
                        line_out += "<td>&#160;</td>"
                line_out += "</tr>"
                line_out += "</table>"

            if not disk :
                output += line_out
            else :
                output += disk_out

        mdebug("View Page " + str(page) + " story " + name + " complete.")
        return output

    def translate_and_check_array(self, req, name, requests, lang, from_lang) :
        mdebug("Acquiring mutex?")
        self.mutex.acquire()
        mdebug("Acquired.")

        assert(req.session.value['username'] in self.client)

        client = self.client[req.session.value['username']]
        assert(client)

        attempts = 15
        finished = False
        stop = False

        for attempt in range(0, attempts) :
            error = False 
            try : 
                if attempt > 0 :
                    mdebug("Previous attempt failed. Re-authenticating")
                    client.access_token = client.get_access_token()

                mdebug("Entering online translation.")
                result = client.translate_array(requests, lang, from_lang = from_lang)

                if not len(result) or "TranslatedText" not in result[0] :
                    mdebug("Probably key expired: " + str(result))
                else :
                    mdebug("Translation complete on attempt: " + str(attempt))
                    finished = True

            except ArgumentOutOfRangeException, e :
                error = "Missing results. Probably we timed out. Trying again: " + str(e)
            except TranslateApiException, e :
                error = "First-try translation failed: " + str(e)
            except IOError, e :
                error = "Connection error. Will try one more time: " + str(e)
            except urllib2.URLError, e :
                error = "Response was probably too slow. Will try again: " + str(e)
            except socket.timeout, e :
                error = "Response was probably too slow. Will try again: " + str(e)
            except Exception, e :
                error = "Unknown fatal translation error: " + str(e)
                stop = True
            finally :
                mdebug("Attempt: " + str(attempt) + " finally.")
                if not finished and not error :
                    error = "Translation API not available for some reason. =("
                if error :
                    self.store_error(req, name, error)

            if finished or stop :
                mdebug("Breaking attempt loop.")
                break

        self.mutex.release()

        if not finished :
            mdebug("Raising fatal error.")
            raise Exception(error)

        mdebug("Yay, finished.")
        return result
    
    def makestorylist(self, req):
        untrans_count = 0
        reading_count = 0
        reading = self.template("reading")
        noreview = self.template("noreview")
        untrans = self.template("untrans")
        finish = self.template("finished")
        
        items = []
        for result in req.db.view("stories/all", startkey=[req.session.value['username']], endkey=[req.session.value['username'], {}]) :
            tmp_story = result["value"]
            tmp_storyname = tmp_story["name"]
            items.append((tmp_storyname, tmp_story))

        items.sort(key = itemhelp, reverse = True)

        for name, story in items :
            reviewed = not ("reviewed" not in story or not story["reviewed"])
            finished = not ("finished" not in story or not story["finished"])
            if isinstance(story['uuid'], tuple) :
                uuid = story['uuid']
                mdebug("skipping UUID: " + uuid[0])
                continue

            if not story["translated"] : 
                untrans_count += 1
                untrans += self.sidestart(req, name, username, story, reviewed, finished)
                untrans += "\n"

                if not mobile :
                    untrans += "<div id='transbutton" + story['uuid'] + "'>"
                    untrans += "\n<a title='" + _("Delete") + "' style='font-size: x-small' class='btn-default btn-xs' onclick=\"trashstory('" + story['uuid'] + "', '" + story["name"] + "')\"><i class='glyphicon glyphicon-trash'></i></a>&#160;"

                    if req.session.value['username'] not in self.client :
                        untrans += _("Please add a translation API key in your account preferences to begin learning with this story") + ".<br/>"
                    else :
                        untrans += "\n<a style='font-size: x-small' class='btn-default btn-xs' onclick=\"trans('" + story['uuid'] + "')\">" + _("Translate") + "</a>"
                    if "last_error" in story and not isinstance(story["last_error"], str) :
                        for err in story["last_error"] :
                            untrans += "<br/>" + err.replace("\n", "<br/>")

                    untrans += "</div>&#160;"

                untrans += "<div style='display: inline' id='translationstatus" + story['uuid'] + "'></div>"

                if "translating" in story and story["translating"] :
                    untrans += "\n<script>translist.push('" + story["uuid"] + "');</script>"
                untrans += "</td>"
                untrans += "</tr>"
            else :
                notsure = self.sidestart(req, name, username, story, reviewed, finished)
                if not mobile :
                    notsure += "\n<a title='" + _("Forget") + "' style='font-size: x-small' class='btn-default btn-xs' onclick=\"dropstory('" + story['uuid'] + "')\"><i class='glyphicon glyphicon-remove'></i></a>"
                notsure += "\n<a title='" + _("Review") + "' style='font-size: x-small' class='btn-default btn-xs' href=\"/home?view=1&#38;uuid=" + story['uuid'] + "\"><i class='glyphicon glyphicon-search'></i></a>"
                notsure += "\n<a title='" + _("Edit") + "' style='font-size: x-small' class='btn-default btn-xs' href=\"/edit?view=1&#38;uuid=" + story['uuid'] + "\"><i class='glyphicon glyphicon-pencil'></i></a>"
                notsure += "\n<a title='" + _("Read") + "' style='font-size: x-small' class='btn-default btn-xs' href=\"/read?view=1&#38;uuid=" + story['uuid'] + "\"><i class='glyphicon glyphicon-book'></i></a>"

                if finished :
                   finish += notsure
                   finish += "\n<a title='" + _("Not finished") + "' style='font-size: x-small' class='btn-default btn-xs' onclick=\"finishstory('" + story['uuid'] + "', 0)\"><i class='glyphicon glyphicon-thumbs-down'></i></a>"
                   finish += "</td></tr>"
                elif reviewed :
                   reading_count += 1
                   reading += notsure
                   reading += "\n<a title='" + _("Review not complete") + "' style='font-size: x-small' class='btn-default btn-xs' onclick=\"reviewstory('" + story['uuid'] + "',0)\"><i class='glyphicon glyphicon-arrow-down'></i></a>"
                   reading += "<a title='" + _("Finished reading") + "' style='font-size: x-small' class='btn-default btn-xs' onclick=\"finishstory('" + story['uuid'] + "',1)\"><i class='glyphicon glyphicon-thumbs-up'></i></a>"
                   reading += "</td></tr>"
                else :
                   noreview += notsure
                   noreview += "\n<a title='" + _("Review Complete") + "' style='font-size: x-small' class='btn-default btn-xs' onclick=\"reviewstory('" + story['uuid'] + "', 1)\"><i class='glyphicon glyphicon-arrow-up'></i></a>"
                   noreview += "</td></tr>"
                   
        return [untrans_count, reading, noreview, untrans, finish, reading_count] 
    
    def memocount(self, req, story, page):
        added = {}
        unique = {}
        progress = []
        total_memorized = 0
        total_unique = 0
        trans_id = 0
        page_dict = req.db[self.story(req, story["name"]) + ":pages:" + str(page)]
        units = page_dict["units"]
        
        memorized = self.view_keys(req, "memorized", units) 

        for x in range(0, len(units)) :
            unit = units[x]
            if "hash" not in unit :
                trans_id += 1
                continue
            ret = self.get_parts(unit, story["source_language"])
            if not ret :
                trans_id += 1
                continue
            py, target = ret
            if unit["hash"] in memorized :
                if unit["hash"] not in added :
                    added[unit["hash"]] = unit
                    progress.append([py, target, unit, x, trans_id, page])
                    total_memorized += 1

            if py and py not in global_processors[story["source_language"]].punctuation :
                unique[unit["hash"]] = True

            trans_id += 1
        
        total_unique = len(unique)
        if "total_memorized" not in story or story["total_memorized"] != total_memorized :
            story["total_memorized"] = total_memorized
        if "total_unique" not in story or story["total_unique"] != total_unique :
            story["total_unique"] = total_unique 
        
        return [total_memorized, total_unique, unique, progress]

    def add_record(self, req, unit, mindex, which, key) :
        char = "".join(unit["source"])
        hcode = self.get_polyphome_hash(mindex, unit["source"])

        changes = req.db.__getitem__(which(req, char), false_if_not_found = True)
        if not changes :
            changes = {} 
            changes["record"] = {}
        
        changes["source"] = unit["source"]

        if hcode not in changes["record"] :
            hcode_contents = {"total_" + key : 0}
        else :
            hcode_contents = changes["record"][hcode]

        hcode_contents["total_" + key] += 1
        if len(unit["multiple_sromanization"]) :
            hcode_contents["sromanization"] = unit["multiple_sromanization"][mindex] if mindex != -1 else unit["sromanization"]
        else :
            hcode_contents["sromanization"] = ""

        hcode_contents["target"] = unit["multiple_target"][mindex] if mindex != -1 else unit["target"]
        hcode_contents["date"] = timest()

        changes["record"][hcode] = hcode_contents

        if "total" not in changes :
            changes["total"] = 0

        changes["total"] += 1

        req.db[which(req, char)] = changes
                
    def operation(self, req, story, edit, offset):
        operation = edit["operation"]

        Processor = getattr(processors, processor_map[story["source_language"]])
        processor = Processor(self, params)

        if operation == "split" :
            nb_unit = int(edit["nbunit"]) + offset
            mindex = int(edit["index"])
            mhash = edit["tid"]
            page = edit["pagenum"]
            page_dict = req.db[self.story(req, story['name']) + ":pages:" + str(page)]
            units = page_dict["units"]
            before = units[:nb_unit] if (nb_unit > 0) else []
            after = units[nb_unit + 1:] if (nb_unit != (len(units) - 1)) else []
            curr = units[nb_unit]
            groups = []

            for char in curr["source"] :
                groups.append(char.encode("utf-8"))

            processor.parse_page(False, req, story, groups, page, temp_units = True)

            page_dict["units"] = before + story["temp_units"] + after

            req.db[self.story(req, story['name']) + ":pages:" + str(page)] = page_dict
            offset += (len(story["temp_units"]) - len(curr))
            del story["temp_units"]
            self.add_record(req, curr, mindex, self.splits, "splits")

        elif operation == "merge" :
            nb_units = int(edit["units"])
            nb_unit_start = int(edit["nbunit0"]) + offset
            mindex_start = int(edit["index0"])
            page = int(edit["page0"]) # all edits should be on the same page
            mhash_start = edit["tid0"]
            mindex_stop = int(edit["index" + str(nb_units - 1)])
            nb_unit_stop = int(edit["nbunit" + str(nb_units - 1)]) + offset
            mhash_stop = edit["tid" + str(nb_units - 1)]
            page_dict = req.db[self.story(req, story['name']) + ":pages:" + str(page)]
            units = page_dict["units"]
            before = units[:nb_unit_start] if (nb_unit_start > 0) else [] 
            after = units[nb_unit_stop + 1:] if (nb_unit_stop != (len(units) - 1)) else [] 
            curr = units[nb_unit_start:(nb_unit_stop + 1)]
            group = ""

            for chargroup in curr :
                for char in chargroup["source"] :
                    group += char.encode("utf-8")

            processor.parse_page(False, req, story, [group], page, temp_units = True)

            if len(story["temp_units"]) == 1 :
                merged = story["temp_units"][0]
                merged_chars = "".join(merged["source"])
                page_dict["units"] = before + [merged] + after
                req.db[self.story(req, story['name']) + ":pages:" + str(page)] = page_dict

                for unit in curr :
                    char = "".join(unit["source"])
                    mindex = unit["multiple_correct"]
                    hcode = self.get_polyphome_hash(mindex, unit["source"])

                    changes = req.db.__getitem__(self.merge(req, char), false_if_not_found = True)
                    if not changes :
                        changes = {} 
                        changes["record"] = {}
                        changes["source"] = unit["source"]

                    if hcode not in changes["record"] :
                        hcode_contents = {}
                        hcode_contents["sromanization"] = unit["multiple_sromanization"][mindex] if mindex != -1 else unit["sromanization"]
                        hcode_contents["target"] = unit["multiple_target"][mindex] if mindex != -1 else unit["target"]
                        hcode_contents["date"] = timest()
                        hcode_contents["members"] = {}
                    else :
                        hcode_contents = changes["record"][hcode]
    
                    if merged_chars not in hcode_contents["members"] :
                        merged_pinyin = merged["multiple_sromanization"][merged["multiple_correct"]] if merged["multiple_correct"] != -1 else merged["sromanization"]
                        hcode_contents["members"][merged_chars] = { "date" : timest(), "total_merges" : 0, "romanization" : " ".join(merged_pinyin)}

                    hcode_contents["members"][merged_chars]["total_merges"] += 1

                    changes["record"][hcode] = hcode_contents

                    if "total" not in changes :
                        changes["total"] = 0

                    changes["total"] += 1

                    req.db[self.merge(req, char)] = changes

                offset += (len(story["temp_units"]) - len(curr))
            if "temp_units" in story :
                del story["temp_units"]
            
        mdebug("Completed edit with offset: " + str(offset))
        return [True, offset]

    def add_story_from_source(self, req, filename, source, filetype, removespaces, source_lang, target_lang) :
        if req.db.doc_exist(self.story(req, filename)) :
            return self.bootstrap(req, self.heromsg + "\n" + _("Upload Failed! Story already exists") + ": " + filename + "</div>")
        
        mdebug("Received new story name: " + filename)
        if removespaces :
            mdebug("Remove spaces requested!")
        else :
            mdebug("Remove spaces not requested.")
        
        if filetype == "txt" :
            mdebug("Source: " + source)

        new_uuid = str(uuid4.uuid4())

        story = {
            'uuid' : new_uuid,
            'translated' : False,
            'name' : filename,
            'filetype' : filetype,
            'source_language' : source_lang.decode("utf-8"), 
            'target_language' : target_lang.decode("utf-8"), 
            'format' : story_format,
            'date' : timest(),
        }
        
        if filetype == "pdf" :
            new_source = {}
            fp = StringIO(source)
            pagenos = set()

            pagecount = 0

            rsrcmgr = PDFResourceManager()
            device = PDFPageAggregator(rsrcmgr, laparams=LAParams())
            interpreter = PDFPageInterpreter(rsrcmgr, device)

            for page in PDFPage.get_pages(fp, pagenos, 0, password='', caching=True, check_extractable=True):
                interpreter.process_page(page)
                layout = device.get_result()

                data2 = []
                images = []
                for obj in layout :
                    sub_data, sub_images = parse_lt_objs(obj, pagecount)
                    data2 += sub_data
                    images += sub_images

                new_page = filter_lines(data2)

                data = "\n".join(new_page)
                mdebug("Page input:\n " + data + " \nfor page: " + str(pagecount))

                de_data = data.decode("utf-8") if isinstance(data, str) else data

                if removespaces :
                    de_data = de_data.replace(u' ', u'')
                    mdebug("After remove spaces:\n " + de_data + " \nfor page: " + str(pagecount))

                '''
                FIXME: We're not deleting the attachments here properly upon failure.
                '''
                
                req.db.put_attachment(self.story(req, filename) + ":original:" + str(pagecount),
                                        "attach",
                                        str({ "images" : images, "contents" : de_data }), 
                                       )

                pagecount += 1

            device.close()
            fp.close()
        elif filetype == "txt" :
            de_source = source.decode("utf-8") if isinstance(source, str) else source
            mdebug("Page input:\n " + source)
            if removespaces :
                de_source = de_source.replace(u' ', u'')
                mdebug("After remove spaces:\n " + de_source)
            req.db[self.story(req, filename) + ":original"] = { "value" : de_source }
        
        req.db[self.story(req, filename)] = story
        req.db[self.index(req, story["uuid"])] = { "value" : filename }

        self.clear_story(req)

        uc = self.heromsg + "\n" + _("Upload Complete! Story ready for translation") + ": " + filename + "</div>"
        return self.bootstrap(req, uc)
        
        
    def flush_pages(self, req, name):
        mdebug("Ready to flush translated pages.")
        allpages = []
        for result in req.db.view('stories/allpages', startkey=[req.session.value['username'], name], endkey=[req.session.value['username'], name, {}]) :
            allpages.append(result["key"][2])

        mdebug("List complete.")
        for tmppage in allpages :
            mdebug("Deleting page " + str(tmppage) + " from story " + name)
            del req.db[self.story(req, name) + ":pages:" + str(tmppage)]

        mdebug("Completed flushing translated pages.")
            
        if req.db.doc_exist(self.story(req, name) + ":final") :
            mdebug("Deleting final version from story " + name)
            del req.db[self.story(req, name) + ":final"]

    def view_check(self, req, name, recreate = False) :
       fh = open(cwd + "views/" + name + ".js", 'r')
       vc = fh.read()
       fh.close()

       try :
           if recreate :
               mdebug("Recreate design document requested for view: " + name)
               del req.db["_design/" + name]
       except Exception, e :
           mwarn("Deleting design document: " + str(e))
           pass

       if not req.db.doc_exist("_design/" + name) :
           mdebug("View " + name + " does not exist. Uploading.")
           req.db["_design/" + name] = json.loads(vc)

    def clear_story(self, req) :
        uuid = False
        if "current_story" in req.session.value :
            uuid = req.session.value["current_story"]
            del req.session.value["current_story"]
            req.session.save()

    def set_page(self, req, story, page) :
        if "current_page" not in story or story["current_page"] != str(page) :
            mdebug("Setting story " + story["name"] + " to page: " + str(page))
            tmp_story = req.db[self.story(req, story["name"])]
            tmp_story["current_page"] = story["current_page"] = str(page)
            req.db[self.story(req, story["name"])] = tmp_story


    def warn_not_replicated(self, req, bootstrap = True, now = False) :
        if mobile :
            msg = _("This account is not fully synchronized. You can follow the progress at the top of the screen until the 'download' arrow reaches 100.")
        else :
            if "connected" in req.session.value and req.session.value["connected"] :
                req.session.value["connected"] = False
                req.session.save()

            msg = _("Missing key on server. Please report this to the author. Thank you.")

        if bootstrap :
            mwarn("bootstrapping: " + msg)
            return self.bootstrap(req, self.heromsg + "\n<h4>" + msg + "</h4></div>", now = now)
        else :
            mwarn("raw: " + msg)
            return msg

    def disconnect(self, session) :
        session.value['connected'] = False
        username = session.value['username']
        if username in self.dbs :
            del self.dbs[username]

        if username in self.view_runs :
            del self.view_runs[username]

        if username in self.client :
            del self.client[username]

        if session.value['database'] in self.client :
            del self.client[session.value['database']]

        session.save()

    def check_all_views(self, req) :
        self.view_check(req, "stories")
        self.view_check(req, "tonechanges")
        self.view_check(req, "mergegroups")
        self.view_check(req, "splits")
        self.view_check(req, "memorized")

    '''
    All stories up to and including mica version 0.4.x only supported
    Chinese and were not generalized to support other languages. Thus,
    the story dictionary format had a very chinese-specific layout.

    To fix this, these pre v0.5.0 stories are thus assumed to have a 
    format of '1', i.e. the first version we started with.
    This is detected if the key "format" is not contained within the
    document for the respective story in question.

    Formats 2 and higher restructure the basic unit structure of a story
    to support other languages.

    Format 1 => Format 2
    ========================
    spinyin => sromanization
    tpinyin => tromanization
    multiple_english => multiple_target
    multiple_spinyin => multiple_sromanization
    english => target
    match_pinyin => match_romanization

    '''

    def upgrade2(self, req, story) :
        conversions = dict(spinyin = u"sromanization", tpinyin = u"tromanization", multiple_english = u"multiple_target", multiple_spinyin = u"multiple_sromanization", english = u"target", match_pinyin = u"match_romanization", pinyin = u"romanization")

        mdebug("Going to upgrade story to version 2.")
        name = story["name"]
        story["upgrading"] = True
        story["upgrade_page"] = "0"

        if "date" not in story :
           story["date"] = timest()

        if "source_language" not in story :
            story["source_language"] = u"zh-CHS"
        if "target_language" not in story :
            story["target_language"] = u"en"
        req.db[self.story(req, name)] = story
        story = req.db[self.story(req, name)]

        try :
            mdebug("First checking analytics...")
            # upgrade the analytics
            design_docs = [ "memorized", "mergegroups", "tonechanges", "splits" ]

            for ddoc in design_docs :
                if req.db.doc_exist("_design/" + ddoc) :
                    mdebug("Design doc " + ddoc + " converting...")
                    for result in req.db.view(ddoc + "/all") :
                        try :
                            doc = result["value"]
                        except Exception, e :
                            merr("Failed to get value out of result: " + str(result))
                            raise e

                        if doc["_id"].count(':mergegroups:\n') :
                            mdebug("Deleting: " + doc["_id"])
                            del req.db[doc["_id"]]
                            continue

                        changed = False

                        if "date" not in doc :
                           doc["date"] = timest()
                           changed = True

                        for old, new in conversions.iteritems() :
                            if old in doc :
                                try :
                                    doc[new] = doc[old]
                                    del doc[old]
                                    changed = True
                                except Exception, e :
                                    merr("Failed to upgrade: new " + new + " old " + old + " doc " + str(doc))
                                    raise e

                            if "record" in doc :
                                for hcode in doc["record"] :

                                    if "date" not in doc["record"][hcode] :
                                       doc["record"][hcode]["date"] = timest()
                                       changed = True

                                    if old in doc["record"][hcode] :
                                        try :
                                            doc["record"][hcode][new] = doc["record"][hcode][old]
                                            del doc["record"][hcode][old]
                                            changed = True
                                        except Exception, e :
                                            merr("Failed to upgrade record: new " + new + " old " + old + " doc " + str(doc))
                                            raise e

                                    if "members" in doc["record"][hcode] :
                                        for member in doc["record"][hcode]["members"] :

                                            if "date" not in doc["record"][hcode]["members"][member] :
                                               doc["record"][hcode]["members"][member]["date"] = timest()
                                               changed = True

                                            if old in doc["record"][hcode]["members"][member] :
                                                try :
                                                    doc["record"][hcode]["members"][member][new] = doc["record"][hcode]["members"][member][old]
                                                    del doc["record"][hcode]["members"][member][old]
                                                    changed = True
                                                except Exception, e :
                                                    merr("Failed to upgrade record member: new " + new + " old " + old + " doc " + str(doc))
                                                    raise e

                        if changed :
                            try :
                                req.db[doc["_id"]] = doc
                            except Exception, e :
                                merr("Failed to save doc: " + str(doc) + str(e))
                                raise e
                else :
                    mdebug("Design doc " + ddoc + " not found.")

            for result in req.db.view('stories/allpages', startkey=[req.session.value['username'], name], endkey=[req.session.value['username'], name, {}]) :
                page = result["key"][2]
                page_dict = result["value"]
                new_units = []
                units = page_dict["units"]
                mdebug("Want to upgrade: " + str(page_dict["_id"]) + " units " + str(len(units)))
                for idx in range(0, len(units)) :
                    unit = units[idx]

                    for old, new in conversions.iteritems() :
                        if old in unit :
                            unit[new] = unit[old]
                            del unit[old]

                    new_units.append(unit)

                mdebug("Units done for page: " + str(page))
                page_dict["units"] = new_units
                # DO MORE CHECKING AND THEN RELEASE THE HOUND

                req.db[self.story(req, name) + ":pages:" + str(page)] = page_dict
                story["upgrade_page"] = str(int(story["upgrade_page"]) + 1)
                req.db[self.story(req, name)] = story
                story = req.db[self.story(req, name)]
                mdebug("next page...")

            mdebug("Story upgrade complete.")

            del story["upgrading"]
            story["format"] = 2
            req.db[self.story(req, name)] = story
            mdebug("Exiting")
        except Exception, e :
            self.store_error(req, name, "Failure to upgrade story: " + str(e))

    def common(self, req) :
        try :
            if req.action == "privacy" :
                output = ""
                helpfh = codecs.open(cwd + "serve/privacy_template.html", "r", "utf-8")
                output += helpfh.read().encode('utf-8').replace("\n", "<br/>")
                helpfh.close()
                return self.bootstrap(req, output, pretend_disconnected = True)
            elif req.http.params.get("connect") :
                if params["mobileinternet"] and params["mobileinternet"].connected() == "none" :
                    return self.bootstrap(req, self.heromsg + "\n<h4>" + deeper + _("To login for the first time and begin synchronization with the website, you must activate internet access.") + "</h4></div>")
                username = req.http.params.get('username')
                password = req.http.params.get('password')
                address = req.http.params.get('address')
                req.session.value["username"] = username
                req.session.value["address"] = address
                if mobile :
                    req.session.value["password"] = password
                req.session.save()

                auth_user = self.authenticate(username, password, address)

                if not auth_user :
                    return self.bootstrap(req, self.heromsg + "\n" + deeper + _("Invalid credentials. Please try again") + ".</h4></div>")

                req.session.value["database"] = auth_user["mica_database"] 
                req.session.save()

                self.verify_db(req, auth_user["mica_database"], password = password)

                if mobile :
                    if req.db.doc_exist("MICA:appuser") :
                       mdebug("There is an existing user. Verifying it is the same one.")
                       appuser = req.db["MICA:appuser"]
                       if appuser["username"] != username :
                            return self.bootstrap(req, self.heromsg + "\n<h4>" + deeper + _("We're sorry. The MICA Reader database on this device already belongs to the user") + " " + \
                                appuser["username"] + " " + _("and is configured to stay in sync replication with the server") + ". " + \
                                _("If you want to change users, you will need to clear this application's data or reinstall it and re-synchronize the app with") + " " + \
                                _("a new account. This requirement is because MICA databases can become large over time, so we want you to be aware of that. Thanks.") + "</h4></div>")
                    else :
                       mdebug("First time user. Reserving this device: " + username)
                       appuser = {"username" : username}
                       req.db["MICA:appuser"] = appuser
                           
                    if not req.db.replicate(address, username, password, req.session.value["database"], params["local_database"]) :
                        return self.bootstrap(req, self.heromsg + "\n<h4>" + deeper + _("Although you have authenticated successfully, we could not start replication successfully. Please try again.") + "</h4></div>")

                req.action = "home"
                req.session.value['connected'] = True 
                req.session.save()

                if req.http.params.get('remember') and req.http.params.get('remember') == 'on' :
                    req.session.value['last_username'] = username
                    req.session.value['last_remember'] = 'checked'
                elif 'last_username' in req.session.value :
                    del req.session.value['last_username']
                    req.session.value['last_remember'] = ''
                req.session.save()

                self.clear_story(req)

                req.session.value["last_refresh"] = str(timest())
                req.session.save()

                user = req.db.__getitem__(self.acct(username), false_if_not_found = True)
                if not user :
                    return self.warn_not_replicated(req)
                    
                if "language" not in user :
                    user["language"] = params["language"]

                if "date" not in user :
                    user["date"] = timest()

                if "story_format" not in user :
                    mwarn("Story format is missing. Upgrading design document for story upgrades.")
                    self.view_check(req, "stories", recreate = True)
                    user["story_format"] = story_format

                self.install_language(user["language"])

                if "app_chars_per_line" not in user :
                    user["app_chars_per_line"] = 70
                if "web_chars_per_line" not in user :
                    user["web_chars_per_line"] = 70
                if "default_app_zoom" not in user :
                    user["default_app_zoom"] = 1.2
                if "default_web_zoom" not in user :
                    user["default_web_zoom"] = 1.0

                req.session.value["app_chars_per_line"] = user["app_chars_per_line"]
                req.session.value["web_chars_per_line"] = user["web_chars_per_line"]
                req.session.value["default_app_zoom"] = user["default_app_zoom"]
                req.session.value["default_web_zoom"] = user["default_web_zoom"]
                req.session.value["language"] = user["language"]
                req.db[self.acct(username)] = user
                req.session.save()

                if not mobile :
                    try :
                        if not req.db.doc_exist("MICA:filelisting") :
                            req.db["MICA:filelisting"] = {"foo" : "bar"} 

                        listing = req.db["MICA:filelisting"]

                        if '_attachments' not in listing or 'cedict.db' not in listing['_attachments'] :
                            minfo("Opening cedict file: " + params["cedict"])
                            fh = open(params["cedict"], 'r')
                            minfo("Uploading cedict to file listing...")
                            req.db.put_attachment("MICA:filelisting", 'cedict.db', fh, new_doc = listing)
                            fh.close()
                            minfo("Uploaded.")
                            listing = req.db["MICA:filelisting"]

                        if '_attachments' not in listing or 'cjklib.db' not in listing['_attachments'] :
                            minfo("Opening cjklib file: " + params["cjklib"])
                            fh = open(params["cjklib"], 'r')
                            minfo("Uploading cjklib to file listing...")
                            req.db.put_attachment("MICA:filelisting", 'cjklib.db', fh, new_doc = listing)
                            fh.close()
                            minfo("Uploaded.")
                    except TypeError, e :
                        mwarn("Account documents don't exist yet. Probably they are being replicated." + str(e))
                    except couch_adapter.ResourceNotFound, e :
                        mwarn("Account document @ MICA:filelisting not found: " + str(e))
                    except Exception, e :
                        mwarn("Database not available yet: " + str(e))
                
            if 'connected' not in req.session.value or req.session.value['connected'] != True :
                req.deeper = deeper
                req.mobile = mobile
                return self.bootstrap(req, load_template(req, FrontPageElement))
                
            username = req.session.value['username']

            if "app_chars_per_line" not in req.session.value :
                user = req.db[self.acct(username)]
                if user :
                    req.session.value["app_chars_per_line"] = user["app_chars_per_line"]
                    req.session.value["web_chars_per_line"] = user["web_chars_per_line"]
                    req.session.value["default_app_zoom"] = user["default_app_zoom"]
                    req.session.value["default_web_zoom"] = user["default_web_zoom"]
                    req.session.save()

            if username not in self.first_request :
                self.check_all_views(req)

                if params["transcheck"] :
                    for result in req.db.view("stories/translating", startkey=[req.session.value['username']], endkey=[req.session.value['username'], {}]) :
                        tmp_storyname = result["key"][1]
                        tmp_story = req.db[self.story(req, tmp_storyname)]
                        mdebug("Killing stale translation session: " + tmp_storyname)
                        tmp_story["translating"] = False

                        if "last_error" in tmp_story :
                            del tmp_story["last_error"]

                        try :
                            req.db[self.story(req, tmp_storyname)] = tmp_story
                        except couch_adapter.ResourceConflict, e :
                            mdebug("Conflict: No big deal. Another thread killed the session correctly.") 

                        if params["transreset"] :
                            self.flush_pages(req, tmp_storyname)

                    if "upgrading" not in req.db["_design/stories"]["views"] :
                        self.view_check(req, "stories", recreate = True)
                        
                    for result in req.db.view("stories/upgrading", startkey=[req.session.value['username']], endkey=[req.session.value['username'], {}]) :
                        tmp_storyname = result["key"][1]
                        tmp_story = req.db[self.story(req, tmp_storyname)]
                        mdebug("Killing stale upgrade session: " + tmp_storyname)
                        tmp_story["upgrading"] = False

                        if "last_error" in tmp_story :
                            del tmp_story["last_error"]

                        try :
                            req.db[self.story(req, tmp_storyname)] = tmp_story
                        except couch_adapter.ResourceConflict, e :
                            mdebug("Conflict: No big deal. Another thread killed the session correctly.") 

                self.first_request[username] = True 
                    
            if req.http.params.get("uploadfile") :
                removespaces = True if req.http.params.get("removespaces", 'off') == 'on' else False
                fh = req.http.params.get("storyfile")
                filetype = req.http.params.get("filetype")
                source_lang = req.http.params.get("source_language")
                target_lang = req.http.params.get("target_language")
                source = fh.file.read()
                return self.add_story_from_source(req, fh.filename.lower().replace(" ","_"), source, filetype, removespaces, source_lang, target_lang)

            if req.http.params.get("uploadtext") :
                removespaces = True if req.http.params.get("removespaces", 'off') == 'on' else False
                source = req.http.params.get("storytext") + "\n"
                filename = req.http.params.get("storyname").lower().replace(" ","_")
                source_lang = req.http.params.get("source_language")
                target_lang = req.http.params.get("target_language")
                return self.add_story_from_source(req, filename, source, "txt", removespaces, source_lang, target_lang) 

            start_page = "0"
            view_mode = "text"
            meaning_mode = "false";
            list_mode = True
            uuid = False
            name = False
            story = False

            if req.http.params.get("uuid") :
                uuid = req.http.params.get("uuid") 

                name = req.db[self.index(req, uuid)]["value"]
                name_found = True if name else False
                    
                if not name :
                    if req.http.params.get("name") :
                        name = req.http.params.get("name")
                    
                if name and name_found :
                    story = req.db[self.story(req, name)]

                    # Language support came later, so assume all old stories
                    # are in Chinese

                    if "source_language" not in story :
                        mdebug("Source Language is missing. Setting default to Chinese")
                        story["source_language"] = u"zh-CHS"
                        req.db[self.story(req, name)] = story
                        story = req.db[self.story(req, name)]

                    if "target_language" not in story :
                        mdebug("Target Language is missing. Setting default to English")
                        story["target_language"] = u"en"
                        req.db[self.story(req, name)] = story
                        story = req.db[self.story(req, name)]

                    if "format" not in story :
                        mdebug("Format is missing. Setting default to format #1")
                        story["format"] = 1 
                        req.db[self.story(req, name)] = story
                        story = req.db[self.story(req, name)]
                        
                    if "date" not in story :
                        mdebug("Date is missing. Setting.")
                        story["date"] = timest()
                        req.db[self.story(req, name)] = story
                        story = req.db[self.story(req, name)]


            if req.http.params.get("delete") :
                story_found = False if not name else req.db.doc_exist(self.story(req, name))
                if name and not story_found :
                    mdebug(name + " does not exist. =(")
                else :
                    if name :
                        tmp_story = req.db[self.story(req, name)]
                        self.flush_pages(req, name)
                        if "filetype" not in tmp_story or tmp_story["filetype"] == "txt" :
                            mdebug("Deleting txt original contents.")
                            del req.db[self.story(req, name) + ":original"]
                        else :
                            mdebug("Deleting original pages")
                            allorig = []
                            for result in req.db.view('stories/alloriginal', startkey=[req.session.value['username'], name], endkey=[req.session.value['username'], name, {}]) :
                                allorig.append(result["key"][2])
                            mdebug("List built.")
                            for tmppage in allorig :
                                mdebug("Deleting original " + str(tmppage) + " from story " + name)
                                del req.db[self.story(req, name) + ":original:" + str(tmppage)]
                            mdebug("Deleted.")

                        
                    if name and story_found :
                        del req.db[self.story(req, name)]
                    
                    if req.db.doc_exist(self.index(req, uuid)) :
                        del req.db[self.index(req, uuid)]
                
                        
                if "current_story" in req.session.value and req.session.value["current_story"] == uuid :
                    self.clear_story(req)
                    uuid = False
                return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Deleted") + ".</h4></div>", now = True)

            if uuid :
                if not req.db.doc_exist(self.index(req, uuid)) :
                    self.clear_story(req)
                    return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Invalid story uuid") + ": " + uuid + "</h4></div>")

            if req.http.params.get("tstatus") :
                out = "<div id='tstatusresult'>"
                if not req.db.doc_exist(self.index(req, uuid)) :
                    out += "error 25 0 0"
                else :
                    if "translating" not in story or not story["translating"] :
                        out += "no 0 0 0"
                    else :
                        curr = float(int(story["translating_current"]))
                        total = float(int(story["translating_total"]))

                        out += "yes " + str(int(curr / total * 100))
                        out += (" " + str(story["translating_page"])) if "translating_page" in story else "0"
                        out += (" " + str(story["translating_pages"])) if "translating_pages" in story else "1"
                        
                out += "</div>"
                return self.bootstrap(req, self.heromsg + "\n" + out + "</div>", now = True)

            if req.http.params.get("finished") :
                finished = True if req.http.params.get("finished") == "1" else False
                tmp_story = req.db[self.story(req, name)]
                tmp_story["finished"] = finished 
                req.db[self.story(req, name)] = tmp_story 
                return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Finished") + ".</h4></div>", now = True)

            if req.http.params.get("reviewed") :
                reviewed = True if req.http.params.get("reviewed") == "1" else False
                tmp_story = req.db[self.story(req, name)]
                tmp_story["reviewed"] = reviewed
                if reviewed :
                    if "finished" not in tmp_story or tmp_story["finished"] :
                        tmp_story["finished"] = False

                    pages = self.nb_pages(req, tmp_story["name"])
                    if pages == 1 :
                        final = {}
                        minfo("Generating final pagesets...")
                        
                        for page in range(0, pages) :
                            minfo("Page " + str(page) + "...")
                            final[str(page)] = self.view_page(req, uuid, name, \
                                story, req.action, "", str(page), \
                                req.session.value["app_chars_per_line"] if mobile else req.session.value["web_chars_per_line"], meaning_mode, disk = True)
                            
                        req.db[self.story(req, name) + ":final"] = final
                req.db[self.story(req, name)] = tmp_story 
                return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Reviewed") + ".</h4></div>", now = True)

            if req.http.params.get("forget") :
                tmp_story = req.db[self.story(req, name)]
                tmp_story["translated"] = False
                tmp_story["reviewed"] = False
                tmp_story["finished"] = False

                if "last_error" in tmp_story :
                    del tmp_story["last_error"]

                req.db[self.story(req, name)] = tmp_story 
                self.flush_pages(req, name)

                story = tmp_story
                
                if "current_story" in req.session.value and req.session.value["current_story"] == uuid :
                    self.clear_story(req)
                    uuid = False
                return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Forgotten") + ".</h4></div>", now = True)

            if req.http.params.get("switchmode") :
                req.session.value["view_mode"] = req.http.params.get("switchmode")
                req.session.save()
                return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Mode changed") + ".</h4></div>", now = True)

            if req.http.params.get("meaningmode") :
                req.session.value["meaning_mode"] = req.http.params.get("meaningmode")
                req.session.save()
                return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Mode changed") + ".</h4></div>", now = True)

            if req.http.params.get("switchlist") :
                req.session.value["list_mode"] = True if int(req.http.params.get("switchlist")) == 1 else False
                req.session.save()
                return self.bootstrap(req, self.heromsg + "\n<h4>" + _("List statistics mode changed") + ".</h4></div>", now = True)

            if req.http.params.get("instant") :
                source = req.http.params.get("instant")
                human = int(req.http.params.get("human")) if req.http.params.get("human") else 0
                out = ""
                out += "<div id='instantresult'>"

                p = ""
                if req.session.value['username'] not in self.client :
                    p += _("Offline only. Missing a translation API key in your account preferences.")
                elif not params["mobileinternet"] or params["mobileinternet"].connected() != "none" :
                    final = { }
                    requests = [source]
                    
                    if not story :
                        name = req.db[self.index(req, req.session.value["current_story"])]["value"]
                        story = req.db[self.story(req, name)]
                    gp = global_processors[story["source_language"]]
                    breakout = source.decode("utf-8") if isinstance(source, str) else source
                    if gp.already_romanized :
                        breakout = breakout.split(" ")
                    
                    if len(breakout) > 1 :
                        for x in range(0, len(breakout)) :
                            requests.append(breakout[x].encode("utf-8"))
                    result = self.translate_and_check_array(req, False, requests, story["target_language"], story["source_language"])
                    for x in range(0, len(requests)) : 
                        part = result[x]
                        if "TranslatedText" not in part :
                            mdebug("Why didn't we get anything: " + json.dumps(result))
                            target = _("No translation available.")
                        else :
                            target = part["TranslatedText"].encode("utf-8")
                        
                        if x == 0 :
                            p += _("Selected translation") + " (" + source + "): " + target + "<br/>\n"
                            final["whole"] = (source, target)
                        else :
                            char = breakout[x-1].encode("utf-8")
                            if "parts" not in final :
                                p += _("Piecemeal translation") + ":<br/>\n"
                                final["parts"] = []
                            p += "(" + char + "): "
                            p += target 
                            p += "<br/>\n"
                            final["parts"].append((char, target))
                else :
                    p += _("No internet access. Offline only.")
                       
                if human :
                    out += "<h4>" + _("Online translation") + ":</h4>"
                    out += p 
                    out += "<h4>" + _("Offline translation") + ":</h4>"

                    try :
                        opaque = gp.parse_page_start()
                        tar = gp.get_first_translation(opaque, source.decode("utf-8"), False)
                        if tar :
                            for target in tar :
                                out += "<br/>" + target.encode("utf-8")
                        else :
                            out += _("None found.")
                        gp.parse_page_stop(opaque)
                    except OSError, e :
                        out += _("Please wait until this account is fully synchronized for an offline translation.")
                else :
                    out += json.dumps(final)
                out += "</div>"
                return self.bootstrap(req, self.heromsg + "\n<h4>" + out + "</h4></div>", now = True)

            if req.http.params.get("translate") :
                output = "<div id='translationstatusresult'>" + self.heromsg
                if story["translated"] :
                    output += _("Story already translated. To re-translate, please select 'Forget'.")
                else :
                    try :
                        self.parse(req, story)
                        output += self.heromsg + _("Translation complete!")
                    except OSError, e :
                        output += self.warn_not_replicated(req, bootstrap = False)
                    except Exception, e :
                        output += _("Failed to translate story") + ": " + str(e)
                output += "</div></div>"
                return self.bootstrap(req, output, now = True)

            # Functions only go here if they are actions against the currently reading story
            # Functions above here can happen on any story
            
            if "current_story" in req.session.value :
                if uuid :
                    if req.session.value["current_story"] != uuid :
                        self.clear_story(req)
                    req.session.value["current_story"] = uuid
                    req.session.save()
                else :
                    uuid = req.session.value["current_story"]
            elif uuid :
                self.clear_story(req)
                req.session.value["current_story"] = uuid
                req.session.save()
                
            if uuid : 
                tmp_story = story
                if not tmp_story :
                    name = req.db[self.index(req, uuid)]["value"]
                    tmp_story = req.db.__getitem__(self.story(req, name), false_if_not_found = True)
                    if not tmp_story :
                        self.clear_story(req)
                        mwarn("Could not lookup: " + self.story(req, name))
                        return self.warn_not_replicated(req)
                        
                if "current_page" in tmp_story :
                    start_page = tmp_story["current_page"]
                    mdebug("Loading start page: " + str(start_page))
                else :
                    self.set_page(req, tmp_story, start_page)
                
            #mdebug("Start page will be: " + str(start_page))

            if "view_mode" in req.session.value :
                view_mode = req.session.value["view_mode"]
            else :
                req.session.value["view_mode"] = view_mode 
                req.session.save()

            if "meaning_mode" in req.session.value :
                meaning_mode = req.session.value["meaning_mode"]
            else :
                req.session.value["meaning_mode"] = meaning_mode 
                req.session.save()

            mdebug("Meaning mode is: " + meaning_mode)

            if "list_mode" in req.session.value :
                list_mode = req.session.value["list_mode"]
            else :
                req.session.value["list_mode"] = list_mode 
                req.session.save()

            if req.http.params.get("multiple_select") :
                nb_unit = int(req.http.params.get("nb_unit"))
                mindex = int(req.http.params.get("index"))
                trans_id = int(req.http.params.get("trans_id"))
                page = req.http.params.get("page")
                
                # This is also kind of silly: getting a whole page
                # of units just to update one of them.
                # Maybe it's not so high overhead. I dunno.
                page_dict = req.db[self.story(req, name) + ":pages:" + str(page)]
                unit = page_dict["units"][nb_unit]
                
                unit["multiple_correct"] = mindex
                
                self.rehash_correct_polyphome(unit) 
                
                page_dict["units"][nb_unit] = unit
                req.db[self.story(req, name) + ":pages:" + str(page)] = page_dict

                self.add_record(req, unit, mindex, self.tones, "selected") 

                return self.bootstrap(req, self.heromsg + "\n<div id='multiresult'>" + \
                                           self.polyphomes(req, story, uuid, unit, nb_unit, trans_id, page) + \
                                           "</div></div>", now = True)

            output = ""

            if req.http.params.get("phistory") :
                page = req.http.params.get("page")
                return self.bootstrap(req, self.heromsg + "\n<div id='historyresult'>" + \
                                           (self.history(req, story, uuid, page) if list_mode else "<h4>" + _("Review History List Disabled") + ".</h4>") + \
                                           "</div></div>", now = True)

            if req.http.params.get("editslist") :
                page = req.http.params.get("page")
                return self.bootstrap(req, self.heromsg + "\n<div id='editsresult'>" + \
                                           self.edits(req, story, uuid, page, list_mode) + \
                                           "</div></div>", now = True)

            if req.http.params.get("memorized") :
                memorized = int(req.http.params.get("memorized"))
                nb_unit = int(req.http.params.get("nb_unit"))
                page = req.http.params.get("page")
                
                # FIXME This is kind of stupid - looking up the whole page
                # just to get the hash of one unit.
                # But, we are storing the whole unit dict inside
                # the memorization link - maybe or maybe not we shouldn't
                # be doing that, or we could put the whole unit's json
                # into the original memorization request. I dunno.
                
                page_dict = req.db[self.story(req, name) + ":pages:" + str(page)]
                unit = page_dict["units"][nb_unit]
                
                if memorized :
                    unit["date"] = timest()
                    req.db[self.memorized(req, unit["hash"])] = unit
                else :
                    del req.db[self.memorized(req, unit["hash"])]
                    
                return self.bootstrap(req, self.heromsg + "\n<div id='memoryresult'>" + _("Memorized!") + " " + \
                                           unit["hash"] + "</div></div>", now = True)

            if req.http.params.get("storyupgrade") :
                if mobile :
                    return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Story upgrades not allowed on mobile devices.") + ".</h4></div>")

                version = int(req.http.params.get("version"))

                original = 0
                if "format" not in story or story["format"] == 1 :
                    if version != 2 :
                        return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Invalid upgrade parameters 1") + " =>" + str(version) + ".</h4></div>")
                    original = 1

                # Add new story upgrades to this list here, like this:
                #elif "format" in story and story["format"] == 2 :
                #    if version != 3 :
                #        return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Invalid upgrade parameters 2") + " =>" + str(version) + ".</h4></div>")
                #    original = 2
                #    mdebug("Will upgrade from version 2 to 3")

                elif "format" in story and story["format"] == story_format and (not "upgrading" in story or not story["upgrading"]) :
                    return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Upgrade complete") + ".</h4></div>")
                else :
                    return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Invalid request.") + ".</h4></div>")

                if version > story_format :
                    return self.bootstrap(req, self.heromsg + "\n<h4>" + _("No such story format") + " :" + str(version) + ".</h4></div>")

                if "upgrading" in story and story["upgrading"] :
                    curr_page = story["upgrade_page"] if "upgrade_page" in story else 0
                    nbpages = self.nb_pages(req, story["name"])
                    assert(nbpages > 0)
                    percent = float(curr_page) / float(nbpages) * 100
                    out = self.heromsg + "\n<h4>" + _("Story upgrade status") + ": " + _("Page") + " " + str(curr_page) + "/" + str(nbpages) + ", " + '{0:.1f}'.format(percent) + "% ...</h4></div>"
                    if "last_error" in story and not isinstance(story["last_error"], str) :
                        out += "<br/>" + _("Last upgrade Exception") + ":<br/>"
                        for err in story["last_error"] :
                            out += "<br/>" + err.replace("\n", "<br/>")
                        del story["upgrading"]
                        del story["last_error"]
                        req.db[self.story(req, story["name"])] = story
                        story = req.db[self.story(req, story["name"])]
                    return self.bootstrap(req, out)

                if "last_error" in story :
                    mdebug("Clearing out last error message.")
                    del story["last_error"]
                    req.db[self.story(req, story["name"])] = story
                    story = req.db[self.story(req, story["name"])]

                mdebug("Starting upgrade thread...")
                if original == 1 : 
                    ut = Thread(target = self.upgrade2, args=[req, story])
                #elif original == 2 :
                #    ut = Thread(target = self.upgrade3, args=[req, story])
                ut.daemon = True
                ut.start()
                mdebug("Upgrade thread started.")
                return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Story upgrade started. You may refresh to follow its status.") + "</h4></div>")


            if req.http.params.get("oprequest") :
                oprequest = req.http.params.get("oprequest");
                edits = json.loads(oprequest) 
                offset = 0
                
                for edit in edits :
                    mdebug("Processing edit: " + str(edit))
                    if isinstance(edit, str) or str(edit).strip() == "" :
                        merr("Skipping Wierd edit request: " + str(edit))
                        continue
                    if edit["failed"] :
                        mdebug("This edit failed. Skipping.")
                        continue

                    try :
                        result = repeat(self.operation, args = [req, story, edit, offset], kwargs = {})
                    except OSError, e :
                        return self.warn_not_replicated(req)
                    
                    if not result[0] and len(result) > 1 :
                        return self.bootstrap(req, result[1])
                    
                    ret = result[1:]
                    success = ret[0]
                    offset = ret[1]
                    
                    if not success :
                        return self.bootstrap(req, self.heromsg + "\n" + _("Invalid Operation") + ": " + str(edit) + "</div>")
                    
            if req.http.params.get("memolist") :
                page = req.http.params.get("page")
                output = ""
                        
                result = self.memocount(req, story, page)
                
                total_memorized, total_unique, unique, progress = result

                pr = str(int((float(total_memorized) / float(total_unique)) * 100)) if total_unique > 0 else 0
                for result in req.db.view('memorized/allcount', startkey=[req.session.value['username']], endkey=[req.session.value['username'], {}]) :
                    output += _("Memorized all stories") + ": " + str(result['value']) + "<br/>"
                output += _("Unique memorized page") + ": " + str(total_memorized) + "<br/>"
                output += _("Unique words this page") + ": " + str(len(unique)) + "<br/>"
                if list_mode :
                    output += "<div class='progress progress-success progress-striped'><div class='progress-bar' style='width: "
                    output += str(pr) + "%;'> (" + str(pr) + "%)</div></div>"

                    if total_memorized :
                        output += "<div class='panel-group' id='panelMemorized'>\n"
                        for p in progress :
                            output += """
                                    <div class='panel panel-default'>
                                      <div class="panel-heading">
                                      """
                            py, target, unit, nb_unit, trans_id, page_idx = p
                            if len(target) and target[0] == '/' :
                                target = target[1:-1]
                            tid = unit["hash"] if py else trans_id 

                            output += "<a class='trans btn-default btn-xs' onclick=\"forget('" + \
                                    str(tid) + "', '" + uuid + "', '" + str(nb_unit) + "', '" + str(page_idx) + "')\">" + \
                                    "<i class='glyphicon glyphicon-remove'></i></a>"

                            output += "&#160; " + "".join(unit["source"]) + ": "
                            output += "<a class='panel-toggle' style='display: inline' data-toggle='collapse' data-parent='#panelMemorized' href='#collapse" + tid + "'>"

                            output += "<i class='glyphicon glyphicon-arrow-down' style='size: 50%'></i>&#160;" + py
                            output += "</a>"
                            output += "</div>"
                            output += "<div id='collapse" + tid + "' class='panel-body collapse'>"
                            output += "<div class='panel-inner'>" + target.replace("/"," /") + "</div>"
                            output += "</div>"
                            output += "</div>"
                        output += "</div>"
                    else :
                        output += "<h4>" + _("No words memorized. Get to work!") + "</h4>"
                else :
                    output += "<h4>" + _("Memorization History List Disabled") + ".</h4>"

                return self.bootstrap(req, self.heromsg + "\n<div id='memolistresult'>" + output + "</div></div>", now = True)
               
            if req.http.params.get("retranslate") :
                page = req.http.params.get("page")
                try :
                    self.parse(req, story, page = page)
                except OSError, e :
                    return self.warn_not_replicated(req)
                
            if req.action in ["home", "read", "edit" ] :
                
                if uuid :
                    # Reload just in case the translation changed anything
                    name = req.db[self.index(req, uuid)]["value"]
                    story = req.db[self.story(req, name)]
                    gp = global_processors[story["source_language"]]
                    
                    if req.action == "edit" and gp.already_romanized :
                        return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Edit mode is only supported for learning character-based languages") + ".</h4></div>\n")
                    
                    if req.http.params.get("page") and not req.http.params.get("retranslate") :
                        page = req.http.params.get("page")
                        mdebug("Request for page: " + str(page))
                        if page == "-1" :
                            page = start_page

                        if req.http.params.get("image") :
                            nb_image = req.http.params.get("image")
                            output = "<div><div id='pageresult'>"
                            image_found = False
                            if "filetype" in story and story["filetype"] != "txt" :
                                attach_raw = req.db.get_attachment(self.story(req, name) + ":original:" + str(page), "attach")
                                original = eval(attach_raw)

                                if "images" in original and int(nb_image) < len(original["images"]) :
                                    # I think couch is already base-64 encoding this, so if we can find
                                    # away to get that out of couch raw, then we shouldn't have to re-encode this ourselves.
                                    output += "<img src='data:image/jpeg;base64," + base64.b64encode(original["images"][int(nb_image)]) + "' width='100%' height='100%'/>"
                                    image_found = True
                            if not image_found :
                               output += _("Image") + " #" + str(nb_image) + " " + _("not available on this page")
                            output += "</div></div>"
                            return self.bootstrap(req, output, now = True)
                        else :
                            self.set_page(req, story, page)
                            output = self.view_page(req, uuid, name, story, req.action, output, page, req.session.value["app_chars_per_line"] if mobile else req.session.value["web_chars_per_line"], meaning_mode)
                            return self.bootstrap(req, "<div><div id='pageresult'>" + output + "</div></div>", now = True)
                    output = self.view(req, uuid, name, story, start_page, view_mode, meaning_mode)
                else :
                    output += self.heromsg + "<h4>" + _("No story loaded. Choose a story to read from the sidebar by clicking the 'M' at the top.")
                    if mobile :
                        output += "</h4><p><br/><h5>" + _("Brand new stories cannot (yet) be created/uploaded yet on the device. You must first create them on the website first. (New stories require a significant amount of computer resources to prepare. Thus, they can only be replicated to the device for regular use.") + "</h5>"
                    else :
                        output += "<br/>" + _("or create one by clicking on Account icon at the top") + ".</h4>"
                    output += "</div>"

                return self.bootstrap(req, output)
            elif req.action == "stories" :
                ftype = "txt" if "filetype" not in story else story["filetype"]
                if ftype != "txt" :
                    return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Story is a") + " " + ftype + ". " + _("Viewing original not yet implemented") + ".</h4></div>\n")
                
                if req.http.params.get("type") :
                    which = req.http.params.get("type")
                    
                    if which == "original" :
                        original = req.db[self.story(req, name) + ":original"]["value"]
                        return self.bootstrap(req, original.encode("utf-8").replace("\n","<br/>"))
                    elif which == "pinyin" :
                        final = req.db[self.story(req, name) + ":final"]["0"]
                        return self.bootstrap(req, final.encode("utf-8").replace("\n","<br/>"))
                    
            elif req.action == "storylist" :
                storylist = self.template("storylist")

                result = repeat(self.makestorylist, args = [req], kwargs = {})
                
                if not result[0] and len(result) > 1 :
                    return self.bootstrap(req, result[1])
                
                untrans_count, reading, noreview, untrans, finish, reading_count = result[1:]
                
                reading += "</table></div></div></div>\n"
                noreview += "</table></div></div></div>\n"
                untrans += "</table></div></div></div>\n"
                finish += "</table></div></div></div>\n"

                scripts = ""

                if untrans_count :
                    storylist += untrans + reading + noreview + finish + "</div></td></tr></table>"
                    scripts += """
                            <script>$('#collapseUntranslated').collapse('show');</script>
                            """
                elif reading_count :
                    storylist += reading + untrans + noreview + finish + "</div></td></tr></table>"
                    scripts += """
                            <script>$('#collapseReading').collapse('show');</script>
                            """
                else :
                    storylist += noreview + reading + untrans + finish + "</div></td></tr></table>"
                    scripts += """
                            <script>$('#collapseReviewing').collapse('show');</script>
                            """

                scripts += """
                            
                           <script>
                           for(var tidx = 0; tidx < translist.length; tidx++) {
                               trans_start(translist[tidx]);
                           }
                           translist = [];
                           </script>
                          """

                try :
                    finallist = load_template(req, StoryElement, storylist) + scripts
                except Exception, e:
                    merr("Storylist fill failed: " + str(e))

                return self.bootstrap(req, "<div><div id='storylistresult'>" + finallist + "</div></div>", now = True)
            
            elif req.action == "account" :
                out = ""

                if username == "demo" :
                    return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Demo account is read-only") + ".</h4></div>")
                 
                user = req.db.__getitem__(self.acct(username), false_if_not_found = True)

                if not user :
                    return self.warn_not_replicated(req)
                
                if req.http.params.get("pack") :
                    req.db.compact()
                    req.db.cleanup()
                    design_docs = ["memorized", "stories", "mergegroups",
                                   "tonechanges", "accounts", "splits" ]

                    for name in design_docs :
                        if req.db.doc_exist("_design/" + name) :
                            mdebug("Compacting view " + name)
                            req.db.compact(name)

                    out += self.heromsg + "\n<h4>" + _("Database compaction complete for your account") + ".</h4></div>\n"
                elif req.http.params.get("changepassword") :
                    if mobile :
                        return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Please change your password on the website, first") + ".</h4></div>")
                    oldpassword = req.http.params.get("oldpassword")
                    newpassword = req.http.params.get("password")
                    newpasswordconfirm = req.http.params.get("confirm")

                    if len(newpassword) < 8 :
                        return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Password must be at least 8 characters! Try again") + ".</h4></div>")
                    if newpassword != newpasswordconfirm :
                        return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Passwords don't match! Try again") + ".</h4></div>")
                    auth_user = self.authenticate(username, oldpassword, req.session.value["address"])
                    if not auth_user :
                        return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Old passwords don't match! Try again") + ".</h4></div>")
                    try :
                        auth_user['password'] = newpassword
                        del self.dbs[username]
                        self.verify_db(req, "_users", cookie = req.session.value["cookie"])
                        req.db["org.couchdb.user:" + username] = auth_user
                        del self.dbs[username]
                        self.verify_db(req, req.session.value["database"], newpassword)
                    except Exception, e :
                        return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Password change failed") + ": " + str(e) + "</h4></div>")
                        
                    out += self.heromsg + "\n<h4>" + _("Success!") + " " + _("User") + " " + username + " " + _("password changed") + ".</h4></div>"

                elif req.http.params.get("changecredentials") :
                    client_id = req.http.params.get("id")
                    client_secret = req.http.params.get("secret")
                    self.client[req.session.value['username']] = Translator(client_id, client_secret)

                    try :
                        # Doesn't matter which languages we test - we just want
                        # to make sure the credentials are valid
                        result = self.translate_and_check_array(req, False, samples[u"zh-CHS"], u"en", u"zh-CHS")

                        if not len(result) or "TranslatedText" not in result[0] :
                            tmsg = _("We tried to test your translation API credentials, but they didn't work. Please check them and try again =)")
                            del self.client[req.session.value['username']]
                        else :
                            user['translator_credentials'] = { 'id' : client_id, 'secret' : client_secret }
                            req.db[self.acct(username)] = user
                            tmsg = _("Your MS translation credentials have been changed to") + ": " + client_id + " => " + client_secret
                    except Exception, e :
                        del self.client[req.session.value['username']]
                        tmsg = _("We tried to test your translation API credentials, but they didn't work because") + ": " + str(e)

                    out += self.heromsg + "\n<h4>" + tmsg + "</h4></div>"

                elif req.http.params.get("newaccount") :
                    if not self.userdb : 
                        return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Server not configured correctly. Can't make accounts") + ".</h4></div>")

                    newusername = req.http.params.get("username")
                    newpassword = req.http.params.get("password")
                    newpasswordconfirm = req.http.params.get("confirm")
                    admin = req.http.params.get("isadmin", 'off')
                    language = "en" # make this dynamic later with a real signup process

                    if newusername == "mica_admin" :
                        return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Invalid account name! Try again") + ".</h4></div>")

                    if len(newpassword) < 8 :
                        return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Password must be at least 8 characters! Try again") + ".</h4></div>")
                    if newpassword != newpasswordconfirm :
                        return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Passwords don't match! Try again") + ".</h4></div>")
                    if 'admin' not in user["roles"] and admin == 'on' :
                        return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Non-admin users can't create admin accounts. What are you doing?!") + "</h4></div>")

                    if self.userdb.doc_exist("org.couchdb.user:" + newusername) :
                        return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Account already exists! Try again") + ".</h4></div>")
                    roles = ['normal']
                    if admin == 'on' :
                        roles.append('admin')

                    self.make_account(req, newusername, newpassword, roles, language = language)

                    out += self.heromsg + "\n<h4>" + _("Success! New user was created") + ": " + newusername + ".</h4></div>"
                elif req.http.params.get("changelanguage") :
                    language = req.http.params.get("language")
                    user["language"] = language
                    req.db[self.acct(username)] = user
                    req.session.value["language"] = language
                    req.session.save()
                    self.install_language(language)
                    out += self.heromsg + "\n<h4>" + _("Success! Language changed") + ".</h4></div>"
                elif req.http.params.get("setappchars") :
                    chars_per_line = int(req.http.params.get("setappchars"))
                    if chars_per_line > 1000 or chars_per_line < 5 :
                        return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Number of characters can't be greater than 1000 or less than 5") + ".</h4></div>")
                    user["app_chars_per_line"] = chars_per_line
                    req.db[self.acct(username)] = user
                    req.session.value["app_chars_per_line"] = chars_per_line 
                    req.session.save()
                    out += self.heromsg + "\n<h4>" + _("Success! Mobile Characters-per-line in a story set to:") + " " + str(chars_per_line) + ".</h4></div>"
                elif req.http.params.get("setwebchars") :
                    chars_per_line = int(req.http.params.get("setwebchars"))
                    if chars_per_line > 1000 or chars_per_line < 5:
                        return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Number of characters can't be greater than 1000 or less than 5") + ".</h4></div>")
                    user["web_chars_per_line"] = chars_per_line
                    req.db[self.acct(username)] = user
                    req.session.value["web_chars_per_line"] = chars_per_line 
                    req.session.save()
                    out += self.heromsg + "\n<h4>" + _("Success! Web Characters-per-line in a story set to:") + " " + str(chars_per_line) + ".</h4></div>"
                elif req.http.params.get("setappzoom") :
                    zoom = float(req.http.params.get("setappzoom"))
                    if zoom > 3.0 or zoom < 0.5 :
                        return self.bootstrap(req, self.heromsg + "\n<h4>" + _("App Zoom level must be a decimal no greater than 3.0 and no smaller than 0.5") + "</h4></div>")
                    user["default_app_zoom"] = zoom 
                    req.db[self.acct(username)] = user
                    req.session.value["default_app_zoom"] = zoom
                    req.session.save()
                    out += self.heromsg + "\n<h4>" + _("Success! App zoom level set to:") + " " + str(zoom) + ".</h4></div>"
                elif req.http.params.get("setwebzoom") :
                    zoom = float(req.http.params.get("setwebzoom"))
                    if zoom > 3.0 or zoom < 0.5 :
                        return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Web Zoom level must be a decimal no greater than 3.0 and no smaller than 0.5") + "</h4></div>")
                    user["default_web_zoom"] = zoom 
                    req.db[self.acct(username)] = user
                    req.session.value["default_web_zoom"] = zoom
                    req.session.save()
                    out += self.heromsg + "\n<h4>" + _("Success! Web zoom level set to:") + " " + str(zoom) + ".</h4></div>"

                out += "<p/><h4><b>" + _("Change Password?") + "</b></h4>"
                if not mobile :
                    out += load_template(req, PasswordElement)
                    out += """
                        <table>
                        <form action='/account' method='post' enctype='multipart/form-data'>
                        """
                else :
                    out += _("Please change your password on the website. Will support mobile in a future version.")

                client_id = _("Need your client ID")
                client_secret = _("Need your client secret")

                if username != "demo" and 'translator_credentials' in user :
                     client_id = user['translator_credentials']['id']
                     client_secret = user['translator_credentials']['secret']
                 
                out += "<tr><td><h5>&#160;" + _("Client ID") + ": </td><td><input type='text' name='id' value='" + client_id + "'/></h5></td></tr>"
                out += "<tr><td><h5>&#160;" + _("Client Secret") + ": </td><td><input type='text' name='secret' value='" + client_secret + "'/></h5></td></tr>"
                out += "<tr><td><button name='changecredentials' type='submit' class='btn btn-default btn-primary' value='1'>" + _("Change Credentials") + "</button></td></tr>"
                out += """
                    </table>
                    </form>
                    <p>
                    <br/>
                    """
                out += """
                        <a onclick="$('#compactModal').modal('show');"
                        """
                out += " class='btn btn-default btn-primary' href='/account?pack=1'>" + _("Compact databases") + "</a>"

                try :
                    out += "<h4><b>" + _("Change Viewing configuration") + "</b>?</h4>"
                    out += "<table>"
                    out += "<tr><td>&#160;" + _("Characters per line") + ":</td><td>"
                    out += "<form action='/account' method='post' enctype='multipart/form-data'>"
                    out += "<input type='text' name='" + ("setappchars" if mobile else "setwebchars")
                    out += "' value='" + str(user["app_chars_per_line" if mobile else "web_chars_per_line"]) + "'/>"
                    out += "</td><tr><td><button name='submit' type='submit' class='btn btn-default btn-primary' value='1'>" + _("Change") + "</button></td></tr>"
                    out += "</form>"
                    out += "</td></tr>"
                    out += "</table>"
                    out += "<table>"
                    out += "<tr><td><h5>&#160;" + _("Default zoom level") + ": </h5></td><td>"
                    out += "<form action='/account' method='post' enctype='multipart/form-data'>"
                    out += "<input type='text' name='" + ("setappzoom" if mobile else "setwebzoom")
                    out += "' value='" + str(user["default_app_zoom" if mobile else "default_web_zoom"]) + "'/>"
                    out += "</td><tr><td><button name='submit' type='submit' class='btn btn-default btn-primary' value='1'>" + _("Change") + "</button></td></tr>"
                    out += "</form>"
                    out += "</td></tr>"
                    out += "</table>"
                except KeyError, e :
                    merr("Keep having this problem: " + str(user) + " " + str(e))
                    raise e
                
                if not mobile and 'admin' in user['roles'] :
                    out += "<h4><b>" + _("Accounts") + "</b>:</h4>"
                    if not self.userdb :
                        out += _("Server is misconfigured. Cannot list accounts.")
                    else :
                        out += "<table>"
                        for result in self.userdb.view('accounts/all') :
                            tmp_doc = result["key"]
                            out += "<tr><td>" + tmp_doc["name"] + "</td></tr>"
                        out += "</table>"

                out += "<h4><b>" + _("Language") + "</b>?</h4>"
                out += """
                    <form action='/account' method='post' enctype='multipart/form-data'>
                    <select name="language">
                """
                softlangs = []
                for l, readable in lang.iteritems() :
                    locale = l.split("-")[0]
                    if locale not in softlangs :
                        softlangs.append((locale, readable))

                for l, readable in softlangs :
                    out += "<option value='" + l + "'"
                    if l == user["language"] :
                        out += "selected"
                    out += ">" + _(readable) + "</option>\n"
                out += """
                    </select>
                    <br/>
                    <br/>
                """
                out += "<button name='changelanguage' type='submit' class='btn btn-default btn-primary' value='1'>" + _("Change Language") + "</button></form>"

                return self.bootstrap(req, out)
                    
            elif req.action == "disconnect" :
                self.disconnect(req.session)
                return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Disconnected from MICA") + "</h4></div>")

            elif req.action == "help" :
                output = ""
                helpfh = codecs.open(cwd + "serve/info_template.html", "r", "utf-8")
                output += helpfh.read().encode('utf-8').replace("\n", "<br/>")
                helpfh.close()
                output = output.replace("https://raw.githubusercontent.com/hinesmr/mica/master", "")
                return self.bootstrap(req, output)
            else :
                return self.bootstrap(req, _("Read, Review, or Edit, my friend?"))

        except exc.HTTPTemporaryRedirect, e :
            raise e
        except couch_adapter.ResourceNotFound, e :
            return self.warn_not_replicated(req)
        except Exception, msg:
            mdebug(_("Exception") + ": " + str(msg))
            out = _("Exception") + ":\n" 
            resp = "<h4>" + _("Exception") + ":</h4>"
            for line in traceback.format_exc().splitlines() :
                resp += "<br>" + line
                out += line + "\n"
            mdebug(out)

            try :
                if isinstance(resp, str) :
                    resp = resp.decode("utf-8")

                resp += "<br/><h2>" + _("Please report the above exception to the author. Thank you") + ".</h2>"
                if "connected" in req.session.value and req.session.value["connected"] :
                    req.session.value["connected"] = False
                    req.session.save()
                return self.bootstrap(req, self.heromsg + "\n<h4 id='gerror'>" + _("Error: Something bad happened") + ": " + str(msg) + "</h4>" \
                                            + resp + "</div>")
            except Exception, e :
                merr("OTHER MICA ********Exception:")
                for line in traceback.format_exc().splitlines() :
                    merr("OTHER MICA ********" + line)
            return out

class IDict(Interface):
    value = Attribute("Dictionary for holding session keys and values.")

class CDict(object):
    implements(IDict)
    def __init__(self, session):
        start = {}
        uid = session.uid

        if params["keepsession"] :
            sfn = params["session_dir"] + "debug.session"
        else :
            sfn = params["session_dir"] + uid + ".session"

        if os.path.isfile(sfn) :
            mdebug("Loading existing session file: " + sfn)
            fh = open(sfn, 'r')
            sc = fh.read().strip()
            fh.close()
            if sc != "" :
                start = json.loads(sc)
        else :
            mdebug("No session existing session file: " + sfn)

        self.value = start 
        self.value["session_uid"] = uid
    def save(self) :
        if params["keepsession"] :
            sfn = params["session_dir"] + "debug.session"
        else :
            sfn = params["session_dir"] + self.value["session_uid"] + ".session"

        #mdebug("Saving to session file: " + sfn)
        fh = open(sfn, 'w')
        fh.write(json.dumps(self.value))
        fh.close()
        pass

sessions = set()

def expired(uid):
   sfn = params["session_dir"] + uid + ".session"
   mdebug("Session " + uid + " has expired.")
   sessions.remove(uid)
   mdebug("Removing session file.")
   os.remove(sfn)
        
class GUIDispatcher(Resource) :
    def __init__(self, mica) :

        Resource.__init__(self)
        self.serve = File(cwd + relative_prefix)
        # example of how to serve individual utf-8 encoded files:
        # self.stories = File(cwd + relative_prefix + "/../stories/")
        # self.stories.contentTypes['.txt'] = 'text/html; charset=utf-8'
        self.files = File(cwd)
        self.icon = File(cwd + relative_prefix + "/favicon.ico")
        self.git = File(cwd + "/.git")
        self.git.indexNames = ["test.rpy"]
        self.mica = mica
            
        self.app = WSGIResource(reactor, reactor.threadpool, self.mica)

    def getChild(self, name, request) :
        # Hack to make WebOb work with Twisted
        request.content.seek(0,0)
        request.setHeader('Access-Control-Allow-Origin', '*')
        request.setHeader('Access-Control-Allow-Origin', '*')
        request.setHeader('Access-Control-Allow-Methods', 'GET')
        request.setHeader('Access-Control-Allow-Headers', 'x-prototype-version,x-requested-with')
        request.setHeader('Access-Control-Max-Age', 2520)
        request.setHeader('Content-Type', 'text/html; charset=utf-8')

        s = request.getSession()
        request.session = IDict(s)
        if s.uid not in sessions :
            sessions.add(s.uid)
            s.notifyOnExpire(lambda: expired(s.uid))

        if name.count(relative_prefix_suffix):
            return self.serve
        #if name.count("stories") :
        #    return self.stories
        if name.count("favicon.ico"):
            return self.icon
        elif name.count("git"):
            return self.git
        else :
            return self.app

class MicaSession(Session) :
    sessionTimeout = 604800 # one week 

class NONSSLRedirect(object) :
    def __init__(self):
        pass

    def __call__(self, environ, start_response):
        req = Params(environ, start_response.im_self.request.session)
        (req.dest, req.path) = prefix(req.unparsed_uri)
        tossl = "https://" + req.dest + ":" + str(params["sslport"]) + "/" + req.path 
        mdebug("Redirecting non-ssl request to: " + tossl)
        resp = exc.HTTPTemporaryRedirect(location = tossl)
        return resp(environ, start_response)
        
class NONSSLDispatcher(Resource) :
    def __init__(self) :

        Resource.__init__(self)
            
        self.nonssl = NONSSLRedirect()
        self.app = WSGIResource(reactor, reactor.threadpool, self.nonssl)

    def getChild(self, name, request) :
        s = request.getSession()
        request.session = IDict(s)
        if s.uid not in sessions :
            sessions.add(s.uid)
            s.notifyOnExpire(lambda: expired(s.uid))
        return self.app

def get_options() :
    from optparse import OptionParser

    parser = OptionParser()

    parser.add_option("-p", "--port", dest = "port", default = "80", help ="port")
    parser.add_option("-s", "--sslport", dest = "sslport", default = "443", help ="sslport")
    parser.add_option("-H", "--host", dest = "host", default = "0.0.0.0", help ="hostname")
    parser.add_option("-k", "--keepsession", dest = "keepsession", action = "store_true", default = False, help ="do not destroy the previous HTTP session")
    parser.add_option("-r", "--transreset", dest = "transreset", action = "store_true", default = False, help ="Throw away old, failed translation sessions")
    parser.add_option("-d", "--debug_host", dest = "debug_host", default = None, help ="Hostname for remote debugging")
    parser.add_option("-l", "--log", dest = "log", default = cwd + "logs/mica.log", help ="MICA main log file.")
    parser.add_option("-t", "--tlog", dest = "tlog", default = cwd + "logs/twisted.log", help ="Twisted log file.")
    parser.add_option("-C", "--cert", dest = "cert", default = False, help = "Path to certificate for Twisted to run OpenSSL")
    parser.add_option("-K", "--privkey", dest = "privkey", default = False, help = "Path to private key for Twisted to run OpenSSL")
    parser.add_option("-a", "--slaves", dest = "slaves", default = "127.0.0.1", help = "List of slave addresses")
    parser.add_option("-w", "--slave_port", dest = "slave_port", default = "5050", help = "Port on which the slaves are running")
    parser.add_option("-e", "--cedict", dest = "cedict", default = False, help = "Location of cedict.db file used by cjklib library.")
    parser.add_option("-j", "--cjklib", dest = "cjklib", default = False, help = "Location of cjklib.db file used by cjklib library.")
    parser.add_option("-T", "--tonefile", dest = "tonefile", default = False, help = "Location of pinyin tone txt file.")
    parser.add_option("-z", "--serialize", dest = "serialize", action = "store_true", default = False, help ="Serialize accesses to the couchbase database on mobile.")

    parser.add_option("-U", "--adminuser", dest = "adminuser", default = False, help = "couch administrator username for server account creation.")
    parser.add_option("-P", "--adminpass", dest = "adminpass", default = False, help = "couch administrator password for server account creation.")

    parser.add_option("-f", "--couchserver", dest = "couchserver", default = "localhost", help = "address of couchdb database")
    parser.add_option("-g", "--couchproto", dest = "couchproto", default = "https", help = "couchdb http protocol (https|http)")
    parser.add_option("-i", "--couchport", dest = "couchport", default = "6984", help = "couchdb port")

    parser.set_defaults()
    options, args = parser.parse_args()

    params = {
               "port" : options.port,
               "sslport" : int(options.sslport),
               "host" : options.host,
               "keepsession" : options.keepsession,
               "debug_host" : options.debug_host,
               "log" : options.log,
               "tlog" : options.tlog,
               "cert" : options.cert,
               "privkey" : options.privkey,
               "slaves" : options.slaves,
               "slave_port" : options.slave_port,
               "cedict" : options.cedict,
               "cjklib" : options.cjklib,
               "tonefile" : options.tonefile,
               "mobileinternet" : False,
               "transreset" : options.transreset,
               "transcheck" : True,
               "duplicate_logger" : False,
               "serialize_couch_on_mobile" : options.serialize,
               "admin_user" : options.adminuser,
               "admin_pass" : options.adminpass,
               "couch_server" : options.couchserver,
               "couch_proto" : options.couchproto,
               "couch_port" : options.couchport, 
    }

    return params 

slaves = {}
params = None

def go(p) :
    global params
    params = p

    for l in lang :
       locale = l.split("-")[0]
       try:
           texts[locale] = gettext.GNUTranslations(open(cwd + "res/messages_" + locale + ".mo", 'rb'))
       except IOError:
           if l == u"en" :
               texts[locale] = gettext.NullTranslations()
           else :
               mdebug("Language translation " + l + " failed. Bailing...")
               exit(1)

    params["language"] = init_localization()
    mdebug("Verifying options.")

    if mobile and "local_database" not in params :
        merr("local_database parameter missing on mobile platform.")
        exit(1)

    if "couch" not in params and mobile :
        merr("We are mobile. Please pass reference to platform-specific couch instance.")
        exit(1)

    if "couch_server" not in params or "couch_port" not in params or "couch_proto" not in params :
        merr("Parameters to reach the couchdb server are required (address, protocol, and port")
        exit(1)

    if ("admin_user" not in params or "admin_pass" not in params or not params["admin_user"] or not params["admin_pass"]) :
        if not mobile :
            mwarn("This is not a mobile deployment and you have not specified admin credentials to be used on the server-side for account management. You will only be able to access existing accounts but not create new ones.")
        params["admin_user"] = False
        params["admin_pass"] = False
    else :
        if mobile :
            merr("This is a mobile deployment and you have specified admin credentials to be used on the server-side for account management. Don't do that.")
            exit(1)

    if "session_dir" not in params :
        params["session_dir"] = cwd + "mica_session/"

    mdebug("Session dir: " + params["session_dir"])

    sslport = int(params["sslport"])
    if sslport != -1 and (not params["cert"] or not params["privkey"]) :
        merr("Need locations of SSL certificate and private key (options -C and -K). You can generate self-signed ones if you want, see the README.")
        exit(1)

    if not params["cedict"] or not params["cjklib"]:
        merr("You must provide the path to compatible CJKLIB and CEDICT files named 'cedict.db' and 'cjklib.db'. If you don't have them, you'll need to steal them from somewhere, like a linux box where CJKLIB has been installed or build them yourself following their instructions. If you build them, they will be located in the corresponding python installation directory for CJK.")
        exit(1)

    if "serialize_couch_on_mobile" not in params :
        params["serialize_couch_on_mobile"] = False

    if not params["keepsession"] :
        if os.path.isdir(params["session_dir"]) :
            mdebug("Destroying all session files")
            try :
                shutil.rmtree(params["session_dir"])
            except Exception, e :
                merr("Failed to remove tree: " + str(e))

    if not os.path.isdir(params["session_dir"]) :
        mdebug("Making new session folder.")
        os.makedirs(params["session_dir"])

    mdebug("Registering session adapter.")
    registerAdapter(CDict, Session, IDict)

    mdebug("Initializing logging.")
    mica_init_logging(params["log"], duplicate = params["duplicate_logger"])

    if "tonefile" not in params or not params["tonefile"] :
        params["tonefile"] = cwd + "/chinese.txt" # from https://github.com/lxyu/pinyin

    if params["tlog"] :
        if params["tlog"] != 1 :
            mdebug("Initializing twisted log.")
            log.startLogging(DailyLogFile.fromFullPath(params["tlog"]), setStdout=True)
    else :
        mdebug("Skipping twisted log")

    try :
        if params["slaves"] :
            slave_addresses = params["slaves"].split(",")

            for slave_address in slave_addresses :
                slave_uri = "http://" + slave_address + ":" + str(params["slave_port"])
                minfo("Registering slave @ " + slave_uri)
                slaves[slave_uri] = MICASlaveClient(slave_uri)
                #slaves[slave_uri].foo("bar")

            assert(len(slaves) >= 1)

        db_adapter = getattr(couch_adapter, params["couch_adapter_type"])

        if params["serialize_couch_on_mobile"] :
            params["q"] = Queue.Queue()

        mica = MICA(db_adapter)

        for l, processor_name in lang.iteritems() :
            if processor_map[l] :
                global_processors[l] = getattr(processors, processor_map[l])(mica, params)

        mica.install_language(params["language"])

        reactor._initThreadPool()
        site = Site(GUIDispatcher(mica))
        site.sessionFactory = MicaSession
        nonsslsite = Site(NONSSLDispatcher())
        nonsslsite.sessionFactory = MicaSession

        if sslport != -1 :
            from twisted.internet import ssl
            from OpenSSL import SSL

            class ChainedOpenSSLContextFactory(ssl.DefaultOpenSSLContextFactory):
                def __init__(self, privateKeyFileName, certificateChainFileName, sslmethod=SSL.SSLv23_METHOD):
                    """
                    @param privateKeyFileName: Name of a file containing a private key
                    @param certificateChainFileName: Name of a file containing a certificate chain
                    @param sslmethod: The SSL method to use
                    """
                    self.privateKeyFileName = privateKeyFileName
                    self.certificateChainFileName = certificateChainFileName
                    self.sslmethod = sslmethod
                    self.cacheContext()
                
                def cacheContext(self):
                    ctx = SSL.Context(self.sslmethod)
                    ctx.use_certificate_chain_file(self.certificateChainFileName)
                    ctx.use_privatekey_file(self.privateKeyFileName)
                    self._context = ctx

            reactor.listenTCP(int(params["port"]), nonsslsite, interface = params["host"])
            reactor.listenSSL(sslport, site, ChainedOpenSSLContextFactory(privateKeyFileName=params["privkey"], certificateChainFileName=params["cert"], sslmethod = SSL.SSLv3_METHOD), interface = params["host"])
            minfo("Point your browser at port: " + str(sslport) + ". (Bound to interface: " + params["host"] + ")")
        else :
            mwarn("Disabling SSL access. Be careful =)")
            minfo("Point your browser at port: " + str(params["port"]) + ". (Bound to interface: " + params["host"] + ")")
            reactor.listenTCP(int(params["port"]), site, interface = params["host"])

        if params["debug_host"] :
            try :
                import debug
                mdebug(str(sys.path))
                import pydevd
                pydevd.settrace(host=params["debug_host"])
            except ImportError, msg :
                mwarn("Failed to import debug file for remote debugging: " + str(msg), True)
                params["debug_host"] = None
                exit(1)

        if params["serialize_couch_on_mobile"] :
            minfo("We will serialize couchdb access. Setting up queue and coroutine.")
            if mobile :
                rt = Thread(target = reactor.run, kwargs={"installSignalHandlers" : 0})
            else :
                rt = Thread(target = reactor.run)

            rt.daemon = True
            rt.start()

            while True :
                while True :
                    try :
                        (co, req, rq) = params["q"].get(timeout=10000)
                        break
                    except Queue.Empty :
                        pass
                try :
                    co.send((req, rq))
                except StopIteration :
                    params["q"].task_done()
                    continue

                params["q"].task_done()

            rt.join()
        else :
            reactor.run()

    except Exception, e :
        merr("Startup exception: " + str(e))
        for line in traceback.format_exc().splitlines() :
            merr(line)

def second_splash() :
    fh = open(cwd + "serve/splash_template.html", 'r')
    output = fh.read()
    fh.close()

    fh = open(cwd + "serve/icon.png", 'r')
    contents = fh.read()
    encoded1 = base64.b64encode(contents)
    fh.close()

    output += "<img src='data:image/jpeg;base64," + str(encoded1) + "' width='100%'/>"
    output += """
</div>
<div class="inner2">
"""
    output += "<p><p><p>"
    fh = open(cwd + "serve/spinner.gif", 'r')
    contents = fh.read() 
    encoded2 = base64.b64encode(contents)
    fh.close()
    output += "<img src='data:image/jpeg;base64," + str(encoded2) + "' width='10%'/>"
    output += "&#160;&#160;" + _("Please wait...") + "</p>"
    output += """ 
</div>    
<div class="inner3">
</div>    
</body>  
</html> 
"""
    return output

if __name__ == "__main__":
    mdebug("Ready to go.")
    params = get_options()
    params["couch_adapter_type"] = "MicaServerCouchDB"
    go(params)

