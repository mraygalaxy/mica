#!/usr/bin/env python
# coding: utf-8

from pwd import getpwuid
from sys import path
from time import sleep
from threading import Thread, Lock, current_thread, Timer, local as threading_local
from datetime import datetime as datetime_datetime
import threading
from copy import deepcopy
from cStringIO import StringIO
from traceback import format_exc
from os import path as os_path, getuid as os_getuid, urandom as os_urandom, remove as os_remove, makedirs as os_makedirs
from re import compile as re_compile, IGNORECASE as re_IGNORECASE, sub as re_sub
from shutil import rmtree as shutil_rmtree
from urllib2 import quote as urllib2_quote, Request as urllib2_Request, urlopen as urllib2_urlopen, URLError as urllib2_URLError, HTTPError as urllib2_HTTPError
from urllib import urlencode
from codecs import open as codecs_open
from uuid import uuid4 as uuid_uuid4
from hashlib import md5 as hashlib_md5
from json import loads as json_loads, dumps as json_dumps
from base64 import b64encode as base64_b64encode
from socket import timeout as socket_timeout
from Queue import Queue as Queue_Queue, Empty as Queue_Empty
from string import ascii_lowercase as string_ascii_lowercase, ascii_uppercase as string_ascii_uppercase
from binascii import hexlify as binascii_hexlify
from sys import settrace as sys_settrace


import couch_adapter
import processors
from processors import * 
from common import *
from translator import *
from templates import *

uploads_enabled = True

if not mobile :
    from oauthlib.common import to_unicode
    from requests_oauthlib import OAuth2Session
    from requests_oauthlib.compliance_fixes import facebook_compliance_fix
    try :
        import PythonMagick
    except ImportError, e :
        # TODO: not using this boolean anywhere yet....
        uploads_enabled = False
        mdebug("Cannot find PythonMagick: uploads will be disabled on this server.")

mdebug("Initial imports complete")

cwd = re_compile(".*\/").search(os_path.realpath(__file__)).group(0)
import sys
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

from webob import Request, Response, exc

if not mobile :
    try :
        from pdfminer.pdfinterp import PDFResourceManager, PDFPageInterpreter
        from pdfminer.converter import PDFPageAggregator
        from pdfminer.layout import LAParams, LTPage, LTTextBox, LTText, LTContainer, LTTextLine, LTImage, LTRect, LTCurve
        from pdfminer.pdfpage import PDFPage
    except ImportError, e :
        mdebug("Could not import pdfminer. Full translation will not work.")
        pass

mdebug("Imports complete.")

pdf_punct = ",卜「,\,,\\,,【,\],\[,>,<,】,〈,@,；,&,*,\|,/,-,_,—,,,，,.,。,?,？,:,：,\:,\：,：,\：,\、,\“,\”,~,`,\",\',…,！,!,（,\(,）,\),口,」,了,丫,㊀,。,门,X,卩,乂,一,丁,田,口,匕,《,》,化,*,厂,主,竹,-,人,八,七,，,、,闩,加,。,』,〔,飞,『,才,廿,来,兀,〜,\.,已,I,幺,去,足,上,円,于,丄,又,…,〉".decode("utf-8")

for letter in (string_ascii_lowercase + string_ascii_uppercase) :
    pdf_punct += letter.decode("utf-8")

pdf_expr = r"([" + pdf_punct + "][" + pdf_punct + "]|[\x00-\x7F][\x00-\x7F]|[\x00-\x7F][" + pdf_punct + "]|[" + pdf_punct + "][\x00-\x7F])"

mdebug("Punctuation complete.")

multipliers = { "days" : 7, "weeks" : 4, "months" : 12, "years" : 10, "decades" : 10 }
# All the months are not the same.... not sure what to do about that
counts = { "days" : 1, "weeks" : 7, "months" : 30, "years" : 365, "decades" : 3650 }
period_mapping = {"days" : "week", "weeks" : "month", "months" : "year", "years" : "decade", "decades" : "decade"}
period_story_mapping = {"week" : "%a", "month" : "%m/%d", "year" : "%b", "decade" : "%Y"}
period_view_mapping = {"days" : "%a %I:%M:%S %p", "weeks" : "%m/%d %I:%M:%S %p", "months" : "%m/%d %I:%M:%S %p", "years" : "%m/%d %I:%M:%S %p", "decades" : "%m/%d/%y %I:%M:%S %p"}
translated_periods = { "days" : _("days"), "day" : _("day"), "weeks" : _("weeks"), 
                "week" : _("week"), "months" : _("months"), "month" : _("month"),
                "years" : _("year"), "year" : _("years") }

def parse_lt_objs (lt_objs, page_number):
    text_content = [] 
    images = []

    if lt_objs :
        if isinstance(lt_objs, LTTextBox) or isinstance(lt_objs, LTText):
            text_content.append(lt_objs.get_text().strip())
        elif isinstance(lt_objs, LTImage):
            images.append(lt_objs.stream.get_data())
        elif isinstance(lt_objs, LTContainer):
            for lt_obj in lt_objs:
                sub_text, sub_images = parse_lt_objs(lt_obj, page_number)
                text_content = text_content + sub_text
                for image in sub_images :
                    images.append(image)

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

        for match in re_compile(r'[0-9]+ +[0-9, ]+', flags=re_IGNORECASE).findall(line) :
            line = line.replace(match, match.replace(" ", ""))

        temp_line = line.strip().decode("utf-8") if isinstance(line, str) else line.strip()
        if len(temp_line) == 3 and temp_line[0] == "(" and temp_line[-1] == ")" :
            matches = re_compile(u'\(.\)', flags=re_IGNORECASE).findall(temp_line)

            if len(matches) == 1 :
                continue

        line = re_sub(r'( *82303.*$|[0-9][0-9][0-9][0-9][0-9]+ *)', '', line)
        test_all = re_sub(r'([\x00-\x7F]| )+', '', line)

        if test_all == "" :
            continue

        no_numbers = re_sub(r"([0-9]| )+", "", line)
        if isinstance(no_numbers, str) :
            no_numbers = no_numbers.decode("utf-8")
        while len(re_compile(pdf_expr).findall(no_numbers)) :
            no_numbers = re_sub(pdf_expr, '', no_numbers)
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
username = getpwuid(os_getuid())[0]
relative_prefix_suffix = "serve"
relative_prefix = "/" + relative_prefix_suffix

def prefix(uri) :
    result = re_compile("[^/]*\:\/\/([^/]*)(\/(.*))*").search(uri)
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
            mdebug("New session. Setting connected to false.")
            self.session.value['connected'] = False

        if "language" not in self.session.value and "HTTP_ACCEPT_LANGUAGE" in environ:
            self.session.value["language"] = environ['HTTP_ACCEPT_LANGUAGE'].split("-")[0].split(",")[0]
            mdebug("Setting session language to browser language: " + self.session.value["language"])
            self.session.save()
                
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
    def tofrom(self, story) :
        return story["source_language"] + "," + story["target_language"]

    def authenticate(self, username, password, auth_url, from_third_party = False) :
        mdebug("Authenticating to: " + str(auth_url))

        username = username.lower()
        lookup_username = username

        if from_third_party :
            lookup_username = from_third_party["username"].lower()
            password = params["admin_pass"]
            username = params["admin_user"].lower()

        lookup_username_unquoted = myquote(str(lookup_username))
        username_unquoted = myquote(str(username))
        userData = "Basic " + (username + ":" + password).encode("base64").rstrip()

        for attempt in range(0, 4) :
            try :
                mdebug("Authentication attempt #" + str(attempt))
                ureq = urllib2_Request(auth_url + "/_users/org.couchdb.user:" + lookup_username_unquoted)
                ureq.add_header('Accept', 'application/json')
                ureq.add_header("Content-type", "application/x-www-form-urlencoded")
                ureq.add_header('Authorization', userData)
                res = urllib2_urlopen(ureq, timeout = 20 if attempt == 0 else 10)
                rr = res.read()
                mdebug("Authentication success with username: " + username + " : " + str(rr) + " type " + str(type(rr)))
                return json_loads(rr), False
            except urllib2_HTTPError, e : 
                if e.code == 401 :
                    return False, _("Invalid credentials. Please try again") + "."
                mdebug("HTTP error: " + username + " " + str(e))
                error = "(HTTP code: " + str(e.code) + ")"
            except urllib2_URLError, e :
                mdebug("URL Error: " + username + " " + str(e))
                error = "(URL error: " + str(e.reason) + ")"
            except Exception, e :
                mdebug("Unknown error: " + username + " " + str(e))
                error = "(Unknown error: " + str(e) + ")"

        return False, _("Your device either does not have adequate signal strength or your connection does not have adequate connectivity. While you do have a connection (3G or Wifi), we were not able to reach the server. Please try again later when you have better internet access by tapping the 'M' at the top to login.") + ""#": " + error)

    def verify_db(self, req, dbname, password = False, cookie = False, users = False, from_third_party = False) :
        username = req.session.value["username"].lower()

        if username not in self.dbs or not self.dbs[username] : 
            mdebug("Database not set. Requesting object.")
            if mobile :
                mdebug("Setting mobile db to prexisting object.")
                self.dbs[username] = self.db
            else :
                address = req.session.value["address"] if "address" in req.session.value else self.credentials()
                if not from_third_party :
                    cs = self.db_adapter(address, username, password, cookie)
                else :
                    cs = self.db_adapter(address, params["admin_user"], params["admin_pass"], cookie)

                req.session.value["cookie"] = cs.cookie
                req.session.save()
                self.dbs[username] = cs[dbname]

            self.views_ready[username] = 0
            req.db = self.dbs[username]
            self.new_job(req, self.view_runner, False, _("Priming database for you. Please wait."), username, True, args = [username, self.dbs[username]])

            mdebug("Installing view counter.")
            if username not in self.views_ready :
                self.views_ready[username] = 0

        req.db = self.dbs[username]

        if req.db.doc_exist(self.acct(username)) :
            user = req.db[self.acct(username)]

    def acct(self, name) :
        return "MICA:accounts:" + name

    def key_common(self, req) :
        return "MICA:" + req.session.value['username']
        
    def story(self, req, key) :
        return self.key_common(req) + ":stories:" + key

    # How many days since 1970 instead of seconds
    def current_day(self) :
        return (int(timest()) / (60*60*24))
    
    def current_period(self, period_key, current_day = False):
        return int(current_day if current_day else self.current_day()) / counts[period_key] 

    def chat_name(self, period, index, peer, current_day, extra = "") :
        return "chat;" + period + ";" + str(index) + ";" + peer + extra

    def chat(self, req, period, index, peer, current_day, extra = "") :
        return self.story(req, self.chat_name(period, index, peer, current_day, extra))

    def chat_period_name(self, period_key, peer, current_day, extra = "") :
        return self.chat_name(period_key, self.current_period(period_key, current_day), peer, extra)

    def chat_period(self, req, period_key, peer, current_day, extra = "") :
        return self.chat(req, period_key, self.current_period(period_key, current_day), peer, extra)

    def index(self, req, key) :
        return self.key_common(req) + ":story_index:" + key 
    
    def merge(self, req, key) :
        return self.key_common(req) + ":mergegroups:" + key 
    
    def splits(self, req, key) :
        return self.key_common(req) + ":splits:" + key 
    
    def tones(self, req, key) :
        return self.key_common(req) + ":tonechanges:" + key 
    
    def memorized(self, req, key):
        return self.key_common(req) + ":memorized:" + key 
    
    def credentials(self) :
        return params["couch_proto"] + "://" + params["couch_server"] + ":" + str(params["couch_port"])

    def install_local_language(self, req, language = False) :
        if language :
            l = language
        elif "language" in req.session.value :
            l = req.session.value["language"]
        else :
            l = get_global_language()

        catalogs.language = l.split("-")[0]

        return l
        
    def __init__(self, db_adapter):
        self.general_processor = Processor(self, params)
        self.client = Translator(params["trans_id"], params["trans_secret"])
        self.mutex = Lock()
        self.transmutex = Lock()
        self.imemutex = Lock()
        self.heromsg = "<div class='img-rounded jumbotron' style='padding: 5px'>"
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

        self.views_ready = {}
        self.view_runs = [ #name , #startend key or regular keys
                ('accounts/all', True),
                ('memorized/allcount', True),
                ('chats/all', True),
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

        self.processors = {}

        for tofrom, readable in processor_map.iteritems() :
            if processor_map[tofrom] :
                self.processors[tofrom] = getattr(processors, processor_map[tofrom])(self, params)
        try :
            mdebug("Checking database access")
            if mobile :
                self.db = self.cs[params["local_database"]]
            else :
                if self.userdb :
                    self.db = self.userdb
                    self.view_check(self, "accounts")

                    if "mica_admin" not in self.cs :
                        self.make_account(self, "mica_admin", "password", "owner@example.com", "mica", admin = True, dbname = "mica_admin")
                else :
                    mwarn("Admin credentials ommitted. Skipping administration setup.")
                                   
        except TypeError, e :
            out = "Account documents don't exist yet. Probably they are being replicated: " + str(e)
            for line in format_exc().splitlines() :
                out += line + "\n"
            mwarn(out)
        except couch_adapter.ResourceNotFound, e :
            mwarn("Account document @ " + self.acct('mica_admin') + " not found: " + str(e))
        except Exception, e :
            mwarn("Database not available yet: " + str(e))

        if mobile :
            mdebug("INIT Launching runloop timer")
            Timer(5, self.runloop_sched).start()

        if not mobile :
            mdebug("Starting view runner thread")
            vt = Thread(target=self.view_runner_sched)
            vt.daemon = True
            vt.start()


    def make_account(self, req, username, password, email, source, admin = False, dbname = False, language = "en") :
        username = username.lower()

        if not dbname :
            new_uuid = str(uuid_uuid4())
            dbname = "mica_" + new_uuid

        if not self.userdb.doc_exist("org.couchdb.user:" + username) :
            mdebug("Creating user in _user database...")
            user_doc = { "name" : username,
                           "password" : password,
                           "roles": [] if admin else [username + "_master"],
                           "type": "user",
                           "mica_database" : dbname,
                           "language" : language,
                           "learnlanguage" : "en",
                           "date" : timest(),
                           "email" : email,
                           "source" : source,
                          }
            try :
                self.userdb["org.couchdb.user:" + username] = user_doc 
            except couch_adapter.CommunicationError, e :
                user_doc["password"] = "XXXXX"
                merr("No user for you: " + str(user_doc) + ": " + str(e))
                raise Exception("Internal validation error upon account creation.")
        else :
            dbname = self.userdb["org.couchdb.user:" + username]["mica_database"]

        mdebug("Retrieving new database: " + dbname)
        newdb = self.cs[dbname]
        new_security = newdb.get_security()

        if len(new_security) == 0 :
            mdebug("Installing security on admin database.")
            new_security = {"admins" : 
                            { 
                              "names" : ["mica_admin", username], 
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
            newdb[self.acct(username)] = { 
                                           'app_chars_per_line' : 70,
                                           'web_chars_per_line' : 70,
                                           'default_app_zoom' : 1.15,
                                           'default_web_zoom' : 1.0,
                                           "language" : language,
                                           "learnlanguage" : "en",
                                           "source" : source, 
                                           'email' : email,
                                           'filters' : {'files' : [], 'stories' : [] },
                                         } 
        savedb = req.db 
        req.db = newdb 
        self.check_all_views(req)
        req.db = savedb

    def view_runner(self, username, db) :
        # This only primes views for logged-in users.
        # Scaling the backgrounding for all users will need more thought.

        # FIXME: If the session expires, the backgrounding continues. Should we
        # leave it that way?

        mdebug("Priming views for user: " + username)
        self.views_ready[username] = 0

        for (name, startend) in self.view_runs :
            if not db.doc_exist("_design/" + name.split("/")[0]) :
                mdebug("View " + name + " does not yet exist. Loading...")
                dbsave = self.db
                self.db = db
                self.view_check(self, name.split("/")[0], recreate = True)
                self.db = dbsave
                mdebug("Done.")
                continue

            mdebug("Priming view for user: " + username + " db " + name)

            if startend :
                for unused in db.view(name, startkey=["foo", "bar"], endkey=["foo", "bar", "baz"]) :
                    pass
            else :
                for unused in db.view(name, keys = ["foo"], username = "bar") :
                    pass

            self.views_ready[username] += 1

        return _("Database optimized.")

    def safe_execute_serial(self) :
        (stuff, rq) = (yield)
        (func, args, kwargs) = stuff

        resp = func(*args, **kwargs)

        rq.put(resp)
        rq.task_done()

    def safe_execute(self, func, args = [], kwargs = {}) :
        if params["serialize_couch_on_mobile"] :
            mdebug("Serializing this job.")
            rq = Queue_Queue()
            co = self.safe_execute_serial()
            co.next()
            params["q"].put((co, (func, args, kwargs), rq))
            resp = rq.get()
        else :
            resp = func(*args, **kwargs)

        return resp

    def view_runner_sched(self) :
        mdebug("Execute the view runner one time to get started...")
        for username, db in self.dbs.iteritems() :
            self.safe_execute(self.view_runner, args = [username, db])

        while True :
            mdebug("View runner complete. Waiting until next time...")
            sleep(1800)
            for username, db in self.dbs.iteritems() :
                self.safe_execute(self.view_runner, args = [username, db])

    def get_filter_params(self, req) :
        filterparams = {"name" : "download/mobile"}
        filterparams["stories"] = ",".join(["none"] + (req.session.value["filters"]["stories"] if "filters" in req.session.value else []))
        files = ["none"]

        if "filters" in req.session.value : 
            for tofrom in req.session.value["filters"]["files"] :
                gp = self.processors[tofrom]
                for f in gp.get_dictionaries() :
                    files.append(f)

        filterparams["files"] = ",".join(files)
        return json_dumps(filterparams)

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

                        if not self.db.replicate(req.session.value["address"], username, req.session.value["password"], req.session.value["database"], params["local_database"], self.get_filter_params(req)) :
                            mdebug("Refreshing session failed to restart replication: Although you have authenticated successfully, we could not start replication successfully. Please try again")
                    else :
                        # On the server, use cookies to talk to CouchDB
                        cookie = req.session.value["cookie"]
                        mdebug("Reusing old cookie: " + str(cookie) + " for user " + username)

                try :
                    self.verify_db(req, req.session.value["database"], cookie = cookie)
                    resp = self.common(req)
                except couch_adapter.CommunicationError, e :
                    merr("Must re-login: " + str(e))
                    self.clean_session(req)
                    # The user has completed logging out / signing out already - then this message appears.
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
            # This 'exception' appears when there is a bug in the software and the software is not functioning normally. A report of the details of the bug follow after the word "Exception"
            aout = ""
            resp = "<h4>" + _("Exception") + ":</h4>"
            aout += "Exception\n"
            for line in format_exc().splitlines() :
                resp += "<br>" + line
                aout += line + "\n"
            resp += "<h2>" + _("Please report the exception above to the author. Thank you.") + "</h2>"
            merr(aout)
            if "connected" in req.session.value and req.session.value["connected"] :
                mwarn("Not a well-caught exception. Setting connected to false.")
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
        rq = Queue_Queue()
        co = self.runloop()
        co.next()
        params["q"].put((co, None, rq))
        resp = rq.get()
        Timer(1, self.runloop_sched).start()
        self.db.detach_thread()

    def __call__(self, environ, start_response):
        try :
            # Hack to make WebOb work with Twisted
            setattr(environ['wsgi.input'], "readline", environ['wsgi.input']._wrapped.readline)

            req = Params(environ, start_response.im_self.request.session)

            req.source = environ["REMOTE_ADDR"]
            req.db = False
            req.dest = ""#prefix(req.unparsed_uri)
            req.front_ads = False

            if not mobile and not params["couch_server"].count("localhost") and not params["couch_server"].count("dev") :
                req.front_ads = True

            if params["serialize_couch_on_mobile"] :
                rq = Queue_Queue()
                co = self.serial_common()
                co.next()
                params["q"].put((co, req, rq))
                resp = rq.get()
            else :
                resp = self.run_common(req)

        except Exception, e :
            merr("BAD MICA ********\nException:")
            for line in format_exc().splitlines() :
                merr(line)

        r = None

        try :
            if isinstance(resp, str) or isinstance(resp, unicode):
                r = Response(resp)(environ, start_response)
            else :
                r = resp(environ, start_response)
        except Exception, e :
            merr("RESPONSE MICA ********\nException:")
            for line in format_exc().splitlines() :
                merr(line)

        return r
    
    def sidestart(self, req, name, username, story, reviewed, finished, gp, tzoffset = 0) :
        rname = name.replace(".txt","").replace("\n","").replace("_", " ")
        if "filetype" in story and story["filetype"] == "chat" :
            [x, period, howmany, peer] = story["name"].split(";")
            rname = peer + " ("
            if period != "days" :
                rname += "From "
            rname += datetime_datetime.fromtimestamp((((int(howmany) * counts[period])) * (60*60*24)) + tzoffset).strftime(period_story_mapping[period_mapping[period]]) + ")"
        sideout = []
        sideout.append("\n<tr>")
        sideout.append("<td style='font-size: x-small; width: 100px'>" )
        if mobile :
            sideout.append("<b>" + rname + "</b>")
        else :
            # 'original' refers to the original text of the story that the user provided for language learning.
            sideout.append("\n<a onclick=\"$('#loadingModal').modal({backdrop: 'static', keyboard: false, show: true});\" title='" + _("Download Original") + "' href=\"/stories?type=original&#38;uuid=")
            sideout.append(story["uuid"])
            sideout.append("\">")
            sideout.append(rname)
            sideout.append("</a>")

        if "source_language" in story :
            sideout.append(" <b>(" + story["source_language"].split("-")[0] + ")</b>")
        
        if (finished or reviewed or story["translated"]) and "pr" in story :
            pr = story["pr"]
            sideout.append("<br/>\n<div class='progress progress-success progress-striped'><div class='progress-bar' style='width: ")
            sideout.append(pr + "%;'> (" + pr + "%)</div></div>")
            
        if mobile :
            if "download" not in story or not story["download"] :
                syncing = _("Syncing")
                sideout.append("<a id='" + name + "' onclick=\"syncstory('" + name + "', '" + story['uuid'] + "')\" class='btn btn-default btn-xs'>" + _("Start Syncing") + "</a>")
            else :
                sideout.append("<a id='" + name + "' onclick=\"unsyncstory('" + name + "', '" + story['uuid'] + "')\" class='btn btn-default btn-xs'>" + _("Stop Syncing") + "</a>")

        sideout.append("</td><td>")

        if not mobile and not gp.already_romanized :
            if finished or reviewed :
                # The romanization is the processed (translated), romanized version of the original story text that was provided by the user for language learning.  
                sideout.append("\n<a title='" + _("Download Romanization") + "' onclick=\"$('#loadingModal').modal({backdrop: 'static', keyboard: false, show: true});\" class='btn-default btn-xs' href=\"/stories?type=pinyin&#38;uuid=" + story["uuid"]+ "\">")
                sideout.append("<i class='glyphicon glyphicon-download-alt'></i></a>")
    
        return sideout

    def template(self, template_prefix) :
        contents_fh = open(cwd + relative_prefix + "/" + template_prefix + "_template.html", "r")
        contents = contents_fh.read()
        contents_fh.close()
        return contents

    def api(self, req, json, human = True, wrap = True) :
        if human :
            out = ""
            if wrap :
                # Don't ask me why, but jquery find() cannot find an element
                # by its ID, if it is not wrapped in *any* parent element.
                # Very strange.
                out += "<div><div id='" + req.action + "result'>"

            out += str(json["desc"])

            if wrap:
                out += "</div></div>"

            return self.bootstrap(req, out, now = True)
        else :
            return self.bootstrap(req, json_dumps(json), now = True)

    def bootstrap(self, req, body, now = False, pretend_disconnected = False, nodecode = False) :

        if isinstance(body, str) and not nodecode :
            body = body.decode("utf-8")

        if not mobile and "username" in req.session.value and req.session.value["username"] == "demo" :
            # The demo account is provided for users who want to give the software a try without committing to it.
            req.skip_show = True
            body = self.heromsg + "<h4>" + _("Demo Account is readonly. You must install the mobile application for interactive use of the demo account.") + "</h4></div>"

        if now :
            contents = body
        else :
            if req.session.value["connected"] :
                req.view_percent = '{0:.1f}'.format(float(self.views_ready[req.session.value['username']]) / float(len(self.view_runs)) * 100.0)
            else :
                req.view_percent = "0.0"
            req.pretend_disconnected = pretend_disconnected
            req.address = req.session.value["address"] if ("address" in req.session.value and req.session.value["address"] is not None) else self.credentials()

            if req.session.value['connected'] and not pretend_disconnected :
                req.user = req.db.try_get(self.acct(req.session.value['username']))

            if not mobile :
                req.oauth = params["oauth"]
            req.mica = self
            contents = run_template(req, HeadElement)

        if not nodecode :
            contents = contents.replace("BOOTBODY", body)
            fh = open(cwd + 'serve/head.js')
            contents = contents.replace("BOOTSCRIPTHEAD", fh.read())
            fh.close()
    
        return contents

    def get_polyphome_hash(self, correct, source) :
        return hashlib_md5(str(correct).lower() + "".join(source).encode("utf-8").lower()).hexdigest()

    def rehash_correct_polyphome(self, unit):
        unit["hash"] = self.get_polyphome_hash(unit["multiple_correct"], unit["source"])

    def test_dicts_handle_common(self, f) :
        fname = params["scratch"] + f 
        exported = False

        try :
            if not os_path.isfile(fname) :
                self.db.get_attachment_to_path("MICA:filelisting_" + f, f, fname)
                mdebug("Exported " + f + " to " + fname)
            exported = True
        except couch_adapter.CommunicationError, e :
            mdebug("FILE " + f + " not fully replicated yet. Waiting..." + str(e))
        except couch_adapter.ResourceNotFound, e :
            mdebug("FILE " + f + " not fully replicated yet. Waiting..." + str(e))

        return exported

    def test_dicts_handle_serial(self) :
        if params["serialize_couch_on_mobile"] :
            (f, rq) = (yield)

        exported = self.test_dicts_handle_common(f)

        if params["serialize_couch_on_mobile"] :
            rq.put(exported)
            rq.task_done()

    def test_dicts(self) :
        files = ["cjklib.db", "cedict.db", "chinese.txt"]

        exported = False
        if mobile :
            all_found = False

            while not all_found :
                all_found = True

                for name, lgp in self.processors.iteritems() :
                    for f in lgp.get_dictionaries() :
                        fname = params["scratch"] + f

                        if not os_path.isfile(fname) :
                            all_found = False

                            mdebug("Replicated file " + f + " is missing at " + fname + ". Exporting...")
                            if params["serialize_couch_on_mobile"] :
                                rq = Queue_Queue()
                                co = self.test_dicts_handle_serial()
                                co.next()
                                params["q"].put((co, f, rq))
                                if rq.get() :
                                    exported = True
                            else :
                                if self.test_dicts_handle_common(f) :
                                    exported = True

                            if not exported :
                                break

                sleep(30)

        for name, lgp in self.processors.iteritems() :
            try :
                handle = lgp.parse_page_start()
                #lgp.test_dictionaries(handle, preload = True)
                lgp.test_dictionaries(handle)
                lgp.parse_page_stop(handle)
            except Exception, e :
                merr("Error preloading dictionaries: " + str(e))

            for f in lgp.get_dictionaries() :
                fname = params["scratch"] + f
                size = os_path.getsize(fname)
                mdebug("Exists FILE: " + str(size) + " " + fname)
                assert(size != 0)

        self.db.detach_thread()

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
            except couch_adapter.ResourceNotFound, e :
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

    def parse(self, req, story, page = False, live = False) :
        name = story['name']
        mverbose("Ready to translate: " + name + ". Counting pages...")

        assert("source_language" in story)

        processor = getattr(processors, processor_map[self.tofrom(story)])(self, params)
    
        page_inputs = 0
        if live or ("filetype" not in story or story["filetype"] == "txt") :
            page_inputs = 1
        else :
            mdebug("Counting now...")
            for result in req.db.view('stories/original', startkey=[req.session.value['username'], name], endkey=[req.session.value['username'], name, {}]) :
                mdebug("Got count.")
                page_inputs = result['value']
       
        mverbose("Page inputs: " + str(page_inputs))
        assert(int(page_inputs) != 0) 
             
        if page :
            page_start = int(page)
            mdebug("Translating single page starting at " + str(page))
            page_inputs = page_start + 1 
        else :  
            page_start = 0
        
        if not live :
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

        opaque = processor.parse_page_start(False if not live else story["source"])

        processor.test_dictionaries(opaque)

        mverbose("Starting translation...")
        for iidx in range(page_start, page_inputs) :
            page_key = self.story(req, name) + ":pages:" + str(iidx)

            mverbose("Translating page " + str(iidx))

            if live :
                page_input = story["source"]
            else :
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
                
            mverbose("Pre-parsing page " + str(iidx))
            parsed = processor.pre_parse_page(opaque, page_input)

            mverbose("Parsed result: " + parsed + " for page: " + str(iidx) + " type: " + str(type(parsed)))

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
            
            if not live :
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
                processor.parse_page(opaque, req, story, groups, str(iidx), progress = self.progress if not live else False)
                online = 0
                offline = 0
                for unit in story["pages"][str(iidx)]["units"] :
                    if not unit["punctuation"] :
                        if unit["online"] :
                            online += 1
                        else :
                            offline += 1 

                mdebug("Translating page " + str(iidx) + " complete. Online: " + str(online) + ", Offline: " + str(offline))
                if not live :
                    req.db[page_key] = story["pages"][str(iidx)]
                    del story["pages"][str(iidx)]

            except Exception, e :
                msg = ""
                for line in format_exc().splitlines() :
                    msg += line + "\n"

                merr(msg)

                if not live :
                    tmpstory = req.db[self.story(req, name)]
                    tmpstory["translating"] = False 
                    req.db[self.story(req, name)] = tmpstory
                    self.store_error(req, name, msg)

                processor.parse_page_stop(opaque)
                raise e

        if not live :
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
                if not live :
                    mdebug("Caching nb_pages: " + str(self.nb_pages(req, tmpstory)))
                if "translated" not in tmpstory or not tmpstory["translated"] :
                    self.flush_pages(req, name)
                        
            except Exception, e :
                mdebug("Failure to sync: " + str(e))
            finally :
                self.transmutex.release()

        mverbose("Translation complete.")
        processor.parse_page_stop(opaque)

    def get_parts(self, unit, tofrom) :
        gp = self.processors[tofrom]
        py = ""
        target = ""
        if unit["multiple_correct"] == -1 :
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
                if not gp.already_romanized :
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
                    if not gp.already_romanized :
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
        gp = self.processors[self.tofrom(story)]
        out = ""
        # Beginning of a sentence. Character may also be translated as 'word' if localized to a language that is already romanized, like English
        if gp.already_romanized :
            out += "\n" + _("This word") + " ("
        else :
            out += "\n" + _("This character") + " ("
        if gp.already_romanized : 
            out += "".join(unit["source"])
        else :
            out += " ".join(unit["source"])
        # end of the previous sentence. 'Polyphonic' means that a character has multiple sounds for the same character. For other languages, like English, this word can be ignored and should be translated as simply having more than one meaning (not sound).
        if gp.already_romanized :
            out += ") " + _("has more than one meaning") + ":<br>"
        else :
            out += ") " + _("is polyphonic: (has more than one pronunciation") + "):<br>"
        out += "<table class='table table-hover table-striped' style='font-size: x-small'>"
        out += "<tr>"
        if len(unit["multiple_sromanization"]) :
            # Pinyin means the romanization of a character-based word, such as Chinese
            out += "<td>" + _("Pinyin") + "</td>"
        out += "<td>" + _("Definition") + "</td>"
        # This appears in a list of items and indicates which is the default item
        out += "<td>" + _("Default") + "?</td></tr>"
        source = "".join(unit["source"])

        total_changes = 0.0
        changes = req.db.try_get(self.tones(req, source))
        
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
                # Appears on a button in review mode that allows the user to choose a definition among multiple choices.
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
            mverbose("Input units: " + str(len(_units)))
            for unit in _units :
                if name == "memorized" :
                    if "hash" in unit :
                        sources.append(unit["hash"])
                else :
                    sources.append("".join(unit["source"]))
            
        if len(sources) == 0 :
            return {} 

        keys = {}
        mverbose("Generating query for view: " + name + " with " + str(len(sources)) + " keys.")
        
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

            mverbose("Issuing query for indexes: start " + str(start) + " stop " + str(stop) + " total " + str(total) )
            for result in req.db.view(name + "/all", keys = sources[start:(stop)], username = req.session.value['username']) :
                keys[result['key'][1]] = result['value']

            if not finished :
                start += inc 
                stop += inc 
        
        return keys
        
    def history(self, req, story, page) :
        gp = self.processors[self.tofrom(story)]
        history = []
        found = {}
        tid = 0
        online = 0
        offline = 0
        try :
            page_dict = req.db[self.story(req, story['name']) + ":pages:" + str(page)]
        except couch_adapter.ResourceNotFound, e :
            return _("If you would like to read this story, please select 'Start Syncing' from the side panel first and wait for it to replicate to your device.")
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
                if gp.already_romanized :
                    history.append([char, str(changes["total"]), "", "<br/>".join(record["target"]), tid])
                else :
                    history.append([char, str(changes["total"]), " ".join(record["sromanization"]), " ".join(record["target"]), tid])
                        
            tid += 1
        
        # Add sort options here
        def by_total( a ):
            return int(float(a[1]))

        history.sort( key=by_total, reverse = True )
        req.history = history
        # This appears underneath the Review-mode legend: 'Breakdown' is a delineation of how many words in this story had to be translated using an offline dictionary or an online dictionary.
        req.onlineoffline = _("Breakdown")
        # Online indicates a count of how many words were translated over the internet
        req.onlineoffline += ": " + _("Online") + ": " + str(online) + ", "
        # Offline indicates a count of how many words were translated using an offline dictionary
        req.onlineoffline += _("Offline") + ": " + str(offline)
        return run_template(req, HistoryElement)

    def edits(self, req, story, page) :
        list_mode = self.get_list_mode(req)
        if list_mode :
            history = []
            found = {}
            tid = 0
            try :
                page_dict = req.db[self.story(req, story['name']) + ":pages:" + str(page)]
            except couch_adapter.ResourceNotFound, e :
                return _("If you would like to read this story, please select 'Start Syncing' from the side panel first and wait for it to replicate to your device.")
            units = page_dict["units"]

            merge_keys = self.view_keys(req, "mergegroups", units) 
            split_keys = self.view_keys(req, "splits", units) 
                
            for unit in units :
                char = "".join(unit["source"])
                if char in self.processors[self.tofrom(story)].punctuation_without_letters or len(char.strip()) == 0:
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

        req.process_edits = "process_edits('" + story["uuid"] + "', 'all', true)"
        req.retrans = "/" + req.action + "?retranslate=1&uuid=" + story['uuid'] + "&page=" + str(page)
        req.list_mode = list_mode
        if list_mode :
            req.history = history

        return run_template(req, EditElement)

    def view(self, req, uuid, name, story, start_page, view_mode, meaning_mode) :
        if not story["translated"] :
            # Begin long explanation
            ut = self.heromsg + "<h4>" + _("This story has not yet been converted to reading format.")
            ut += " "
            if mobile :
                ut += _("Translation requires significant computer power, so you must convert (translate) it online first, and then it will be synchronized with this device.")
            else :
                ut += _("Please click 'Translate' in the side panel to proceed.")
            ut += "</h4></div>"
            return ut 

        upgrade_needed = 0

        if "format" not in story or story["format"] == 1 :
            # The next series of messages occur when the software releases a new version that uses a database/file format that is not backwards-compatible with a previous version. In these cases, the database needs to be "upgraded". The software directs the users through a procedure to perform this upgrade, as well as any error messages associated with completing the upgrade process.
            out = self.heromsg + "\n<h4>" + _("The database for this story") + " (<b>" + name + "</b>) " + _("needs to be upgraded to version 2") + "."
            upgrade_needed = 2

        # Future upgrade numbers go here...

        if upgrade_needed > 0 :
            if mobile :
                out += _("Unfortunately, this can only be performed with the online version. Please login to your account online to perform the upgrade. The changes will then be synchronized to all your devices. Thank you.")
            else :
                out += "<br/><a class='btn btn-default btn-primary' href='/" + req.action + "?storyupgrade=1&uuid=" + uuid + "&version=" + str(upgrade_needed) + "'>" + _("Start Upgrade") + "</a>" 

            if "last_error" in story and not isinstance(story["last_error"], str) :
                out + "Last upgrade Exception:<br/>"
                for err in story["last_error"] :
                    out += "<br/>" + myquote(err.replace("\n", "<br/>"))

            out += "</h4></div>"
            return out

        req.gp = self.processors[self.tofrom(story)]

        if "filetype" in story and story["filetype"] == "chat" :
            [x, period, howmany, peer] = story["name"].split(";")
            if self.current_period(period) == int(howmany) : 
                period = period[:-1]
                # These two messages together effectively say "Chat with: xxxxx"
                req.story_name = _("Chat") + " " + (_("today") if period == "day" else (_("this") + " " + period)) + " " + ("w/") + " " + peer
            else :
                # These two messages together effectively say "Chat with: xxxxx"
                howmany_diff = self.current_period(period) - int(howmany)
                mdebug("howmany diff: " + str(howmany_diff))
                print_period = period[:-1] if howmany_diff == 1 else period
                req.story_name = _("Chat") + " " + str(howmany_diff) + " " + print_period + " " + _("ago") + " " + " " + _("w/") + " " + peer
        else :
            req.story_name = story["name"]

        req.install_pages = "install_pages('" + req.action + "', " + str(self.nb_pages(req, story)) + ", '" + uuid + "', " + start_page + ", '" + view_mode + "', true, '" + meaning_mode + "');"
        req.source_language = story["source_language"]
        req.target_language = story["target_language"]

        req.process_reviews = "process_reviews('" + uuid + "', true)"
        output = run_template(req, ViewElement)

        return output

    def nb_pages(self, req, story, cached = True, force = False):
        nb_pages = 0

        if cached and "nb_pages" in story and not force:
            mdebug("Using cached value for nb_pages")
            nb_pages = story["nb_pages"]
        else :
            mdebug("Generating cached value for nb_pages: " + story["name"])
            for result in req.db.view('stories/pages', startkey=[req.session.value['username'], story["name"]], endkey=[req.session.value['username'], story["name"], {}]) :
                nb_pages = result['value']
                break

            assert(nb_pages != 0)

            if cached :
                tmp_story = req.db[self.story(req, story["name"])]
                tmp_story["nb_pages"] = nb_pages 
                req.db[self.story(req, story["name"])] = tmp_story

        return nb_pages 
    
    def roman_holder(self, source, color) :
        holder = "<div class='roman" + color + "'>"
        
        for x in range(0, len(source)) :
            holder += "&#160;"
            
        holder += "</div>"
        return holder
    
    def view_page(self, req, uuid, name, story, action, output, page, chars_per_line, meaning_mode, disk = False, start_trans_id = 0, tzoffset = 0, chat = False) :
        output = [output]
        gp = self.processors[self.tofrom(story)]

        if mobile and req.session.value["username"] == "demo" and gp.already_romanized :
            chars_per_line = 10 

        mverbose("View Page " + str(page) + " story " + str(name) + " start...")

        if name :
            try :
                page_dict = req.db[self.story(req, name) + ":pages:" + str(page)]
            except couch_adapter.ResourceNotFound, e :
                return _("If you would like to read this story, please select 'Start Syncing' from the side panel first and wait for it to replicate to your device.")
        else :
            page_dict = story["pages"]["0"]

        mverbose("View Page " + str(page) + " story " + str(name) + " fetched...")

        units = page_dict["units"]
        words = len(units)
        lines = [] 
        line = [] 

        trans_id = start_trans_id 
        chars = 0
        batch = -1

        mverbose("View Page " + str(page) + " story " + str(name) + " building...")
            
        sources = {}

        if action == "edit" :
            sources['mergegroups'] = self.view_keys(req, "mergegroups", units) 
            sources['splits'] = self.view_keys(req, "splits", units) 
        elif action == "home" :
            sources['tonechanges'] = self.view_keys(req, "tonechanges", units) 
        elif action == "read" :
            sources['memorized'] = self.view_keys(req, "memorized", units) 
        
        mverbose("View Page " + str(page) + " story " + str(name) + " querying...")

        for x in range(0, len(units)) :
            unit = units[x]

            source = "".join(unit["source"])

            ret = self.get_parts(unit, self.tofrom(story))

            if ret == False :
                continue

            py, target = ret

            if py in ['\n', u'\n'] or target in ['\n', u'\n']:
               if len(line) > 0 :
                   lines.append(line)
                   line = []
                   chars = 0
            else :
                if py not in gp.punctuation_without_letters and chars >= chars_per_line :
                   lines.append(line)
                   line = []
                   chars = 0

                if py in gp.punctuation_without_letters :
                    line.append([py, False, trans_id, [], x, source])
                else :
                    chars += len(py)
                    p = [target, py, trans_id, unit, x, source]
                    line.append(p)

            trans_id += 1

        if len(line) :
            lines.append(line)

        mverbose("View Page " + str(page) + " story " + str(name) + " grouped...")
        
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

        recommendations = False

        for line in lines :
            disk_out = ""
            line_out = []

            if not disk :
                line_out.append("\n<table>")
                line_out.append("\n<tr>")

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

                    line_out.append("\n<td style='vertical-align: middle; text-align: center; font-size: ")
                    if not mobile :
                        line_out.append(str(req.session.value["default_web_zoom"] * 100.0))
                    else :
                        line_out.append("100")
                    line_out.append("%' ")

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
                            line_out.append("class='mergetop mergebottom")
                            if not prev_merge : 
                                batch += 1
                                line_out.append(" mergeleft")
                            line_out.append("'")
                            use_batch = "merge" 
                        else :
                            if not curr_merge :
                                sourcesplits = False if source not in sources['splits'] else sources['splits'][source]
                                if sourcesplits and unit["hash"] in sourcesplits["record"] :
                                    batch += 1
                                    use_batch = "split" 
                                    line_out.append("class='splittop splitbottom splitleft splitright'")

                        prev_merge = curr_merge if not skip_prev_merge else False

                    line_out.append(">")

                    if "timestamp" not in unit or not unit["punctuation"] :
                        line_out.append("<span id='spanselect_" + trans_id + "' class='")
                        line_out.append("batch" if use_batch else "none")
                        line_out.append("'>")
                        if gp.already_romanized :
                            line_out.append("<a class='transroman'")
                        else :
                            line_out.append("<a class='trans'")
                        line_out.append(" uniqueid='" + tid + "' ")
                        line_out.append(" nbunit='" + nb_unit + "' ")
                        line_out.append(" transid='" + trans_id + "' ")
                        line_out.append(" batchid='" + (str(batch) if use_batch else "-1") + "' ")
                        line_out.append(" operation='" + (str(use_batch) if use_batch else "none") + "' ")
                        line_out.append(" page='" + page + "' ")
                        line_out.append(" pinyin=\"" + (py if py else target) + "\" ")
                        line_out.append(" index='" + (str(unit["multiple_correct"]) if py else '-1') + "' ")
                        line_out.append(" style='color: black; font-weight: normal")
                        if "punctuation" not in unit or not unit["punctuation"] :
                            line_out.append("; cursor: pointer")
                        line_out.append("' ")
                        if chat :
                            if "select_idx" in unit :
                                line_out.append(" onclick=\"select_chat_option('" + str(unit["select_idx"]) + "')\"")
                        else :
                            line_out.append(" onclick=\"select_toggle('" + trans_id + "')\"")
                        line_out.append(">")

                        line_out.append(source if py else target)
                        line_out.append("</a>")
                        line_out.append("</span>")
                    else :
                        period = story["name"].split(";")[1]
                        ts = " (" + datetime_datetime.fromtimestamp(int(unit["timestamp"]) + tzoffset).strftime(period_view_mapping[period]) + ")"
                        line_out.append(source + u": " + ts + ":&#160;&#160;&#160;")

                    line_out.append("</td>")

                    if py :
                        if action == "edit" and merge_end :
                            # mergeright
                            line_out.append(merge_end_spacer)
                        elif action == "edit" and curr_merge :
                            line_out.append(merge_spacer)
                        else :
                            line_out.append(spacer)

                line_out.append("</tr>\n<tr>")

            for word in line :
                target = word[0].replace("\"", "\\\"").replace("\'", "\\\"")
                py = word[1]
                unit = word[3]
                trans_id = str(word[2])
                tid = unit["hash"] if py else trans_id 
                nb_unit = str(word[4])
                source = word[5]
                largest_hcode = False 
                largest_index = -1
                largest = -1

                if py and (py not in gp.punctuation) :
                    if not disk :
                        if action == "home" :
                            home_changes = False if source not in sources['tonechanges'] else sources['tonechanges'][source]

                            if home_changes :
                                for hcode, record in home_changes["record"].iteritems() :
                                    curr = record["total_selected"]
                                    if largest < curr :
                                        largest_hcode = hcode
                                        largest = curr 
                                    elif largest == curr :
                                        # If there is no winner, then don't recommend anything
                                        largest = -1
                                        largest_hcode = False
                                        break

                                if largest_hcode == unit["hash"] :
                                    largest_hcode = False
                                    largest = -1

                                if largest_hcode :
                                    for idx in range(0, len(unit["multiple_target"])) :
                                        hcode = self.get_polyphome_hash(idx, source)
                                        if hcode == largest_hcode :
                                            largest_index = idx
                                            break

                                    if largest_index == -1 :
                                        mdebug("Problem with logic: " + str(unit) + " largest_hcode: " + str(hcode) + " changes: " + str(home_changes))
                                        largest_hcode = False

                line_out.append("\n<td style='vertical-align: bottom; text-align: center; font-size: ")
                if not mobile :
                    line_out.append(str(req.session.value["default_web_zoom"] * 100.0))
                else :
                    line_out.append("100")

                line_out.append("%")

                if "punctuation" not in unit or not unit["punctuation"] :
                    line_out.append("; cursor: pointer")

                if largest_hcode :
                    line_out.append("; border: 2px solid black")

                line_out.append("'>")

                if py and (py not in gp.punctuation) and not unit["punctuation"] :
                    if not disk :
                        if gp.already_romanized :
                            line_out.append("<a class='transroman' ")
                        else :
                            line_out.append("<a class='trans' ")

                        add_count = ""

                        if action == "home" :
                            color = "grey" if not unit["punctuation"] else "white"
                            if py and len(unit["multiple_target"]) :
                                color = "green"

                            if home_changes :
                                if unit["hash"] in home_changes["record"] :
                                    color = "black"
                                    add_count = " (" + str(int(home_changes["total"])) + ")"

                            if color != "black" and py and len(unit["multiple_sromanization"]) :
                                fpy = " ".join(unit["multiple_sromanization"][0])
                                for ux in range(1, len(unit["multiple_sromanization"])) :
                                     upy = " ".join(unit["multiple_sromanization"][ux])
                                     if upy != fpy :
                                         color = "red"
                                         break

                            if color != "" :
                                line_out.append(" style='color: " + color + "' ")
                        elif py :
                            line_out.append(" style='color: black' ")
                            color = "grey" if not unit["punctuation"] else "white"

                        line_out.append(" id='ttip" + trans_id + "'")

                        if action in ["read","edit"] or not(len(unit["multiple_target"])) :
                            line_out.append(" onclick=\"toggle('" + tid + "', ")
                            line_out.append(("0" if action == "read" else "1") + ")\"")

                        line_out.append(">")
                        
                        if action == "home" :
                            if largest_hcode :
                                if not recommendations :
                                    recommendations = 0

                                recommendations += 1

                                if len(unit["multiple_sromanization"]) :
                                    largest_target = " ".join(unit["multiple_sromanization"][largest_index])
                                else :
                                    largest_target = " ".join(unit["multiple_target"][largest_index])
                                line_out.append("<span page='" + str(page) + "' target='" + largest_target + "' nbunit='" + str(nb_unit) + "' index='" + str(largest_index) + "' transid='" + str(trans_id) + "' class='review' source='" + source + "'>")
                        
                        if gp.already_romanized :
                            if color not in [ "grey", "white" ] :
                                line_out.append(target)
                            else :
                                line_out.append(self.roman_holder(source, color))
                        else :
                            if py == u' ' :
                                line_out.append(self.roman_holder(source, color))
                            elif py :
                                line_out.append(py)
                            else :
                                line_out.append(target.lower())
        
                        line_out.append(add_count)

                        if largest_hcode :
                            line_out.append("</span>")

                        line_out.append("</a>")
                    else :
                        disk_out += (("hold" if py == u' ' else py) if py else target).lower()
                else :
                    if disk :
                        disk_out += (("hold" if py == u' ' else py) if py else target).lower()
                    else :
                        if "timestamp" not in unit or not unit["punctuation"] :
                            line_out.append((("hold" if py == u' ' else py) if py else target).lower())

                if not disk :
                    if action == "home" :
                        if "ipa_word" in unit and unit["ipa_word"] :
                            line_out.append("<br>" + unit["ipa_word"])
                    line_out.append("<br/>")

                    if action == "home" and py and len(unit["multiple_target"]) :
                        line_out.append("<div style='display: none' id='pop" + str(trans_id) + "'>")
                        line_out.append(self.polyphomes(req, story, uuid, unit, nb_unit, trans_id, page))
                        line_out.append("</div>")
                        line_out.append("<script>")
                        line_out.append("multipopinstall('" + str(trans_id) + "', 0);\n")
                        line_out.append("</script>")

                    line_out.append("</td>")

                    if py :
                        line_out.append(spacer)
                else :
                    disk_out += " "

            if disk :
                disk_out += "\n"
            else :
                line_out.append("</tr>")
                line_out.append("<tr>")

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
                    line_out.append("\n<td style='vertical-align: bottom; text-align: center'>")
                    line_out.append("<table><tr>")
                    line_out.append("<td><div style='display: none' class='memory" + tid + "'>")
                    line_out.append("<img src='" + req.mpath + "/spinner.gif' width='15px'/>&#160;")
                    line_out.append("</div></td>")
                    line_out.append("</tr><tr><td>")
                    if gp.already_romanized :
                        line_out.append("<div class='transroman ")
                    else :
                        line_out.append("<div class='trans ")
                        
                    line_out.append(" trans" + tid + "' style='display: ")
                    line_out.append("block" if (action == "read" and not memorized) else "none")
                    line_out.append("; font-size: ")
                    if not mobile :
                        line_out.append(str(req.session.value["default_web_zoom"] * 100.0))
                    else :
                        line_out.append("100")
                    line_out.append("%")

                    line_out.append("' id='trans" + tid + "'>")
                    if py and not unit["punctuation"] :
                        if not memorized :
                            line_out.append("<div revealid='" + tid + "' ")
                            line_out.append("class='reveal reveal" + tid + "'")
                            if meaning_mode == "true":
                                line_out.append("style='display: none'")
                            line_out.append(">&#160;&#160;<a class='reveal' onclick=\"reveal('" + tid + "', false)\"><i class='glyphicon glyphicon-expand'></i></a></div>")
                            line_out.append("<div class='definition definition" + tid + "' ")
                            if meaning_mode == "false":
                                line_out.append("style='display: none'")
                            line_out.append(">")
                        if action in ["read", "edit"] :
                            if gp.already_romanized :
                                line_out.append("<a class='transroman' ")
                            else :
                                line_out.append("<a class='trans' ")
                            if uuid :
                                line_out.append("onclick=\"memorize('" + \
                                        tid + "', '" + str(uuid) + "', '" + str(nb_unit) + "', '" + page + "')\">")
                            else :
                                line_out.append("onclick=\"memorize_nostory('" + \
                                        tid + "', '" + myquote(source) + "', '" + str(unit["multiple_correct"]) + "')\">")

                        line_out.append(target.replace("/"," /<br/>"))
                            
                        if action == "read" :
                            if "ipa_word" in unit and unit["ipa_word"] :
                                line_out.append("<br>" + unit["ipa_word"])
                    
                        if action in [ "read", "edit" ] :
                            line_out.append("</a>")

                        if not memorized :
                            line_out.append("</div>")

                    line_out.append("<br/>")
                    line_out.append("</div>")
                    line_out.append("<div style='display: ")
                    line_out.append("none" if (action in ["read", "edit"] and not memorized) else "block")
                    if gp.already_romanized :
                        line_out.append("' class='transroman")
                    else :
                        line_out.append("' class='trans")
                    
                    line_out.append(" blank" + tid + "'>")
                    line_out.append("&#160;</div>")
                    line_out.append("</td>")
                    line_out.append("</tr></table>")
                    line_out.append("</td>")
                    if py :
                        line_out.append("<td>&#160;</td>")
                line_out.append("</tr>")
                line_out.append("</table>")

            if not disk :
                output.append("".join(line_out))
            else :
                output.append(disk_out)

        if recommendations :
            # This appears on a button in review mode on the right-hand side to allow the user to "Bulk Review" a bunch of words that the system has already found for you. 
            output = ["<b>" + _("Found Recommendations") + ": " + str(recommendations) + "</b><br/><br/>"] + output 

        mverbose("View Page " + str(page) + " story " + str(name) + " complete.")
        return "".join(output)

    def translate_and_check_array(self, req, name, requests, lang, from_lang) :
        assert(req.http.params.get("username") or "username" in req.session.value)

        username = req.http.params.get("username")

        if not username :
            username = req.session.value['username']

        mdebug("translate Preparing for mobile internet check")
        if (int(req.http.params.get("test", "0")) or mobile) :
            result = []
            if not params["mobileinternet"] or params["mobileinternet"].connected() != "none" :
                newdict = {"name" : name, "requests" : json_dumps(requests)}
                for k in req.http.params :
                    if k not in ["test"] :
                        newdict[k] = req.http.params.get(k)

                newdict["source_language"] = from_lang
                newdict["target_language"] = lang
                newdict["username"] = username 
                if mobile :
                    newdict["password"] = req.session.value["password"]
                newdict["lang"] = req.session.value["language"]

                mdebug("Preparing online relay with: " + str(newdict) + " to " + params["main_server"])

                try :
                    ureq = urllib2_Request("https://" + params["main_server"] + "/online", urlencode(newdict))
                    mverbose("Returning from online relay")
                    data = json_loads(urllib2_urlopen(ureq, timeout = 20).read())
                    mverbose("Finished data read from online relay: " + str(data))
                    if data["success"] :
                        result = data["result"]
                    else :
                        result.append({"TranslatedText" : data["desc"]})
                except Exception, e :
                    mdebug("Failed to request online translation: " + str(e))
                    return False
            else :
                mdebug("Appending what we can't find.")
                result.append({"TranslatedText" : _("No internet access. Offline instant translation only.")})

            return result

        self.mutex.acquire()

        attempts = 15
        finished = False
        stop = False

        for attempt in range(0, attempts) :
            error = False 
            try : 
                if attempt > 0 :
                    mdebug("Previous attempt failed. Re-authenticating")
                    self.client.access_token = self.client.get_access_token()

                mverbose("Entering online translation.")
                result = self.client.translate_array(requests, lang, from_lang = from_lang)

                if not len(result) or "TranslatedText" not in result[0] :
                    mdebug("Probably key expired: " + str(result))
                else :
                    finished = True

            except ArgumentOutOfRangeException, e :
                error = "Missing results. Probably we timed out. Trying again: " + str(e)
            except TranslateApiException, e :
                error = "First-try translation failed: " + str(e)
            except IOError, e :
                error = "Connection error. Will try one more time: " + str(e)
            except urllib2.URLError, e :
                error = "Response was probably too slow. Will try again: " + str(e)
            except socket_timeout, e :
                error = "Response was probably too slow. Will try again: " + str(e)
            except Exception, e :
                error = "Unknown fatal translation error: " + str(e)
                stop = True
            finally :
                mverbose("Attempt: " + str(attempt) + " finally.")
                if not finished and not error :
                    error = "Translation API not available for some reason. =("
                if error :
                    self.store_error(req, name, error)

            if finished or stop :
                break

        self.mutex.release()

        if not finished :
            mdebug("Raising fatal error.")
            raise OnlineTranslateException(error)

        return result
    
    def makestorylist(self, req, tzoffset):
        untrans_count = 0
        reading_count = 0
        reading = [self.template("reading")]
        chatting = {"week" : [], "month" : [], "year" : [], "decade" : []}
        noreview = [self.template("noreview")]
        untrans = [self.template("untrans")]
        finish = [self.template("finished")]
        
        items = []
        for result in req.db.view("stories/all", startkey=[req.session.value['username']], endkey=[req.session.value['username'], {}]) :
            tmp_story = result["value"]
            tmp_storyname = tmp_story["name"]
            items.append((tmp_storyname, tmp_story))

        items.sort(key = itemhelp, reverse = True)

        for name, story in items :
            gp = self.processors[self.tofrom(story) if "source_language" in story else "zh-CHS,en"]

            reviewed = not ("reviewed" not in story or not story["reviewed"])
            finished = not ("finished" not in story or not story["finished"])
            if isinstance(story['uuid'], tuple) :
                uuid = story['uuid']
                mdebug("skipping UUID: " + uuid[0])
                continue

            notsure = self.sidestart(req, name, username, story, reviewed, finished, gp, tzoffset)

            if not story["translated"] : 
                untrans_count += 1
                untrans += notsure
                untrans.append("\n")

                if not mobile :
                    untrans.append("<div id='transbutton" + story['uuid'] + "'>")
                    # This appears in the left-hand pop-out side panel and allows the user to remove a story from the system completely.
                    
                    untrans.append("<a href='/home?delete=1&#38;uuid=" + story['uuid'] + "&#38;name=" + myquote(story["name"]) + "' title='" + _("Delete") + "' style='font-size: x-small; cursor: pointer' class='btn-default btn-xs'><i class='glyphicon glyphicon-trash'></i></a>")

                    # This appears in the left-hand pop-out side panel and allows the user to begin conversion of a newly uploaded story into MICA format for learning. 
                    untrans.append("\n<a style='font-size: x-small; cursor: pointer' class='btn-default btn-xs' onclick=\"trans('" + story['uuid'] + "')\">" + _("Translate") + "</a>")
                    if "last_error" in story and not isinstance(story["last_error"], str) :
                        for err in story["last_error"] :
                            untrans.append("<br/>" + myquote(err.replace("\n", "<br/>")))

                    untrans.append("</div>&#160;")

                untrans.append("<div style='display: inline' id='translationstatus" + story['uuid'] + "'></div>")

                if "translating" in story and story["translating"] :
                    untrans.append("\n<script>translist.push('" + story["uuid"] + "');</script>")
                untrans.append("</td>")
                untrans.append("</tr>")
            else : 
                notsure.append("")
                if not mobile :
                    # This appears in the left-hand pop-out side panel and allows the user to throw away (i.e. Forget) the currently processed version of a story. Afterwards, the user can subsequently throw away the story completely or re-translate it. 
                    notsure.append("\n<a href='/home?forget=1&#38;uuid=" + story['uuid'] + "' title='" + _("Forget") + "' style='font-size: x-small; cursor: pointer' class='btn-default btn-xs'><i class='glyphicon glyphicon-remove'></i></a>")
                notsure.append("\n<a onclick=\"$('#loadingModal').modal({backdrop: 'static', keyboard: false, show: true});\" title='" + _("Review") + "' style='font-size: x-small' class='btn-default btn-xs' href=\"/home?view=1&#38;uuid=" + story['uuid'] + "\"><i class='glyphicon glyphicon-search'></i></a>")
                notsure.append("\n<a onclick=\"$('#loadingModal').modal({backdrop: 'static', keyboard: false, show: true});\" title='" + _("Edit") + "' style='font-size: x-small' class='btn-default btn-xs' href=\"/edit?view=1&#38;uuid=" + story['uuid'] + "\"><i class='glyphicon glyphicon-pencil'></i></a>")
                notsure.append("\n<a onclick=\"$('#loadingModal').modal({backdrop: 'static', keyboard: false, show: true});\" title='" + _("Read") + "' style='font-size: x-small' class='btn-default btn-xs' href=\"/read?view=1&#38;uuid=" + story['uuid'] + "\"><i class='glyphicon glyphicon-book'></i></a>")

                if finished :
                   finish += notsure
                    # This appears in the left-hand pop-out side panel and allows the user to change their mind and indicate that they are indeed not finished reading the story. This will move the story back into the 'Reading' section. 
                   finish.append("\n<a title='" + _("Not finished") + "' style='font-size: x-small; cursor: pointer' class='btn-default btn-xs' onclick=\"finishstory('" + story['uuid'] + "', 0)\"><i class='glyphicon glyphicon-thumbs-down'></i></a>")
                   finish.append("</td></tr>")
                elif reviewed :
                   if "filetype" in story and story["filetype"] == "chat" :
                       period = story["name"].split(";")[1]
                       chatting[period_mapping[period]] += notsure
                       chatting[period_mapping[period]].append("</td></tr>")
                   else :
                       reading_count += 1
                       reading += notsure
                        # This appears in the left-hand pop-out side panel and allows the user to change their mind and indicate that they are not finished reviewing a story. This will move the story back into the 'Reviewing' section. 
                       reading.append("\n<a title='" + _("Review not complete") + "' style='font-size: x-small; cursor: pointer' class='btn-default btn-xs' onclick=\"reviewstory('" + story['uuid'] + "',0)\"><i class='glyphicon glyphicon-arrow-down'></i></a>")
                        # This appears in the left-hand pop-out side panel and allows the user to indicate that they have finished with a story and do not want to see it at the top of the list anymore. This will move the story back into the 'Finished' section. 
                       reading.append("<a title='" + _("Finished reading") + "' style='font-size: x-small; cursor: pointer' class='btn-default btn-xs' onclick=\"finishstory('" + story['uuid'] + "',1)\"><i class='glyphicon glyphicon-thumbs-up'></i></a>")
                       reading.append("</td></tr>")
                else :
                   noreview += notsure
                    # This appears in the left-hand pop-out side panel and allows the user to indicate that they have finished reviewing a story for accuracy. This will move the story into the 'Reading' section. 
                   noreview.append("\n<a title='" + _("Review Complete") + "' style='font-size: x-small' class='btn btn-default btn-xs' onclick=\"reviewstory('" + story['uuid'] + "', 1)\"><i class='glyphicon glyphicon-arrow-up'></i></a>")
                   noreview.append("</td></tr>")
                   
        return [untrans_count, reading, noreview, untrans, finish, reading_count, chatting] 
    
    def memocount(self, req, story, page):
        added = {}
        unique = {}
        progress = []
        total_memorized = 0
        total_unique = 0
        trans_id = 0
        try :
            page_dict = req.db[self.story(req, story["name"]) + ":pages:" + str(page)]
        except couch_adapter.ResourceNotFound, e :
            return False
        units = page_dict["units"]
        
        memorized = self.view_keys(req, "memorized", units) 

        for x in range(0, len(units)) :
            unit = units[x]
            if "hash" not in unit :
                trans_id += 1
                continue
            ret = self.get_parts(unit, self.tofrom(story))
            if not ret :
                trans_id += 1
                continue
            py, target = ret
            if unit["hash"] in memorized :
                if unit["hash"] not in added :
                    added[unit["hash"]] = unit
                    progress.append([py, target, unit, x, trans_id, page])
                    total_memorized += 1

            if py and py not in self.processors[self.tofrom(story)].punctuation :
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

        changes = req.db.try_get(which(req, char))
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

        processor = getattr(processors, processor_map[self.tofrom(story)])(self, params)

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

                    changes = req.db.try_get(self.merge(req, char))
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

    def add_story_from_source(self, req, filename, source, filetype, source_lang, target_lang, sourcepath) :
        if sourcepath :
            assert(source == False)

            # Do a test that we can read it back in.
            fp = open(sourcepath, 'rb')

        if filetype == "chat" :
            assert(not req.db.doc_exist(self.story(req, filename)))
        elif req.db.doc_exist(self.story(req, filename)) :
            return self.bootstrap(req, self.heromsg + "\n" + _("Upload Failed! Story already exists") + ": " + filename + "</div>")
        
        mdebug("Received new story name: " + filename)

        gp = self.processors[source_lang + "," + target_lang]

        removespaces = False if gp.already_romanized else (True if filetype == "txt" else False)

        if removespaces :
            mdebug("Remove spaces requested!")
        else :
            mdebug("Remove spaces not requested.")
        
        if filetype == "txt" :
            if not source :
                source = fp.read()
            mdebug("Source: " + source)

        new_uuid = str(uuid_uuid4())

        story = {
            'uuid' : new_uuid,
            'translated' : False if filetype != "chat" else True,
            'reviewed' : False if filetype != "chat" else True,
            'name' : filename,
            'filetype' : filetype,
            'source_language' : source_lang.decode("utf-8"), 
            'target_language' : target_lang.decode("utf-8"), 
            'format' : story_format,
            'date' : timest(),
            'nb_pages' : 0,
        }
        
        try :
            if filetype == "chat" :
                pass
            elif filetype == "pdf" :
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

                    # I'm keeping the code here to parse the image in case
                    # we want them in the future. Even though we're still 
                    # going to render the whole page anyway.

                    density = "300"
                    bgColor = PythonMagick.Color("#ffffff")
                    im = PythonMagick.Image()
                    im.density(density)
                    im.read((sourcepath + "[" + str(pagecount) + "]").encode("utf-8"))
                    size = "%sx%s" % (im.columns(), im.rows())
                    flattened = PythonMagick.Image(size, bgColor)
                    flattened.type = im.type
                    flattened.composite(im, 0, 0, PythonMagick.CompositeOperator.SrcOverCompositeOp)
                    flattened.density(density)
                    flattened.quality(100)
                    blob = PythonMagick.Blob()
                    flattened.write(blob, "png")
                    images = [blob.data] + images

                    if gp.already_romanized :
                        new_page = data2
                    else :
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

                    if (pagecount % 10) == 0 :
                       jobs = req.db["MICA:jobs"]
                       jobs["list"][req.job_uuid]["result"] = _("Page") + ": " + str(pagecount)
                       req.db["MICA:jobs"] = jobs

                device.close()
                fp.close()
            else : # TXT format
                de_source = source.decode("utf-8") if isinstance(source, str) else source
                mdebug("Page input:\n " + source)
                if removespaces :
                    de_source = de_source.replace(u' ', u'')
                    mdebug("After remove spaces:\n " + de_source)

                origkey = self.story(req, filename) + ":original"

                if req.db.doc_exist(origkey) :
                    # Sometimes we code in errors. Until we have a proper cleanup function,
                    # just overwrite the original and lose a little disk space if the story
                    # is not re-uploaded.
                    # The same problem is already handled for non-TXT stories, like PDFs
                    # because the original goes into put_attachment, which deletes the original
                    # attachment if it already exists.
                    orig = req.db[origkey]
                    orig["value"] = de_source
                else :
                    orig = { "value" : de_source }

                req.db[origkey] = orig
            
            req.db[self.story(req, filename)] = story
            req.db[self.index(req, story["uuid"])] = { "value" : filename }

            self.clear_story(req)
        except Exception, e :
            # Need to make sure we clear the uploaded file before releasing the exception.
            for line in format_exc().splitlines() :
                merr(line)
            if sourcepath :
                fp.close()
                os_remove(sourcepath)
            raise e

        if sourcepath :
            fp.close()
            os_remove(sourcepath)

        return _("Upload Complete! Story ready for translation") + ": " + filename
        
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
           req.db["_design/" + name] = json_loads(vc)

    def clear_chat(self, req, story_name):
        peer = story_name.split(";")[-1]
        mdebug("Checking if peer is in session cache: " + peer)

        if "chats" not in req.session.value :
            req.session.value["chats"] = {"days" : {}, "weeks" : {}, "months" : {}, "years" : {}, "decades" : {}}
            req.session.save()

        for period_key in multipliers.keys() :
            if period_key not in req.session.value["chats"] :
                req.session.value["chats"][period_key] = {}
                req.session.save()

            if peer in req.session.value["chats"][period_key] :
                mdebug("Clearing chat with peer from session cache:" + peer)
                del req.session.value["chats"][period_key][peer]
                req.session.save()
            
    def clear_story(self, req) :
        uuid = False
        if "current_story" in req.session.value :
            uuid = req.session.value["current_story"]
            name_map = req.db.try_get(self.index(req, uuid))
            if name_map :
                self.clear_chat(req, name_map["value"])
            del req.session.value["current_story"]
            req.session.save()

    def set_page(self, req, story, page) :
        if "current_page" not in story or story["current_page"] != str(page) :
            mdebug("Setting story " + story["name"] + " to page: " + str(page))
            tmp_story = req.db[self.story(req, story["name"])]
            tmp_story["current_page"] = story["current_page"] = str(page)
            req.db[self.story(req, story["name"])] = tmp_story


    def warn_not_replicated(self, req, bootstrap = True, now = False) :
        self.clear_story(req)

        if mobile :
            msg = _("This account is not fully synchronized. You can follow the progress at the top of the screen until the 'download' arrow reaches 100.")
        else :
            if "connected" in req.session.value and req.session.value["connected"] :
                mwarn("Setting to disconnected!")
                req.session.value["connected"] = False
                req.session.save()

            # Indicates a bug in the software due to invalid synchronization between the user's mobile device and the website. 
            msg = _("Synchronization error. Please report this to the author. Thank you.")

        if bootstrap :
            mwarn("bootstrapping: " + msg)
            return self.bootstrap(req, self.heromsg + "\n<h4>" + msg + "</h4></div>", now = now)
        else :
            mwarn("raw: " + msg)
            return msg

    def clean_session(self, req) :
        mwarn("Loggin out user now.")
        req.session.value['connected'] = False

        if 'username' in req.session.value :
            if mobile :
                req.db.stop_replication()

            username = req.session.value['username']
            if username in self.dbs :
                del self.dbs[username]

            if username in self.view_runs :
                del self.view_runs[username]

            req.session.save()

    def check_all_views(self, req) :
        self.view_check(req, "stories")
        self.view_check(req, "tonechanges")
        self.view_check(req, "mergegroups")
        self.view_check(req, "splits")
        self.view_check(req, "memorized")
        self.view_check(req, "chats")
        if not mobile :
            self.view_check(req, "download")

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

        req.db.detach_thread()

    def multiple_select(self, req, record, nb_unit, mindex, trans_id, page, name) :
        # This is also kind of silly: getting a whole page
        # of units just to update one of them.
        # Maybe it's not so high overhead. I dunno.
        page_dict = req.db[self.story(req, name) + ":pages:" + str(page)]
        unit = page_dict["units"][nb_unit]
        
        unit["multiple_correct"] = mindex
        
        self.rehash_correct_polyphome(unit) 
        
        page_dict["units"][nb_unit] = unit
        req.db[self.story(req, name) + ":pages:" + str(page)] = page_dict

        if record :
            self.add_record(req, unit, mindex, self.tones, "selected") 
        return unit

    def run_job_complete(self, req, cleanup, self_delete, job) :
        if cleanup :
            cleanup(*args, **kwargs)

        if self_delete and job["success"] :
            mdebug("Deleting job immediately. Not adding to list")
            try :
                jobs = req.db["MICA:jobs"]
                if job["uuid"] in jobs["list"] :
                    del jobs["list"][job["uuid"]]
                    req.db["MICA:jobs"] = jobs
            except Exception, e :
                mdebug("Failed to delete immediately: " + str(e))
                while True :
                    sleep(3600)
        else :
            job["finished"] = True
            jobs = req.db["MICA:jobs"]
            jobs["list"][job["uuid"]] = job
            req.db["MICA:jobs"] = jobs

    def run_job(self, req, func, cleanup, job, self_delete, args, kwargs) :
        self.install_local_language(req)

        try :
            mdebug("Running job: " + str(job))
            req.job_uuid = job["uuid"]
            job["result"] = self.safe_execute(func, args, kwargs)
            job["success"] = True
            mdebug("Complete job: " + str(job))
        except Exception, e :
            mdebug("Error job: " + str(job) + " " + str(e))
            job["success"] = False
            job["result"] = str(e)

        self.safe_execute(self.run_job_complete, args = [req, cleanup, self_delete, job])

        req.db.detach_thread()

    def new_job(self, req, func, cleanup, description, obj, self_delete, args = [], kwargs = {}) :
        out = ""
        job = { "uuid" : str(uuid_uuid4()),
               "description" : description, 
               "object" : obj,
               "date" : timest(),
               "finished" : False,
               "success" : False,
               "result" : False,
        }

        mdebug("Submitting job: " + str(job))

        try :
            jobs = req.db.try_get("MICA:jobs")
            if not jobs :
                jobs = {"list" : {}}

            vt = Thread(target=self.run_job, args = [req, func, cleanup, job, self_delete, args, kwargs])
            vt.daemon = True
            jobs["list"][job["uuid"]] = job
            req.db["MICA:jobs"] = jobs

            mdebug("Starting job: " + str(job))

            vt.start()

            # This happens when a user uploads a new story, or performs other long-running actions that
            # cannot be completed in a single click. The request goes into a background job and is
            # processed in the background.
            out = self.heromsg + "\n<h4>" + _("Request submitted. Please refresh later. Thank You.") + "<script>window.location.href='/home';</script></h4></div>"
                
        except Exception, e :
            # If a background request that was submitted (like uploading a new story) fails to complete,
            # this message will appear to instruct them to try again.
            out = self.heromsg + "\n<h4>Error: " + _("Please try your request again.") + ": " + _(description) + "</h4></div>"
            out += str(e)

        mdebug("Submitted: " + str(job))
        return self.bootstrap(req, out)
            
    def forgetstory(self, req, uuid, name) :
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
        # 'Forgot' a story using the button in the side-panel.
        return _("Forgotten")

    def deletestory(self, req, uuid, name) : 
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
                    if tmp_story["filetype"] == "chat" :
                        self.clear_chat(req, tmp_story["name"])
                        
                    mdebug("Deleting original pages")
                    allorig = []
                    for result in req.db.view('stories/alloriginal', startkey=[req.session.value['username'], name], endkey=[req.session.value['username'], name, {}]) :
                        allorig.append(result["key"][2])
                    mdebug("List built.")
                    pagecount = 0
                    for tmppage in allorig :
                        mdebug("Deleting original " + str(tmppage) + " from story " + name)
                        del req.db[self.story(req, name) + ":original:" + str(tmppage)]
                        pagecount += 1
                        if (pagecount % 10) == 0 :
                           jobs = req.db["MICA:jobs"]
                           # This appears when a story is being deleted from the database. The page
                           # number will appear at the end of 'Deleted Page' to indicate how many
                           # pages of the story have been deleted.
                           jobs["list"][req.job_uuid]["result"] = _("Deleted Page") + ": " + str(pagecount)
                           req.db["MICA:jobs"] = jobs
                    mdebug("Deleted.")

                
            if name and story_found :
                del req.db[self.story(req, name)]
            
            if req.db.doc_exist(self.index(req, uuid)) :
                del req.db[self.index(req, uuid)]
                
        if "current_story" in req.session.value and req.session.value["current_story"] == uuid :
            self.clear_story(req)
            uuid = False
        # The user has deleted a story from the system.
        return _("Deleted")

    def api_validate(self, req, human_default = "0") :
        human = True if int(req.http.params.get("human", human_default)) else False

        if "connected" not in req.session.value or not req.session.value["connected"] :
            if not req.http.params.get("username") or not req.http.params.get("password") :
                return self.api(req, {"success" : False, "desc" : _("API access denied")}, human)
            else :
                username = req.http.params.get("username")
                password = req.http.params.get("password")
                auth_user, reason = self.authenticate(username, password, self.credentials())
                if not auth_user :
                    return self.api(req, {"success" : False, "desc" : _("API access denied") + ": " + str(reason)}, human)

        return False 

    def common_disconnect(self, req) : 
        self.clean_session(req)
        self.install_local_language(req)
        req.skip_show = True
        return self.bootstrap(req, run_template(req, FrontPageElement))

    def common_privacy(self, req) :
        self.install_local_language(req)
        output = ""
        helpfh = codecs_open(cwd + "serve/privacy_template.html", "r", "utf-8")
        output += helpfh.read().encode('utf-8').replace("\n", "<br/>")
        helpfh.close()
        return self.bootstrap(req, output, pretend_disconnected = True)

    def common_help(self, req) :
        l = self.install_local_language(req)
        output = ""
        helpfh = codecs_open(cwd + "serve/" + tutorials[l], "r", "utf-8")
        output += helpfh.read().encode('utf-8').replace("\n", "<br/>")
        helpfh.close()
        output = output.replace("https://raw.githubusercontent.com/hinesmr/mica/master", "")
        req.skip_show = True
        return self.bootstrap(req, output)

    def common_switchlang(self, req) :
        if not req.http.params.get("lang") :
            return self.bootstrap(req, 'error', now = True)

        req.session.value["language"] = req.http.params.get("lang")
        req.session.save()
        self.install_local_language(req)
        return self.bootstrap(req, run_template(req, FrontPageElement))

    def common_auth(self, req) :
        # We only allow jabber to do this from the localhost. Nowhere else.
        if req.source != "127.0.0.1" :
            return self.bootstrap(req, 'error', now = True)

        if not req.http.params.get("username") or not req.http.params.get("password") :
            return self.bootstrap(req, 'error', now = True)

        username = req.http.params.get("username").lower()
        password = req.http.params.get("password")

        auth_user = self.userdb.try_get("org.couchdb.user:" + username)

        if not auth_user or "temp_jabber_pw" not in auth_user or password != auth_user["temp_jabber_pw"] :
            auth_user, reason = self.authenticate(username, password, self.credentials())

            if not auth_user :
                return self.bootstrap(req, 'bad', now = True)
            else :
                mdebug("Success jabber auth w/ password: " + username)
        else :
            mdebug("Success jabber auth w/ token: " + username)

        return self.bootstrap(req, 'good', now = True)

    def common_online(self, req) :
        v = self.api_validate(req)
        if v :
            return v

        out = {"success" : True, "desc" : False}
        target_language = req.http.params.get("target_language")
        source_language = req.http.params.get("source_language")
        requests = json_loads(req.http.params.get("requests"))
        language = req.http.params.get("lang")

        self.install_local_language(req, language)
        try :
            out["result"] = self.translate_and_check_array(req, False, requests, target_language, source_language)
        except OnlineTranslateException, e :
            return self.api(req, {"success" : False, "desc" : _("Internet access error. Try again later: ") + str(e)}, False, wrap = False)

        return self.api(req, out, False, wrap = False)

    def common_instant(self, req) :
        human = True if int(req.http.params.get("human", "1")) else False

        v = self.api_validate(req, "1")
        if v :
            return v

        target_language = req.http.params.get("target_language")
        source_language = req.http.params.get("source_language")
        source = req.http.params.get("source")
        language = req.http.params.get("lang")

        out = ""
        if not human :
            out = {"success" : True, "online" : [], "offline" : []}

        mdebug("Request to translate: " + str(source) + " from " + source_language + " to " + target_language)

        self.install_local_language(req, language)

        if human :
            out += "<h4><b>" + _("Online instant translation") + ":</b></h4>"

        requests = [source]
        gp = self.processors[source_language + "," + target_language]

        breakout = source.decode("utf-8") if isinstance(source, str) else source
        if gp.already_romanized :
            breakout = breakout.split(" ")
        
        if len(breakout) > 1 :
            for x in range(0, len(breakout)) :
                requests.append(breakout[x].encode("utf-8"))

        try :
            result = self.translate_and_check_array(req, False, requests, target_language, source_language)
            if not result :
                if human :
                    out += _("Internet access error. Try again later: ") + "<br/>"
                else :
                    out["whole"] = {"source" : source, "target" : _("Internet access error. Try again later: ")}
            else :
                for x in range(0, len(requests)) : 
                    if (x + 1) > len(result) :
                        continue

                    part = result[x]
                    if "TranslatedText" not in part :
                        target = _("No instant translation available.")
                    else :
                        target = part["TranslatedText"].encode("utf-8")
                    
                    if x == 0 :
                        if human :
                            out += _("Selected instant translation") + " (" + source + "): " + target + "<br/>\n"
                        else :
                            out["whole"] = {"source" : source, "target" : target}
                    else :
                        char = breakout[x-1].encode("utf-8")
                        if human :
                            if x == 1:
                                out += _("Piecemeal instant translation") + ":<br/>\n"
                        if human :
                            out += "(" + char + "): "
                            out += target 
                            out += "<br/>\n"
                        else :
                            out["online"].append({"char" : char, "target" : target})

        except OnlineTranslateException, e :
            mwarn("Online translate error: " + str(e))
            return self.api(req, {"success" : False, "desc" : _("Internet access error. Try again later: ") + str(e)}, human)

               
        if human :
            out += "<h4><b>" + _("Offline instant translation") + ":</b></h4>"

        try :
            opaque = gp.parse_page_start()
            gp.test_dictionaries(opaque)
            try :
                for idx in range(0, len(requests)) :
                    request = requests[idx]
                    if gp.already_romanized and len(requests) > 1 and idx == 0 :
                        continue
                    request_decoded = request.decode("utf-8")
                    tar = gp.get_first_translation(opaque, request_decoded, False)
                    if tar :
                        for target in tar :
                            ipa = gp.get_ipa(request_decoded)

                            if human :
                                out += "<br/>(" + request
                                if ipa :
                                    out += ", " + str(ipa[0])
                                out += "): " + target.encode("utf-8")
                            else :
                                out["offline"].append({"request" : request, "ipa" : ipa, "target" : target.encode("utf-8")})
                    else :
                        if human :
                            out += "<br/>(" + request + ") " + _("No instant translation found.")
                        else :
                            out["offline"].append({"request" : request, "ipa" : False, "target" : False})

                gp.parse_page_stop(opaque)
            except OSError, e :
                mdebug("Looking up target instant translation failed: " + str(e))
                return self.api(req, {"success" : False, "desc" : _("Please wait until this account is fully synchronized for an offline instant translation.")}, human)
        except Exception, e :
            mdebug("Instant test failed: " + str(e))
            return self.api(req, {"success" : False, "desc" : _("Please wait until this account is fully synchronized for an offline instant translation.")}, human)

        if human :
            out = {"success" : True, "desc" : out}

        return self.api(req, out, human)

    def roll_period(self, req, period_key, period_next_key, peer) :
        to_delete = []

        for result in req.db.view('chats/all', startkey=[req.session.value['username'], period_key, peer], endkey=[req.session.value['username'], period_key, peer, {}]) :
            tmp_story = result["value"]
            tmp_storyname = tmp_story["name"]

            [x, period, howmany, peer] = tmp_story["name"].split(";")

            period_difference = self.current_period(period_key) - int(howmany)
            period_difference_max = multipliers[period_key] - 1
            if period_difference < period_difference_max :
                continue

            to_delete.append((tmp_story["name"], tmp_story["uuid"]))

            pages = self.nb_pages(req, tmp_story)
            for page_nb in range(0, pages) :
                origkey = self.chat_period(req, period_key, peer, (int(howmany) * counts[period])) + ":original:" + str(page_nb)
                pagekey = self.chat_period(req, period_key, peer, (int(howmany) * counts[period])) + ":pages:" + str(page_nb)
                orig = req.db.try_get(origkey)
                if orig :
                    mdebug("Got original to roll.")
                    old_messages = orig["messages"]
                    page = req.db.try_get(pagekey)
                    if page :
                        mdebug("Got page to roll.")
                        old_units = page["units"]

                        mdebug("Rolling " + str(len(old_messages)) + " messages of period " + period_key + " from peer " + peer + " to next period " + period_next_key)
                        self.add_period(req, period_next_key, peer, old_messages, old_units, tmp_story, int(howmany) * counts[period_key])
                        mdebug("add for roll returned")
                    else :
                        mdebug("Couldn't find page to roll: " + pagekey)
                else :
                    mdebug("Couldn't find original to roll: " + origkey)

        mdebug("Checking for deletes...")
        for (name, uuid) in to_delete :
            mdebug("Want to delete story: " + name)
            self.new_job(req, self.deletestory, False, _("Deleting Story From Database"), name, True, args = [req, uuid, name])
        mdebug("Roll complete for period: " + period_key)

    def period_keys(self, req, period_key, current_day, peer, page) :
        origkey = self.chat_period(req, period_key, peer, current_day) + ":original:" + str(page)
        pagekey = self.chat_period(req, period_key, peer, current_day) + ":pages:" + str(page)
        return origkey, pagekey

    def add_period(self, req, period_key, peer, messages, new_units, story, current_day = False) :
            if peer not in req.session.value["chats"][period_key] :
                mdebug("Peer not in session. Checking for story...")
                if not req.db.try_get(self.chat_period(req, period_key, peer, current_day)) :
                    mdebug("Adding new story for period " + period_key + " and peer" + peer)
                    self.add_story_from_source(req, self.chat_period_name(period_key, peer, current_day), False, "chat", story["source_language"], story["target_language"], False)
                mdebug("Looking up story for period " + period_key + " and peer" + peer)
                story = req.db[self.chat_period(req, period_key, peer, current_day)]
                req.session.value["chats"][period_key][peer] = story 
                req.session.save()

            csession = req.session.value["chats"][period_key][peer]

            page = str(max(0, int(csession["nb_pages"]) - 1))

            changed_page = False
            while True :
                origkey, pagekey = self.period_keys(req, period_key, current_day, peer, page)
                mdebug("Adding message period " + period_key + " to page key: " + pagekey)

                chat_orig = req.db.try_get(origkey)
                chat_page = False 

                if chat_orig :
                    chat_page = req.db.try_get(pagekey)
                else :
                    chat_orig = { "messages" : [] }

                if not chat_page : 
                    chat_page = { "units" : [] }

                # 20 messages per page is just a wild guess. Will need to make it
                # configurable in the preferences, of course

                if len(chat_orig["messages"]) >= 20 :
                    mdebug("Adding new page over 20 messages.")
                    changed_page = True
                    page = int(page) + 1 

                    origkey, pagekey = self.period_keys(req, period_key, current_day, peer, page)
                    if req.db.try_get(origkey) or req.db.try_get(pagekey) :
                        mdebug("There is a discrepancy between cached pages and db pages. Resetting.")
                        story["name"] = self.chat_period_name(period_key, peer, current_day)
                        page = str(self.nb_pages(req, story, force = True) - 1)

                    continue
                break
                    
            chat_orig["messages"] += messages
            mdebug("Adding to: " + origkey)
            req.db[origkey] = chat_orig
            mdebug("Adding to: " + pagekey)
            chat_page["units"] += new_units
            req.db[pagekey] = chat_page
            mdebug("Finished adding")

            if changed_page or csession["nb_pages"] == 0 :
                mdebug("Recounting: " + pagekey)
                story["name"] = self.chat_period_name(period_key, peer, current_day)
                story["nb_pages"] = str(int(page) + 1)
                req.session.value["chats"][period_key][peer] = story 
                req.session.save()
                self.nb_pages(req, story, force = True)
            mdebug("Add complete")

    def common_chat_ime(self, req) :
        self.imemutex.acquire()
        try :
            self.install_local_language(req, req.http.params.get("lang"))
            mode = req.http.params.get("mode")
            orig = req.http.params.get("source")
            imes = int(req.http.params.get("ime"), 0)
            msgfrom = req.http.params.get("msgfrom", False)
            msgto = req.http.params.get("msgto", False)
            peer = req.http.params.get("peer", False)
            timestamp = req.http.params.get("ts", False)
            if timestamp :
                timestamp = float(timestamp) / 1000.0

            start_trans_id = int(req.http.params.get("start_trans_id", 0))
            story = {
               "name" : "ime",
               "target_language" : supported_map[req.http.params.get("target_language")],
               "source_language" : supported_map[req.http.params.get("source_language")],
            }

            gp = self.processors[self.tofrom(story)]
            out = {"success" : False}
            lens = []
            chars = []
            source = ""
            if orig :
                imes = int(req.http.params.get("ime"))
                #mdebug("Type: " + str(type(orig)))
                #start = timest()
                char_result = gp.get_chars(orig)
                #mdebug("IME time: " + str(timest() - start) + " for " + str(orig))

                if not char_result :
                    mdebug("No result from search for: " + orig)
                    out["desc"] = _("No result") + "."
                    if not gp.already_romanized :
                        self.imemutex.release()
                        return self.api(req, out, False)

                    source = orig
                else :
                    imes = len(char_result)

                    for imex in range(0, imes) :
                        if imes > 0 :
                            source += " " + str(imex + 1) + ". "
                        source += char_result[imex][0]
                        lens.append(len(char_result[imex][0]))
                        chars.append(char_result[imex][0])

            else :
                # legacy implementation for v0.5
                for imex in range(1, imes + 1) :
                    if imes > 1 :
                        source += " " + str(imex) + ". "
                    char_result = req.http.params.get("ime" + str(imex)).decode("utf-8")
                    source += char_result 
                    lens.append(len(char_result))
                    chars.append(char_result)

            story["source"] = source
        except Exception, e :
            out = ""
            for line in format_exc().splitlines() :
                out += line + "\n"
            merr(out)
            self.imemutex.release()
            raise e


        # FIXME: The long-term solution to open all sqlite database handles
        # inside the main routine and use couroutines to synchronize
        # all DB accesses from the main processor, but that requires
        # re-writing the processor, let's deal with that later.
        # The goal is to allow sqlite to do normal caching.
        # Currently, the RomanizedSource languages are still are
        # not closing/re-opening their sqlite handles and may crash.
        # We don't want to re-open them anyway and need to keep
        # them open in the main thread.
        # When we finish this fix, we can remove the imemutex lock below.

        cerror = False
        try :
            try :
                #sys_settrace(tracefunc)
                #start = timest()
                self.parse(req, story, live = True)
                #sys_settrace(None)
                #mdebug("Parse time: " + str(timest() - start) + " for " + str(orig))
                #call_report()

            except Exception, e :
                merr("Cannot parse chat: " + str(e))
                cerror = e
            finally :
                if cerror :
                    self.imemutex.release()
                    raise cerror

            if peer :
                messages = [{
                                "timestamp" : timestamp,
                                "from" : msgfrom,
                                "to" : msgto,
                                "msg" : source,
                                "source_language" : story["source_language"],
                                "target_language" : story["target_language"],
                            }]

                before = gp.add_unit([msgfrom], msgfrom, [msgfrom], punctuation = True, timestamp = timestamp)
                self.rehash_correct_polyphome(before)
                self.add_period(req, "days", peer, messages, [before] + story["pages"]["0"]["units"], story)
                
            out["success"] = True
            out["result"] = {"chars" : chars, "lens" : lens, "word" : orig}

            select_idx = 1
            for unit_idx in range(2, min(len(story["pages"]["0"]["units"]), (len(chars) * 2 + 1)), 2) :
                story["pages"]["0"]["units"][unit_idx]["select_idx"] = select_idx
                select_idx += 1

            out["result"]["human"] = self.view_page(req, False, False, story, mode, "", "0", "100", "false", disk = False, start_trans_id = start_trans_id, chat = True if not peer else False)


        except OSError, e :
            merr("OSError: " + str(e))
            out["result"] = self.warn_not_replicated(req, bootstrap = False)
        except processors.NotReady, e :
            merr("Translation processor is not ready: " + str(e))
            out["result"] = self.warn_not_replicated(req, bootstrap = False)
        except Exception, e :
            err = ""
            for line in format_exc().splitlines() :
                err += line + "\n"
            merr(err)
            out["result"] = _("Chat error") + ": " + source 

        self.imemutex.release()

        return self.api(req, out, False) 

    def common_uploadfile(self, req) :
        fh = req.http.params.get("storyfile")
        filetype = req.http.params.get("filetype")
        langtype = req.http.params.get("languagetype")
        source_lang, target_lang = langtype.split(",")
        # Stream the file contents directly to disk, first
        # Make sure it's not too big while we're doing it...
        sourcepath = "/tmp/mica_uploads/" + binascii_hexlify(os_urandom(4)) + "." + filetype
        mdebug("Will stream upload to " + sourcepath)
        sourcefh = open(sourcepath, 'wb')

        sourcebytes = 0
        maxbytes = { "pdf" : 30*1024*1024, "txt" : 1*1024*1024 }
        sourcefailed = False
        while True :
            data = fh.file.read(1)
            if data == '' :
                break
            sourcebytes += 1
            if sourcebytes > maxbytes[filetype] :
                sourcefailed = True
                break 

            sourcefh.write(data)

        sourcefh.close()
        fh.file.close()

        if sourcefailed :
            mdebug("File is too big. Deleting it and aborting upload: " + fh.filename)
            os_remove(sourcepath)
            # This appears when the user tries to upload a story document that is too large.
            # At the end of the message will appear something like '30 MB', or whatever is
            # the current maximum file size allowed by the system.
            return self.bootstrap(req, self.heromsg + "\n<h4>" + _("File is too big. Maximum file size:") + " " + str(maxbytes[filetype] / 1024 / 1024) + " MB.</h4></div>")

        mdebug("File " + fh.filename + " uploaded to disk. Bytes: " + str(sourcebytes))

        # A new story has been uploaded and is being processed in the background.
        return self.new_job(req, self.add_story_from_source, False, _("Processing New PDF Story"), fh.filename, False, args = [req, fh.filename.lower().replace(" ","_").replace(",","_").replace(";","_"), False, filetype, source_lang, target_lang, sourcepath])

    def common_uploadtext(self, req) :
        source = req.http.params.get("storytext") + "\n"
        filename = req.http.params.get("storyname").lower().replace(" ","_").replace(",","_").replace(";","_")
        langtype = req.http.params.get("languagetype")
        source_lang, target_lang = langtype.split(",")

        # A new story has been uploaded and is being processed in the background.
        return self.new_job(req, self.add_story_from_source, False, _("Processing New TXT Story"), filename, False, args = [req, filename, source, "txt", source_lang, target_lang, False])

    def common_tstatus(self, req, story) :
        uuid = story["uuid"]
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

    def common_finished(self, req, story) :
        name = story["name"]
        finished = True if req.http.params.get("finished") == "1" else False
        tmp_story = req.db[self.story(req, name)]
        tmp_story["finished"] = finished 
        req.db[self.story(req, name)] = tmp_story 
        # Finished reviewing a story in review mode.
        return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Finished") + ".</h4></div>", now = True)

    def common_reviewed(self, req, story) :
        name = story["name"]
        uuid = story["uuid"]
        reviewed = True if req.http.params.get("reviewed") == "1" else False
        tmp_story = req.db[self.story(req, name)]
        tmp_story["reviewed"] = reviewed
        if reviewed :
            if "finished" not in tmp_story or tmp_story["finished"] :
                tmp_story["finished"] = False

            pages = self.nb_pages(req, tmp_story)
            if pages == 1 :
                final = {}

                if req.db.doc_exist(self.story(req, name) + ":final") :
                    final["_rev"] = req.db[self.story(req, name) + ":final"]["_rev"]

                minfo("Generating final pagesets...")
                
                for page in range(0, pages) :
                    minfo("Page " + str(page) + "...")
                    final[str(page)] = self.view_page(req, uuid, name, \
                        story, req.action, "", str(page), \
                        req.session.value["app_chars_per_line"] if mobile else req.session.value["web_chars_per_line"], meaning_mode, disk = True)
                    
                req.db[self.story(req, name) + ":final"] = final
        req.db[self.story(req, name)] = tmp_story 
        return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Reviewed") + ".</h4></div>", now = True)

    def common_translate(self, req, story) :
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

    def common_jobs(self, req, jobs) :
        out = self.heromsg + "\n<h4>" + _("MICA is busy processing the following. Please wait") + ":</h4></div>\n"
        out += "<table class='table'>"

        finished = []

        for jkey in jobs["list"] :
            job = jobs["list"][jkey]
            out += "<tr>"
            if job["finished"] :
                finished.append(job)
                out += "<td>" + _("Finished") + ": </td>"
            else :
                # Same as 'processing', when a background job is running like uploading/deleting stories.
                out += "<td>" + _("Running") + ": </td>"

            out += "<td>" + _(job["description"]) + "</td><td>&#160;&#160;</td><td>" + job["object"] + "</td><td>&#160;&#160;</td>" 
        
            out += "<td>"

            if job["result"] :
                out += job["result"]
            elif not job["finished"] :
                out += _("Please wait")

            out += "</td>"

            out += "</tr>"

        out += "</table>"

        if len(finished) > 0 :
            for job in finished :
                del jobs["list"][job["uuid"]]
            req.db["MICA:jobs"] = jobs

        return self.bootstrap(req, out)

    def common_multiple_select(self, req, story) :
        nb_unit = int(req.http.params.get("nb_unit"))
        mindex = int(req.http.params.get("index"))
        trans_id = int(req.http.params.get("trans_id"))
        page = req.http.params.get("page")
        unit = self.multiple_select(req, True, nb_unit, mindex, trans_id, page, story["name"])

        return self.bootstrap(req, self.heromsg + "\n<div id='multiresult'>" + \
                                   self.polyphomes(req, story, story["uuid"], unit, nb_unit, trans_id, page) + \
                                   "</div></div>", now = True)

    def common_memorizednostory(self, req, story) :
        memorized = int(req.http.params.get("memorizednostory"))
        multiple_correct = int(req.http.params.get("multiple_correct"))
        source = req.http.params.get("source")
        mdebug("Received memorization request without story: " + str(memorized) + " " + str(multiple_correct) + " " + source)
        nshash = self.get_polyphome_hash(multiple_correct, source)

        if memorized :
            unit = self.general_processor.add_unit([source], source, [source]) 
            unit["multiple_correct"] = multiple_correct
            unit["date"] = timest()
            unit["hash"] = nshash
            if not req.db.doc_exist(self.memorized(req, nshash)) :
                req.db[self.memorized(req, nshash)] = unit
        else :
            if req.db.doc_exist(self.memorized(req, nshash)) :
                del req.db[self.memorized(req, nshash)]

        return self.bootstrap(req, self.heromsg + "\n<div id='memoryresult'>" + _("Memorized!") + " " + \
                                   str(nshash) + "</div></div>", now = True)

    def common_memorized(self, req, story) :
        memorized = int(req.http.params.get("memorized"))
        nb_unit = int(req.http.params.get("nb_unit"))
        page = req.http.params.get("page")
        
        # FIXME This is kind of stupid - looking up the whole page
        # just to get the hash of one unit.
        # But, we are storing the whole unit dict inside
        # the memorization link - maybe or maybe not we shouldn't
        # be doing that, or we could put the whole unit's json
        # into the original memorization request. I dunno.
        
        page_dict = req.db[self.story(req, story["name"]) + ":pages:" + str(page)]
        unit = page_dict["units"][nb_unit]
        
        if memorized :
            unit["date"] = timest()
            if not req.db.doc_exist(self.memorized(req, unit["hash"])) :
                req.db[self.memorized(req, unit["hash"])] = unit
        else :
            if req.db.doc_exist(self.memorized(req, unit["hash"])) :
                del req.db[self.memorized(req, unit["hash"])]
            
        return self.bootstrap(req, self.heromsg + "\n<div id='memoryresult'>" + _("Memorized!") + " " + \
                                   unit["hash"] + "</div></div>", now = True)

    def common_storyupgrade(self, req, story) :
        name = story["name"]
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
            # 'format' referring to the database format the we are upgrading to
            return self.bootstrap(req, self.heromsg + "\n<h4>" + _("No such story format") + " :" + str(version) + ".</h4></div>")

        if "upgrading" in story and story["upgrading"] :
            curr_page = story["upgrade_page"] if "upgrade_page" in story else 0
            nbpages = self.nb_pages(req, story)
            assert(nbpages > 0)
            percent = float(curr_page) / float(nbpages) * 100
            out = self.heromsg + "\n<h4>" + _("Story upgrade status") + ": " + _("Page") + " " + str(curr_page) + "/" + str(nbpages) + ", " + '{0:.1f}'.format(percent) + "% ...</h4></div>"
            if "last_error" in story and not isinstance(story["last_error"], str) :
                out += "<br/>" + _("Last upgrade Exception") + ":<br/>"
                for err in story["last_error"] :
                    out += "<br/>" + err.replace("\n", "<br/>")
                del story["upgrading"]
                del story["last_error"]
                req.db[self.story(req, name)] = story
                story = req.db[self.story(req, name)]
            return self.bootstrap(req, out)

        if "last_error" in story :
            mdebug("Clearing out last error message.")
            del story["last_error"]
            req.db[self.story(req, name)] = story
            story = req.db[self.story(req, name)]

        mdebug("Starting upgrade thread...")
        if original == 1 : 
            ut = Thread(target = self.upgrade2, args=[req, story])
        #elif original == 2 :
        #    ut = Thread(target = self.upgrade3, args=[req, story])
        ut.daemon = True
        ut.start()
        mdebug("Upgrade thread started.")
        return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Story upgrade started. You may refresh to follow its status.") + "</h4></div>")

    def common_memolist(self, req, story) :
        list_mode = self.get_list_mode(req)
        page = req.http.params.get("page")
        output = []
                
        result = self.memocount(req, story, page)

        if result :
            total_memorized, total_unique, unique, progress = result

            pr = str(int((float(total_memorized) / float(total_unique)) * 100)) if total_unique > 0 else 0
            for result in req.db.view('memorized/allcount', startkey=[req.session.value['username']], endkey=[req.session.value['username'], {}]) :
                # In 'Reading' mode, we record lots of statistics about the user's behavior, most importantly: which words they have memorized and which ones they have not. 'Memorized all stories' is a concise statement that show the user a sum total number of across all stories of the number of words they have memorized in all.
                output.append(_("Memorized all stories") + ": " + str(result['value']) + "<br/>")
            # Same as previous, except the count only covers the page that the user is currently reading and does not include duplicate words
            output.append(_("Unique memorized page") + ": " + str(total_memorized) + "<br/>")
            # A count of all the unique words on this page, not just the ones the user has memorized.
            output.append(_("Unique words this page") + ": " + str(len(unique)) + "<br/>")
            if list_mode :
                output.append("<div class='progress progress-success progress-striped'><div class='progress-bar' style='width: ")
                output.append(str(pr) + "%;'> (" + str(pr) + "%)</div></div>")

                if total_memorized :
                    output.append("<div class='panel-group' id='panelMemorized'>\n")
                    for p in progress :
                        output.append("""
                                <div class='panel panel-default'>
                                  <div class="panel-heading">
                                  """)
                        py, target, unit, nb_unit, trans_id, page_idx = p
                        if len(target) and target[0] == '/' :
                            target = target[1:-1]
                        tid = unit["hash"] if py else trans_id 

                        output.append("<a style='cursor: pointer' class='trans btn-default btn-xs' onclick=\"forget('" + \
                                str(tid) + "', '" + story["uuid"] + "', '" + str(nb_unit) + "', '" + str(page_idx) + "')\">" + \
                                "<i class='glyphicon glyphicon-remove'></i></a>")

                        output.append("&#160; " + "".join(unit["source"]) + ": ")
                        output.append("<a class='panel-toggle' style='display: inline' data-toggle='collapse' data-parent='#panelMemorized' href='#collapse" + tid + "'>")

                        output.append("<i class='glyphicon glyphicon-arrow-down' style='size: 50%'></i>&#160;" + py)
                        output.append("</a>")
                        output.append("</div>")
                        output.append("<div id='collapse" + tid + "' class='panel-body collapse'>")
                        output.append("<div class='panel-inner'>" + target.replace("/"," /") + "</div>")
                        output.append("</div>")
                        output.append("</div>")
                    output.append("</div>")
                else :
                    output.append("<h4>" + _("No words memorized. Get to work!") + "</h4>")
            else :
                output.append(_("If you would like to read this story, please select 'Start Syncing' from the side panel first and wait for it to replicate to your device."))
        else :
            # statistics in reading mode are disabled
            output.append("<h4>" + _("Memorization History List Disabled") + ".</h4>")

        return self.bootstrap(req, self.heromsg + "\n<div id='memolistresult'>" + "".join(output) + "</div></div>", now = True)

    def common_view(self, req, uuid, from_third_party, start_page) :
        view_mode = "text"
        if "view_mode" in req.session.value :
            view_mode = req.session.value["view_mode"]
        else :
            req.session.value["view_mode"] = view_mode 
            req.session.save()

        meaning_mode = "false"
        if "meaning_mode" in req.session.value :
            meaning_mode = req.session.value["meaning_mode"]
        else :
            req.session.value["meaning_mode"] = meaning_mode 
            req.session.save()

        output = ""
        if uuid :
            # Reload just in case the translation changed anything
            name = req.db[self.index(req, uuid)]["value"]
            story = req.db[self.story(req, name)]
            gp = self.processors[self.tofrom(story)]
 
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
                            output += "<img src='data:image/jpeg;base64," + base64_b64encode(original["images"][int(nb_image)]) + "' width='100%' height='100%'/>"
                            image_found = True
                    if not image_found :
                       # Beginning of a sentence: Original source image of the current page from which the text comes
                       output += _("Image") + " #" + str(nb_image) + " "
                       # end of thes sentence, indicating that a particular image number doesn't exist.
                       output += _("not available on this page")
                    output += "</div></div>"
                    return self.bootstrap(req, output, now = True)
                else :
                    self.set_page(req, story, page)
                    output = self.view_page(req, uuid, name, story, req.action, output, page, req.session.value["app_chars_per_line"] if mobile else req.session.value["web_chars_per_line"], meaning_mode)
                    return self.bootstrap(req, "<div><div id='pageresult'>" + output + "</div></div>", now = True)
            output = self.view(req, uuid, name, story, start_page, view_mode, meaning_mode)
        else :
            output = ""
            if from_third_party and "output" in from_third_party :
                return self.bootstrap(req, "<div id='newaccountresult'>" + from_third_party["output"] + "<br/><a href='/home' class='btn btn-default btn-primary'>" + _("Start learning!") + "</a></div>", now = True)
            elif from_third_party and "redirect" in from_third_party :
                return self.bootstrap(req, from_third_party["redirect"], now = True)

            else :
                # Beginning of a message.
                output += self.heromsg + "<h4>" + _("No story loaded. Choose a story to read from the sidebar by clicking the 'M' at the top.")
                if mobile :
                    output += "</h4><p><br/><h5>" + _("Brand new stories cannot (yet) be created/uploaded yet on the device. You must first create them on the website. (New stories require a significant amount of computer resources to prepare. Thus, they can only be synchronized to the device for regular use.") + ")</h5>"
                else :
                    # end of a message
                    output += "<br/>" + _("or create one by clicking on Account icon at the top") + ".</h4>"
                    output += "<br/><br/>"
                    output += "<h4>"
                    # Beginning of a message
                    output += _("If this is your first time here") + ", <a class='btn btn-primary' href='/help'>"
                    # end of a message
                    output += _("please read the tutorial") + "</a>"
                    output += "</h4>"
                output += "</div>"

        return self.bootstrap(req, output)

    def common_stories(self, req, story) :
        ftype = "txt" if "filetype" not in story else story["filetype"]
        if ftype != "txt" :
            # words after 'a' indicate the type of the story's original format, such as PDF, or TXT or EPUB, or whatever...
            return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Story is a") + " " + \
                       # Tho original story format as it was imported, that is
                       ftype + ". " + _("Viewing original not yet implemented") + ".</h4></div>\n")
        
        which = req.http.params.get("type")
        assert(which)
            
        if which == "original" :
            original = self.heromsg + _("Here is the original story. Choose from one of the options in the above navigation bar to begin learning with this story.") + "</div>"
            original += req.db[self.story(req, story["name"]) + ":original"]["value"]
            return self.bootstrap(req, original.encode("utf-8").replace("\n","<br/>"))
        elif which == "pinyin" :
            final = req.db[self.story(req, story["name"]) + ":final"]["0"]
            return self.bootstrap(req, final.encode("utf-8").replace("\n","<br/>"))

    def common_account(self, req, story) :
        out = ""

        username = req.session.value["username"].lower()
        user = req.db.try_get(self.acct(username))

        if not user :
            return self.warn_not_replicated(req)
        
        if req.http.params.get("pack") :
            req.db.compact()
            req.db.cleanup()
            design_docs = ["memorized", "stories", "mergegroups",
                           "tonechanges", "accounts", "splits", "chats" ]

            if not mobile :
                design_docs.append("download")

            for name in design_docs :
                if req.db.doc_exist("_design/" + name) :
                    mdebug("Compacting view " + name)
                    req.db.compact(name)

            # The user requested that the software's database be "cleaned" or compacted to make it more lean and mean. This message appears when the compaction operation has finished.
            out += self.heromsg + "\n<h4>" + _("Database compaction complete for your account") + ".</h4></div>\n"
        elif req.http.params.get("changepassword") :
            if mobile :
                # The next handful of mundane phrases are associated with the creation
                # and management of user accounts in the software program and the relevant
                # errors that can occur while performing operations on a user's account.
                return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Please change your password on the website, first") + ".</h4></div>")
            oldpassword = req.http.params.get("oldpassword")
            newpassword = req.http.params.get("password")
            newpasswordconfirm = req.http.params.get("confirm")

            if len(newpassword) < 8 :
                return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Password must be at least 8 characters! Try again") + ".</h4></div>")
            if newpassword != newpasswordconfirm :
                return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Passwords don't match! Try again") + ".</h4></div>")
            auth_user, reason = self.authenticate(username, oldpassword, req.session.value["address"])
            if not auth_user :
                return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Old passwords don't match! Try again") + ": " + str(reason) + ".</h4></div>")
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

        elif req.http.params.get("resetpassword") :
            if mobile :
                return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Please change your password on the website, first") + ".</h4></div>")

            newpassword = binascii_hexlify(os_urandom(4))

            auth_user, reason = self.authenticate(username, False, req.session.value["address"], from_third_party = {"username" : username})
            if not auth_user :
                return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Could not lookup your account! Try again") + ": " + str(reason) + ".</h4></div>")

            try :
                auth_user['password'] = newpassword
                del self.dbs[username]
                self.verify_db(req, "_users", cookie = req.session.value["cookie"])
                req.db["org.couchdb.user:" + username] = auth_user
                del self.dbs[username]
                self.verify_db(req, req.session.value["database"], newpassword)
            except Exception, e :
                out = ""
                for line in format_exc().splitlines() :
                    out += line + "\n"
                merr(out)
                return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Password change failed") + ": " + str(e) + "</h4></div>")
                
            out += self.heromsg + "\n<h4>" + _("Success!") + " " + _("User") + " " + username + " " + _("password changed") + ".<br/><br/>" + _("Please write (or change) it") + ": <b>" + newpassword + "</b><br/><br/>" + _("You will need it to login to your mobile device") + ".</h4></div>"

        elif req.http.params.get("newaccount") :
            if not self.userdb : 
                # This message appears only on the website when used by administrators to indicate that the server is misconfigured and does not have the right privileges to create new accounts in the system.
                return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Server not configured correctly. Can't make accounts") + ".</h4></div>")

            newusername = req.http.params.get("username").lower()
            newpassword = req.http.params.get("password")
            newpasswordconfirm = req.http.params.get("confirm")
            admin = True if req.http.params.get("isadmin", 'off') == 'on' else False
            email = req.http.params.get("email")
            language = req.http.params.get("language")

            if newusername == "mica_admin" :
                return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Invalid account name! Try again") + ".</h4></div>")

            if len(newpassword) < 8 :
                return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Password must be at least 8 characters! Try again") + ".</h4></div>")
            if newpassword != newpasswordconfirm :
                return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Passwords don't match! Try again") + ".</h4></div>")

            if not req.session.value["isadmin"] :
                return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Non-admin users can't create admin accounts. What are you doing?!") + "</h4></div>")

            if self.userdb.doc_exist("org.couchdb.user:" + newusername) :
                return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Account already exists! Try again") + ".</h4></div>")

            if newusername.count(":") or newusername.count(";") :
                return self.bootstrap(req, self.heromsg + "\n<h4>" + _("We're sorry, but you cannot have colon ':' characters in your account name or email address.") + "</h4></div>")

            self.make_account(req, newusername, newpassword, email, "mica", admin = admin, language = language)

            out += self.heromsg + "\n<h4>" + _("Success! New user was created") + ": " + newusername + ".</h4></div>"
        elif req.http.params.get("deleteaccount") and req.http.params.get("username") :
            if mobile :
                return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Please delete your account on the website and then uninstall the application. Will support mobile in a future version.") + ".</h4></div>")

            username = req.http.params.get("username").lower()

            if not self.userdb : 
                # This message appears only on the website when used by administrators to indicate that the server is misconfigured and does not have the right privileges to create new accounts in the system.
                return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Server not configured correctly. Can't make accounts") + ".</h4></div>")

            if not self.userdb.doc_exist("org.couchdb.user:" + username) :
                return self.bootstrap(req, self.heromsg + "\n<h4>" + _("No such account. Cannot delete it.") + ".</h4></div>")

            auth_user = self.userdb["org.couchdb.user:" + username]


            if req.session.value["username"] != username :
                if not req.session.value["isadmin"] :
                    # This message is for hackers attempting to break into the website. It's meant to be mean on purpose.
                    return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Go away and die.") + "</h4></div>")
                role_length = len(self.userdb["org.couchdb.user:" + username]["roles"])

                if role_length == 0 :
                    return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Admin accounts can't be deleted by other people. The admin must delete their own account.") + "</h4></div>")

            dbname = auth_user["mica_database"]
            mdebug("Confirming database before delete: " + dbname)

            todelete = self.cs[dbname]

            del self.userdb["org.couchdb.user:" + username]
            del self.cs[dbname]

            if req.session.value["username"] != username :
                out += self.heromsg + "\n<h4>" + _("Success! Account was deleted") + ": " + username + "</h4></div>"
            else :
                self.clean_session(req)
                req.skip_show = True
                return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Your account has been permanently deleted.") + "</h4></div>")

        elif req.http.params.get("changelanguage") :
            language = req.http.params.get("language")
            user["language"] = language
            req.db[self.acct(username)] = user
            req.session.value["language"] = language
            req.session.save()
            self.install_local_language(req)
            out += self.heromsg + "\n<h4>" + _("Success! Language changed") + ".</h4></div>"
        elif req.http.params.get("changelearnlanguage") :
            language = req.http.params.get("learnlanguage")
            user["learnlanguage"] = language
            req.session.value["learnlanguage"] = language
            req.session.save()
            req.db[self.acct(username)] = user
            self.install_local_language(req)
            out += self.heromsg + "\n<h4>" + _("Success! Learning Language changed") + ".</h4></div>"
        elif req.http.params.get("changeemail") :
            email = req.http.params.get("email")
            try :
                email_user = self.userdb["org.couchdb.user:" + username]
                email_user['email'] = email 
                self.userdb["org.couchdb.user:" + username] = email_user
            except Exception, e :
                return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Email address change failed") + ": " + str(e) + "</h4></div>")
            user["email"] = email 
            req.db[self.acct(username)] = user
            req.session.save()
            out += self.heromsg + "\n<h4>" + _("Success! Email changed") + ".</h4></div>"
        elif req.http.params.get("setappchars") :
            chars_per_line = int(req.http.params.get("setappchars"))
            if chars_per_line > 1000 or chars_per_line < 5 :
                # This number of characters refers to a limit of the number of words or characters that are allowed to be displayed on a particular line of a page of a story. This allows the user to adapt the viewing mode manually to big screens and small screens.
                return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Number of characters can't be greater than 1000 or less than 5") + ".</h4></div>")
            user["app_chars_per_line"] = chars_per_line
            req.db[self.acct(username)] = user
            req.session.value["app_chars_per_line"] = chars_per_line 
            req.session.save()
            # Same as before, but specifically for a mobile device
            out += self.heromsg + "\n<h4>" + _("Success! Mobile Characters-per-line in a story set to:") + " " + str(chars_per_line) + ".</h4></div>"
        elif req.http.params.get("tofrom") :
            tofrom = req.http.params.get("tofrom")
            remove = int(req.http.params.get("remove"))

            if tofrom not in processor_map :
                # Someone supplied invalid input to the server indicating a dictionary that does not exist. 
                return self.bootstrap(req, self.heromsg + "\n<h4>" + _("No such dictionary. Please try again") + ": " + tofrom + ".</h4></div>")

            if "filters" not in user :
               user["filters"] = {'files' : [], 'stories' : [] }

            if remove == 0 :
                if tofrom not in user["filters"]['files'] :
                    user["filters"]['files'].append(tofrom)
            else :
                if tofrom in user["filters"]['files'] :
                    user["filters"]['files'].remove(tofrom)

            req.session.value["filters"] = user["filters"]

            if mobile :
                req.db.stop_replication()

                if not self.db.replicate(req.session.value["address"], username, req.session.value["password"], req.session.value["database"], params["local_database"], self.get_filter_params(req)) :
                    return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Failed to intiate download of this dictionary. Please try again") + ": " + tofrom + ".</h4></div>")

            req.db[self.acct(username)] = user
            req.session.save()

            if mobile :
                if remove == 0 :
                    out += self.heromsg + "\n<h4>" + _("Success! We will start downloading that dictionary") + ": " + supported[tofrom] + ".</h4></div>"
                else :
                    out += self.heromsg + "\n<h4>" + _("Success! We will no longer download that dictionary") + ": " + supported[tofrom] + ".</h4></div>"
            else :
                if remove == 0 :
                    out += self.heromsg + "\n<h4>" + _("Success! We will start distributing that dictionary to your devices") + ": " + supported[tofrom] + ".</h4></div>"
                else :
                    out += self.heromsg + "\n<h4>" + _("Success! We will no longer distribute that dictionary to your devices") + ": " + supported[tofrom] + ".</h4></div>"

        elif req.http.params.get("setwebchars") :
            chars_per_line = int(req.http.params.get("setwebchars"))
            if chars_per_line > 1000 or chars_per_line < 5:
                return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Number of characters can't be greater than 1000 or less than 5") + ".</h4></div>")
            user["web_chars_per_line"] = chars_per_line
            req.db[self.acct(username)] = user
            req.session.value["web_chars_per_line"] = chars_per_line 
            req.session.save()
            # Same as before, but specifically for a website 
            out += self.heromsg + "\n<h4>" + _("Success! Web Characters-per-line in a story set to:") + " " + str(chars_per_line) + ".</h4></div>"
        elif req.http.params.get("setappzoom") :
            zoom = float(req.http.params.get("setappzoom"))
            if zoom > 3.0 or zoom < 0.5 :
                # The 'zoom-level' has a similar effect to the number of characters per line, except that it controls the whole layout of the application (zoom in or zoom out) and not just individual lines.
                return self.bootstrap(req, self.heromsg + "\n<h4>" + _("App Zoom level must be a decimal no greater than 3.0 and no smaller than 0.5") + "</h4></div>")
            user["default_app_zoom"] = zoom 
            req.db[self.acct(username)] = user
            req.session.value["default_app_zoom"] = zoom
            req.session.save()
            # Same as before, but specifically for an application running on a mobile device
            out += self.heromsg + "\n<h4>" + _("Success! App zoom level set to:") + " " + str(zoom) + ".</h4></div>"
        elif req.http.params.get("setwebzoom") :
            zoom = float(req.http.params.get("setwebzoom"))
            if zoom > 3.0 or zoom < 0.5 :
                # Same as before, but specifically for an application running on the website 
                return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Web Zoom level must be a decimal no greater than 3.0 and no smaller than 0.5") + "</h4></div>")
            user["default_web_zoom"] = zoom 
            req.db[self.acct(username)] = user
            req.session.value["default_web_zoom"] = zoom
            req.session.save()
            # Same as before, but specifically for an application running on the website 
            out += self.heromsg + "\n<h4>" + _("Success! Web zoom level set to:") + " " + str(zoom) + ".</h4></div>"

        out += "<p/><h4><b>" + _("Account") + ": " + username + "</b></h4><br/>"

        if mobile :
            out += "<h4><b>" + _("Dictionaries") + "?</b></h4>"
        else :
            # This allows the user to indicate on the website whether or not their mobile devices should synchronize a particular dictionary to their device.
            out += "<h4><b>" + _("Send Dictionaries to your devices?") + "</b></h4>"
        out += "<h5>(" + _("Offline dictionaries are required for using 'Edit' mode of some character-based languages and for re-translating individual pages in Review mode. Instant translations require internet access, so you can skip these downloads if your stories have already been edited/reviewed and you are mostly using 'Reading' mode. Each dictionary is somewhere between 30 to 50 MB each") + ".)</h5>"

        out += "<table>"
        for pair, readable in supported.iteritems() :
            out += "<tr><td>"
            out += "<form action='/account' method='post' enctype='multipart/form-data'>"
            dname = "dict" + pair.replace("-", "")
            out += "<input type='hidden' name='tofrom' value='" + pair + "'/>\n"

            out += "<button id='" + dname + "' name='downloaddictionary' type='submit' class='btn btn-default btn-primary"

            downloaded = False 

            if "filters" in user and pair in user["filters"]["files"] :
                downloaded = True

            remove = False
            if not downloaded :
                # The next few messages appear on mobile devices and allow the user to control the synchronization status
                # of the story they want to use. For example, if a story (or a dictionary) is on the website,
                # but not yet synchronized with the device, we show a series of messages as the user indicates
                # which ones to download/synchronize and which ones not to.
                out += "'>" + _("Download")
            else :
                all_found = True

                lgp = self.processors[pair]
                for f in lgp.get_dictionaries() :
                    fname = params["scratch"] + f

                    if not os_path.isfile(fname) :
                        all_found = False
                        break

                remove = True
                if all_found :
                    out += "'>" + _("Stop downloading")
                else :
                    #out += " btn-disabled' disabled"
                    out += "'"
                    out += ">" + _("Downloading") + "..."

            out += "</button>"

            if remove :
                out += "<input type='hidden' name='remove' value='1'/>\n"
            else :
                out += "<input type='hidden' name='remove' value='0'/>\n"

            out += "</form>"
            out += "</td><td>"
            out += "&#160;" + _(readable) + "<br/>"
            out += "</td></tr>"
        out += "</table>"

        try :
            # the zoom level or characters-per-line limit
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

        out += "<h4><b>" + _("Learning Language") + "</b>?</h4>"
        out += """
            <form action='/account' method='post' enctype='multipart/form-data'>
            <select name="learnlanguage">
        """
        softlangs = []
        for l, readable in lang.iteritems() :
            locale = l.split("-")[0]
            if locale not in softlangs :
                softlangs.append((locale, readable))

        for l, readable in softlangs :
            out += "<option value='" + l + "'"
            if "learnlanguage" in user and l == user["learnlanguage"] :
                out += "selected"
            out += ">" + _(readable) + "</option>\n"
        out += """
            </select>
            <br/>
            <br/>
        """
        out += "<button name='changelearnlanguage' type='submit' class='btn btn-default btn-primary' value='1'>" + _("Change Learning Language") + "</button></form>"

        out += """
                <a onclick="$('#compactModal').modal({backdrop: 'static', keyboard: false, show: true});;"
                """

        out += " class='btn btn-default btn-primary' href='/account?pack=1'>" + _("Compact databases") + "</a>"

        if username == "demo" :
            return self.bootstrap(req, out)
         
        out += "<p/><h4><b>" + _("Change Password") + "?</b></h4>"
        if not mobile :
            out += run_template(req, PasswordElement)
        else :
            out += _("Please change your password on the website. Will support mobile in a future version.")

        if self.userdb :
            if not mobile and req.session.value["isadmin"] :
                out += "<h4><b>" + _("Accounts") + "</b>:</h4>"
                out += "<table>"
                for result in self.userdb.view('accounts/all') :
                    tmp_doc = result["key"]
                    out += "<tr><td>" + tmp_doc["name"] + "</td><td>&#160;&#160;"
                    out += (tmp_doc["email"] if "email" in tmp_doc else "no email =(") + "</td>"
                    out += "<td>Source: " + (tmp_doc["source"] if "source" in tmp_doc else "mica") + "</td>"
                    out += "<td><a href='/account?deleteaccount=1&username=" + tmp_doc["name"] + "'>Delete</a></td>"
                    out += "</tr>"
                out += "</table>"

        if not mobile :
            out += "<h4><b>" + _("Email Address") + "</b>?</h4>"
            out += """
                <form action='/account' method='post' enctype='multipart/form-data'>
            """
            out += "<input type='text' name='email' value='" + (user["email"] if "email" in user else _("Please Provide")) + "'/>"
            out += "<br/><br/><button name='changeemail' type='submit' class='btn btn-default btn-primary' value='1'>" + _("Change Email") + "</button></form>"
        else :
            out += _("Please change your email address on the website. Will support mobile in a future version.")

        out += "<p/><h4><b>" + _("Delete Account?") + "</b></h4>"
        if not mobile :
            out += run_template(req, DeleteAccountElement)
        else :
            out += _("Please delete your account on the website and then uninstall the application. Will support mobile in a future version.")

        return self.bootstrap(req, out)
                    
    def common_chat(self, req, unused_story) :
        if "jabber_key" not in req.session.value :
            req.session.value["jabber_key"] = binascii_hexlify(os_urandom(4))
            req.session.save()

        if req.http.params.get("history") :
            def by_date(story):
                return int((story["name"].split(";")[2]))

            peer = req.http.params.get("history")
            tzoffset = int(req.http.params.get("tzoffset"))

            if not mobile :
                self.roll_period(req, "years", "decades", peer)
                self.roll_period(req, "months", "years", peer)
                self.roll_period(req, "weeks", "months", peer)
                self.roll_period(req, "days", "weeks", peer)


            out = "<div><div id='chathistoryresult'><div class='msg'>"
            for period_key in ["days", "weeks", "months", "years", "decades"] :
                stories = []

                for result in req.db.view('chats/all', startkey=[req.session.value['username'], period_key, peer], endkey=[req.session.value['username'], period_key, peer, {}]) :
                    stories.append(result["value"])

                if len(stories) :
                    mdebug("Found " + str(len(stories)) + " stories for period " + period_key)

                    stories.sort(key=by_date, reverse=True)
                    added = False
                    for tmp_story in stories :
                        nb_pages = self.nb_pages(req, tmp_story)

                        if not nb_pages :
                            nb_pages = self.nb_pages(req, tmp_story, force = True)
                            if not nb_pages :
                                mdebug("Empty. =(")
                                continue

                        if mobile :
                            if tmp_story["name"] not in req.session.value["filters"]["stories"] :
                                mdebug("Skipping un-downloaded story: " + tmp_story["name"])
                                continue

                        added = True
                        [x, period, howmany, peer] = tmp_story["name"].split(";")
                        out += self.view_page(req, tmp_story["uuid"], tmp_story["name"], tmp_story, "read", "", str(nb_pages - 1), "100", "false", disk = False, tzoffset = tzoffset)
                        break

                    if added :
                        break

            out += "</div></div></div>"
            return self.bootstrap(req, out, now = True)

        req.main_server = params["main_server"]

        if "chats" not in req.session.value :
            req.session.value["chats"] = {"days" : {}, "weeks" : {}, "months" : {}, "years" : {}, "decades" : {}}
            req.session.save()

        story = {
           "target_language" : supported_map[req.session.value["language"]],
           "source_language" : supported_map[req.session.value["learnlanguage"]],
        }

        if self.tofrom(story) not in self.processors :
            return self.bootstrap(req, self.heromsg + "\n<h4>" + _("We're sorry, but chat for this language pair is not supported") + ": " + lang[story["source_language"]] + " " + _("to") + " " + lang[story["target_language"]] + " (" + _("as indicated by your account preferences") + "). " + _("Please choose a different 'Learning Language' in your accout preferences. Thank you."))


        req.gp = self.processors[self.tofrom(story)]
        req.source_language = story["source_language"]
        req.target_language = story["target_language"]
        out = run_template(req, ChatElement)
        return self.bootstrap(req, out)

    def common_storylist(self, req, unused_story) :
        if req.http.params.get("sync") :
            sync = int(req.http.params.get("sync"))
            tmpuuid = req.http.params.get("uuid")
            tmpname = req.db[self.index(req, tmpuuid)]["value"]
            tmpstory = req.db[self.story(req, tmpname)]
            tmpuser = req.db[self.acct(req.session.value["username"])]

            if sync == 1 :
                tmpstory["download"] = True
                if tmpname not in tmpuser["filters"]["stories"] :
                    tmpuser["filters"]["stories"].append(tmpname)
            else :
                tmpstory["download"] = False
                if tmpname in tmpuser["filters"]["stories"] :
                    tmpuser["filters"]["stories"].remove(tmpname)
                
            req.session.value["filters"] = tmpuser["filters"]

            if mobile :
                req.db.stop_replication()
                if not self.db.replicate(req.session.value["address"], req.session.value["username"], req.session.value["password"], req.session.value["database"], params["local_database"], self.get_filter_params(req)) :
                    return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Failed to change synchronization. Please try again") + ": " + tofrom + ".</h4></div>")

            req.db[self.story(req, tmpname)] = tmpstory
            req.db[self.acct(req.session.value["username"])] = tmpuser
            req.session.save()

            #mdebug("Want to perform: user " + str(tmpuser) + " story " + str(tmpstory))
            return self.bootstrap(req, "changed", now = True)

        tzoffset = int(req.http.params.get("tzoffset"))

        storylist = [self.template("storylist")]

        result = repeat(self.makestorylist, args = [req, tzoffset], kwargs = {})
        
        if not result[0] and len(result) > 1 :
            return self.bootstrap(req, result[1])
        
        untrans_count, reading, noreview, untrans, finish, reading_count, chatting = result[1:]
        
        reading.append("</table></div></div></div>\n")
        noreview.append("</table></div></div></div>\n")
        untrans.append("</table></div></div></div>\n")
        finish.append("</table></div></div></div>\n")

        chat_all = [self.template("chatting")]

        for period in [ "week", "month", "year", "decade" ] :
            if len(chatting[period]) :
                chat_all.append("<tr><td>" + _("Recent") + " " + translated_periods[period] + ":</td></tr>")
                chat_all += chatting[period]

        chat_all.append("</table></div></div></div>\n")

        scripts = [""]

        if untrans_count :
            storylist += untrans + reading + chat_all + noreview + finish + ["</div></td></tr></table>"]
            scripts.append("<script>$('#collapseUntranslated').collapse('show');</script>")
        elif reading_count :
            storylist += reading + chat_all + untrans + noreview + finish + ["</div></td></tr></table>"]
            scripts.append("<script>$('#collapseReading').collapse('show');</script>")
        else :
            storylist += noreview + reading + chat_all + untrans + finish + ["</div></td></tr></table>"]
            scripts.append("<script>$('#collapseReviewing').collapse('show');</script>")

        scripts.append("""
                    
                   <script>
                   for(var tidx = 0; tidx < translist.length; tidx++) {
                       trans_start(translist[tidx]);
                   }
                   translist = [];
                   </script>
                  """)

        try :
            finallist = run_template(req, StoryElement, "".join(storylist)) + "".join(scripts)
        except Exception, e:
            merr("Storylist fill failed: " + str(e))

        return self.bootstrap(req, "<div><div id='storylistresult'>" + finallist + "</div></div>", now = True)

    def common_phistory(self, req, story) :
        return self.bootstrap(req, self.heromsg + "\n<div id='historyresult'>" + \
                                   # statistics in review mode are disabled
                                   (self.history(req, story, req.http.params.get("page")) if self.get_list_mode(req) else "<h4>" + _("Review History List Disabled") + ".</h4>") + \
                                   "</div></div>", now = True)

    def common_editslist(self, req, story) :
        return self.bootstrap(req, self.heromsg + "\n<div id='editsresult'>" + \
                                   self.edits(req, story, req.http.params.get("page")) + \
                                   "</div></div>", now = True)

    def baidu_compliance_fix(self, session):
        self.fixed = False

        def _compliance_fix(r):
            if self.fixed :
                return r
            self.fixed = True
            # Facebook returns a content-type of text/plain when sending their
            # x-www-form-urlencoded responses, along with a 200. If not, let's
            # assume we're getting JSON and bail on the fix.
            mdebug("Going to dump response token text: " + r.text)
            token = json_loads(r.text)
            mdebug("Adding bearer to token type") 
            token['token_type'] = 'Bearer'
            r._content = to_unicode(dumps(token)).encode('UTF-8')
            return r

        session.register_compliance_hook('access_token_response', _compliance_fix)
        return session

    def common_oauth(self, req) :
        from_third_party = False
        self.install_local_language(req)
        who = req.action
        creds = params["oauth"][who]
        redirect_uri = params["oauth"]["redirect"] + who 
        service = OAuth2Session(creds["client_id"], redirect_uri=redirect_uri)

        if who == "facebook" :
            service = facebook_compliance_fix(service)

        if who == "baidu" :
            service = self.baidu_compliance_fix(service)

        if not req.http.params.get("code") and not req.http.params.get("finish") :
            if req.http.params.get("error") :
                reason = req.http.params.get("error_reason") if req.http.params.get("error_reason") else "Access Denied."
                desc = req.http.params.get("error_description") if req.http.params.get("error_description") else "Access Denied."
                if reason == "user_denied" :
                    # User denied our request to create their account using social networking. Apologize and move on.
                    req.skip_show = True
                    return self.bootstrap(req, self.heromsg + "<h4>" +  _("We're sorry you feel that way, but we need your authorization to use this service. You're welcome to try again later. Thanks.") + "</h4></div>")
                else :
                    # Social networking service denied our request to authenticate and create an account for some reason. Notify and move on.
                    req.skip_show = True
                    return self.bootstrap(req, self.heromsg + "<h4>" + _("Our service could not create an account from you") + ": " + desc + " (" + str(reason) + ").</h4></div>")
            else :
                # Social networking service experience some unknown error when we tried to authenticate the user before creating an account.
                req.skip_show = True
                return self.bootstrap(req, self.heromsg + "<h4>" + _("There was an unknown error trying to authenticate you before creating an account. Please try again later") + ".</h4></div>")

        code = req.http.params.get("code")

        req.skip_show = True
        if not req.http.params.get("finish") :
            return self.bootstrap(req, "<div id='newaccountresultdestination' style='font-size: large'><img src='" + req.mpath + "/spinner.gif' width='15px'/>&#160;" + _("Signing you in, Please wait") + "...</div><script>finish_new_account('" + code + "', '" + who + "');</script>")


        service.fetch_token(creds["token_url"], client_secret=creds["client_secret"], code = code)

        mdebug("Token fetched successfully: " + str(service.token))

        if who == "baidu" :
            del service.token["token_type"]

        lookup_url = creds["lookup_url"]

        updated = False

        if "force_token" in creds and creds["force_token"] :
            if updated :
                lookup_url += "&"
            else :
                lookup_url += "?"
            lookup_url += "access_token=" + service.token["access_token"]

        r = service.get(lookup_url)
        
        mdebug("MICA returned content is: " + str(r.content))
        values = json_loads(r.content)

        if who == "renren" :
            values = values["response"]

        if creds["verified_key"] :
            assert(creds["verified_key"] in values)

            if not values[creds["verified_key"]] :
                req.skip_show = True
                return self.bootstrap(self.heromsg + "<h4>" + _("You have successfully signed in with the 3rd party, but they cannot confirm that your account has been validated (that you are a real person). Please try again later.") + "</h4></div>")

        if creds["email_key"] and creds["email_key"] not in values :
            authorization_url, state = service.authorization_url(creds["reauthorization_base_url"])
            req.skip_show = True
            out = self.heromsg + "<h4>" + _("We're sorry. You have declined to share your email address, but we need a valid email address in order to create an account for you") + ". <a class='btn btn-primary' href='"
            out += authorization_url
            out += "'>" + _("You're welcome to try again") + "</a>" + "</h4></div>"
            return self.bootstrap(req, out)

        password = binascii_hexlify(os_urandom(4))
        if "locale" not in values :
            language = "en"
        else :
            language = values["locale"].split("-")[0] if values['locale'].count("-") else values["locale"].split("_")[0]

        if creds["email_key"] :
            if isinstance(values[creds["email_key"]], dict) :
                values["email"] = None

                if "preferred" in values[creds["email_key"]] :
                    values["email"] = values[creds["email_key"]]["preferred"]

                if values["email"] is None :
                    for key, email in values[creds["email_key"]] :
                        if email is not None :
                            values["email"] = email 
            else :
                values["email"] = values[creds["email_key"]]

        from_third_party = values
        if creds["email_key"] :
            from_third_party["username"] = values["email"]

        #req.skip_show = True
        #return self.bootstrap(req, "User info fetched: " + str(from_third_party))  

        if not self.userdb.doc_exist("org.couchdb.user:" + values["username"]) :
            if values["email"].count(":") or values["email"].count(";") :
                return self.bootstrap(req, self.heromsg + "<h4>" + _("We're sorry, but you cannot have colon ':' characters in your account name or email address.") + ":&#160;" + _("Original login service") + ":&#160;<b>" + source + "</b>&#160;." + _("Please choose a different service and try again") + "</h4></div>")

            self.make_account(req, values["email"], password, values["email"], who, language = language)
            mdebug("Language: " + language)

            output = ""
            output += "<h4>" + _("Congratulations. Your account is created") + ": " + values["email"] 
            output += "<br/><br/>" + _("We have created a default password to be used with your mobile device(s). Please write it down somewhere. You will need it only if you want to synchronize your mobile devices with the website. If you do not want to use the mobile application, you can ignore it. If you do not want to write it down, you will have to come back to your account preferences and reset it before trying to login to the mobile application. You are welcome to go to your preferences now and change this password.")

            output += "<br/><br/>Save this Password: " + password
            output += "<br/><br/>" + _("If this is your first time here") + ", <a class='btn btn-primary' href='/help'>"
            output += _("please read the tutorial") + "</a>"
            output += "<br/><br/>Happy Learning!</h4>"

            from_third_party["output"] = output
        else :
            from_third_party["redirect"] = "<h3>" + _("Redirecting") + "...</h3><script>window.location.href='/home';</script>" 
            auth_user = self.userdb["org.couchdb.user:" + values["username"]]

            if "source" not in auth_user or ("source" in auth_user and auth_user["source"] != who) :
                req.skip_show = True
                source = "mica" if "source" not in auth_user else auth_user["source"]
                return self.bootstrap(req, self.heromsg + "<h4>" + _("We're sorry, but someone has already created an account with your credentials") + ":&#160;" + _("Original login service") + ":&#160;<b>" + source + "</b>&#160;." + _("Please choose a different service and try again") + "</h4></div>")

        return from_third_party

    def common_connect(self, req, from_third_party) :
        password = False
        username = False

        if from_third_party :
            username = from_third_party["email"].lower()
            req.session.value["from_third_party"] = True 
        else :
            req.session.value["from_third_party"] = False 
            if params["mobileinternet"] and params["mobileinternet"].connected() == "none" :
                # Internet access refers to the wifi mode or 3G mode of the mobile device. We cannot connect to the website without it...
                req.skip_show = True
                return self.bootstrap(req, self.heromsg + "<h4>" + _("To login for the first time and begin synchronization with the website, you must activate internet access.") + "</h4></div>")
            username = req.http.params.get('username').lower()
            password = req.http.params.get('password')

        if req.http.params.get("address") :
            address = req.http.params.get('address')
        elif "adddress" in req.session.value and req.session.value["address"] != None :
            address = req.session.value["address"]
        else :
            address = self.credentials()

        req.session.value["username"] = username
        req.session.value["address"] = address

        # Make a temporary jabber secret that is safe to store in a session
        # so the BOSH javascript client can authenticate
        if not mobile :
            if "temp_jabber_pw" in params :
                req.session.value["temp_jabber_pw"] = params["temp_jabber_pw"]
            else :
                req.session.value["temp_jabber_pw"] = binascii_hexlify(os_urandom(4))

        if mobile :
            req.session.value["password"] = password

        req.session.save()

        mdebug("authenticating...")

        auth_user, reason = self.authenticate(username, password, address, from_third_party = from_third_party)

        if not auth_user :
            # User provided the wrong username or password. But do not translate as 'username' or 'password' because that is a security risk that reveals to brute-force attackers whether or not an account actually exists.
            req.skip_show = True
            return self.bootstrap(req, self.heromsg + "<h4>" + str(reason) + "</h4></div>")

        req.session.value["isadmin"] = True if len(auth_user["roles"]) == 0 else False
        req.session.value["database"] = auth_user["mica_database"] 
        req.session.save()

        mdebug("verifying...")
        self.verify_db(req, auth_user["mica_database"], password = password, from_third_party = from_third_party)

        if not mobile :
            if "temp_jabber_pw" not in params :
                auth_user["temp_jabber_pw"] = req.session.value["temp_jabber_pw"]
                self.userdb["org.couchdb.user:" + username] = auth_user

        if mobile :
            if req.db.doc_exist("MICA:appuser") :
               mdebug("There is an existing user. Verifying it is the same one.")
               appuser = req.db["MICA:appuser"]
               if appuser["username"] != username :
                    # Beginning of a message 
                    req.skip_show = True
                    return self.bootstrap(req, self.heromsg + "<h4>" + _("We're sorry. The MICA Reader database on this device already belongs to the user") + " " + \
                        # next part of the same message 
                        appuser["username"] + " " + _("and is configured to stay in synchronization with the server") + ". " + \
                         # next part of the same message 
                        _("If you want to change users, you will need to clear this application's data or reinstall it and re-synchronize the app with") + " " + \
                         # end of the message 
                        _("a new account. This requirement is because MICA databases can become large over time, so we want you to be aware of that. Thanks.") + "</h4></div>")
            else :
               mdebug("First time user. Reserving this device: " + username)
               appuser = {"username" : username}
               req.db["MICA:appuser"] = appuser
                   
            tmpuser = req.db.try_get(self.acct(username))
            if tmpuser and "filters" in tmpuser :
                mdebug("Found old filters.")
                req.session.value["filters"] = tmpuser["filters"]
                req.session.save()
            if not req.db.replicate(address, username, password, req.session.value["database"], params["local_database"], self.get_filter_params(req)) :
                # This 'synchronization' refers to the ability of the story to keep the user's learning progress and interactive history and stories and all other data in sync across both the website and all devices that the user owns.
                req.skip_show = True
                return self.bootstrap(req, self.heromsg + "<h4>" + _("Although you have authenticated successfully, we could not start synchronization successfully. Please try again.") + "</h4></div>")

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

        user = req.db.try_get(self.acct(username))
        if not user :
            return self.warn_not_replicated(req)

        if not mobile :
            jobs = req.db.try_get("MICA:jobs")
            if not jobs :
                req.db["MICA:jobs"] = {"list" : {}}
            
        if "language" not in user :
            user["language"] = get_global_language()

        if "learnlanguage" not in user :
            user["learnlanguage"] = "en"

        if "source" not in user :
            user["source"] = "mica"

        if "date" not in user :
            user["date"] = timest()

        if "story_format" not in user :
            mwarn("Story format is missing. Upgrading design document for story upgrades.")
            self.view_check(req, "stories", recreate = True)
            user["story_format"] = story_format

        if "app_chars_per_line" not in user :
            user["app_chars_per_line"] = 70
        if "web_chars_per_line" not in user :
            user["web_chars_per_line"] = 70
        if "default_app_zoom" not in user :
            user["default_app_zoom"] = 1.15
        if "default_web_zoom" not in user :
            user["default_web_zoom"] = 1.0

        if "filters" not in user :
           user["filters"] = {'files' : [], 'stories' : [] }

        req.session.value["app_chars_per_line"] = user["app_chars_per_line"]
        req.session.value["web_chars_per_line"] = user["web_chars_per_line"]
        req.session.value["default_app_zoom"] = user["default_app_zoom"]
        req.session.value["default_web_zoom"] = user["default_web_zoom"]
        req.session.value["filters"] = user["filters"]

        if req.session.value["username"] == "demo" :
            req.session.value["language"] = get_global_language()
        else :
            req.session.value["language"] = user["language"]

        req.session.value["learnlanguage"] = user["learnlanguage"]

        req.db[self.acct(username)] = user
        req.session.save()

        if not mobile :
            try :
                if req.db.doc_exist("MICA:filelisting") :
                    del req.db["MICA:filelisting"]

                for name, lgp in self.processors.iteritems() :
                    for f in lgp.get_dictionaries() :
                        if not req.db.doc_exist("MICA:filelisting_" + f) :
                            req.db["MICA:filelisting_" + f] = {"foo" : "bar"} 

                mdebug("Checking if files exist............") 
                for name, lgp in self.processors.iteritems() :
                    for f in lgp.get_dictionaries() :
                        listing = req.db["MICA:filelisting_" + f]
                        fname = params["scratch"] + f 

                        if '_attachments' not in listing or f not in listing['_attachments'] :
                            if os_path.isfile(fname) :
                                minfo("Opening dict file: " + f)
                                fh = open(fname, 'r')
                                minfo("Uploading " + f + " to file listing...")
                                req.db.put_attachment("MICA:filelisting_", f, fh, new_doc = listing)
                                fh.close()
                                minfo("Uploaded.")
                            else :
                                minfo("Cannot Upload " + f + ", not generated yet.")
                        else :
                            mdebug("File " + f + " already exists.")
                            handle = lgp.parse_page_start()
                            #lgp.test_dictionaries(handle, preload = True)
                            lgp.test_dictionaries(handle)
                            lgp.parse_page_stop(handle)

            except TypeError, e :
                out = "Account documents don't exist yet. Probably they are being replicated: " + str(e)
                for line in format_exc().splitlines() :
                    out += line + "\n"
                mwarn(out)
            except couch_adapter.ResourceNotFound, e :
                mwarn("Account document @ MICA:filelisting not found: " + str(e))
            except Exception, e :
                out = "Database not available yet: " + str(e)
                for line in format_exc().splitlines() :
                    out += line + "\n"
                mwarn(out)

        return False

    def common_logged_in_check(self, req) :
        username = req.session.value['username'].lower()

        if "app_chars_per_line" not in req.session.value :
            user = req.db[self.acct(username)]
            if "filters" not in user :
                user["filters"] = {'files' : [], 'stories' : [] }
                req.db[self.acct(username)] = user
                user = req.db[self.acct(username)]

            if user :
                req.session.value["app_chars_per_line"] = user["app_chars_per_line"]
                req.session.value["web_chars_per_line"] = user["web_chars_per_line"]
                req.session.value["default_app_zoom"] = user["default_app_zoom"]
                req.session.value["default_web_zoom"] = user["default_web_zoom"]
                req.session.value["filters"] = user["filters"]
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

            tmpjobs = req.db.try_get("MICA:jobs")

            if tmpjobs and len(tmpjobs["list"]) > 0 :
                mdebug("Resettings jobs for user.")
                tmpjobs["list"] = {} 
                req.db["MICA:jobs"] = tmpjobs 

            self.first_request[username] = True 

    def common_bulkreview(self, req, name) :
        count = int(req.http.params.get("count"))

        mdebug("Going to perform reviews for " + str(count) + " words.")

        for idx in range(0, count) :
            nb_unit = int(req.http.params.get("nbunit" + str(idx)))
            mindex = int(req.http.params.get("index" + str(idx)))
            trans_id = int(req.http.params.get("transid" + str(idx)))
            page = req.http.params.get("page" + str(idx))
            
            mdebug("Review word: " + str(idx) + " index: " + str(mindex) + " unit " + str(nb_unit) + " id " + str(trans_id))
            self.multiple_select(req, False, nb_unit, mindex, trans_id, page, name)

    def common_oprequest(self, req, story) :
        oprequest = req.http.params.get("oprequest");
        edits = json_loads(oprequest) 
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
            except AttributeError, e :
                return self.warn_not_replicated(req)
            
            if not result[0] and len(result) > 1 :
                return self.bootstrap(req, result[1])
            
            ret = result[1:]
            success = ret[0]
            offset = ret[1]
            
            if not success :
                # This occurs in Edit mode when a merge/split request failed.
                return self.bootstrap(req, self.heromsg + "\n" + _("Invalid Operation") + ": " + str(edit) + "</div>")

        return False

    def common_rest(self, req, from_third_party) :
        if from_third_party and "output" in from_third_party :
            return self.bootstrap(req, "<div id='newaccountresult'>" + from_third_party["output"] + "<br/><a href='/home' class='btn btn-default btn-primary'>" + _("Start learning!") + "</a></div>", now = True)
        elif from_third_party and "redirect" in from_third_party :
            return self.bootstrap(req, from_third_party["redirect"], now = True)
        else :
            # This occurs when you come back to the webpage, and were previously reading a story, but need to indicate in which mode to read the story (of three modes).
            out = _("Read, Review, or Edit, my friend?") + "<br/><br/>"
            out += _("If this is your first time here") + ", <a class='btn btn-primary' href='/help'>"
            out += _("please read the tutorial") + "</a>"
        return self.bootstrap(req, out)


    def get_list_mode(self, req) :
        list_mode = True

        if "list_mode" in req.session.value :
            list_mode = req.session.value["list_mode"]
        else :
            req.session.value["list_mode"] = list_mode 
            req.session.save()

        return list_mode

    def common(self, req) :
        global times
        try :
            if req.action in ["disconnect", "privacy", "help", "switchlang", "online", "instant" ] :
                func = getattr(self, "common_" + req.action)
                return func(req)

            if req.action == "auth" and not mobile :
                return self.common_auth(req)

            from_third_party = False

            if not mobile and req.action in params["oauth"].keys() :
                oauth_result = self.common_oauth(req)
                if isinstance(oauth_result, str) or isinstance(oauth_result, unicode) :
                    return oauth_result 

                from_third_party = oauth_result

            if req.http.params.get("connect") or from_third_party != False :
                connect_result = self.common_connect(req, from_third_party)
                if connect_result :
                    return connect_result
                
            self.install_local_language(req)

            if 'connected' not in req.session.value or req.session.value['connected'] != True :
                return self.bootstrap(req, run_template(req, FrontPageElement))
                
            self.common_logged_in_check(req)

            if req.action == "chat" and req.http.params.get("ime") :
                return self.common_chat_ime(req)

            if req.http.params.get("uploadfile") :
                return self.common_uploadfile(req)

            if req.http.params.get("uploadtext") :
                return self.common_uploadtext(req)

            start_page = "0"
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
                return self.new_job(req, self.deletestory, False, _("Deleting Story From Database"), name, False, args = [req, uuid, name])

            if uuid :
                if not req.db.doc_exist(self.index(req, uuid)) :
                    self.clear_story(req)
                    # The user tried to access a story that does not exist (probably because they deleted it), but because they navigated to an old webpage address, they provide the software with a UUID (identifier) of a non-existent story by accident due to the browser probably having cached the address in the browser's history. 
                    return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Invalid story uuid") + ": " + uuid + "</h4></div>")

            for param in ["tstatus", "finished", "reviewed", "translate"] :
                if req.http.params.get(param) :
                    return getattr(self, "common_" + param)(req, story)

            if req.http.params.get("forget") :
                # Resetting means that we are dropping the translate contents of the original story. We are
                # not deleteing the story itself, nor the user's memorization data, only the translated
                # version of the story itself.
                return self.new_job(req, self.forgetstory, False, _("Resetting Story In Database"), name, False, args = [req, uuid, name])

            if req.http.params.get("switchmode") :
                req.session.value["view_mode"] = req.http.params.get("switchmode")
                req.session.save()
                # The user can switch between multiple ways to view a story, by showing just the text, or the text + the original image of the page side-by-side, or by just showing the original image of the page. This mode is not the same as the top navigation bar modes. But just say mode - it's simpler.
                return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Mode changed") + ".</h4></div>", now = True)

            if req.http.params.get("meaningmode") :
                req.session.value["meaning_mode"] = req.http.params.get("meaningmode")
                req.session.save()
                return self.bootstrap(req, self.heromsg + "\n<h4>" + _("Mode changed") + ".</h4></div>", now = True)

            if req.http.params.get("switchlist") :
                req.session.value["list_mode"] = True if int(req.http.params.get("switchlist")) == 1 else False
                req.session.save()
                # This mode is also different: It indicates that statistics shown in each high-level mode (Review, Edit, or Read) will not be shown.
                return self.bootstrap(req, self.heromsg + "\n<h4>" + _("List statistics mode changed") + ".</h4></div>", now = True)

            # We want the job list to appear before using any story-related functions
            # User must wait.
            jobs = req.db.try_get("MICA:jobs")

            if jobs and len(jobs["list"]) > 0 :
                return self.common_jobs(req, jobs)

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
                    tmp_story = req.db.try_get(self.story(req, name))
                    if not tmp_story :
                        self.clear_story(req)
                        mwarn("Could not lookup: " + self.story(req, name))
                        return self.warn_not_replicated(req)
                        
                if "current_page" in tmp_story :
                    start_page = tmp_story["current_page"]
                    mdebug("Loading start page: " + str(start_page))
                else :
                    self.set_page(req, tmp_story, start_page)
                
            for param in ["multiple_select", "phistory", "editslist", "memorizednostory", "memorized", "storyupgrade", "memolist" ] :
                if req.http.params.get(param) :
                    return getattr(self, "common_" + param)(req, story)

            if req.http.params.get("oprequest") :
                oprequest_result = self.common_oprequest(req, story)
                if oprequest_result :
                    return oprequest_result
 
            if req.http.params.get("retranslate") :
                page = req.http.params.get("page")
                try :
                    self.parse(req, story, page = page)
                except OSError, e :
                    return self.warn_not_replicated(req)
                
            if req.http.params.get("bulkreview") :
                self.common_bulkreview(req, name)

            if req.action in ["home", "read", "edit" ] :
                return self.common_view(req, uuid, from_third_party, start_page)

            if req.action in ["stories", "storylist", "account", "chat"] :
                func = getattr(self, "common_" + req.action)
                return func(req, story)

            return self.common_rest(req, from_third_party)

        except exc.HTTPTemporaryRedirect, e :
            raise e
        except couch_adapter.ResourceNotFound, e :
            return self.warn_not_replicated(req)

        except Exception, msg:
            mdebug(_("Exception") + ": " + str(msg))
            out = _("Exception") + ":\n" 
            resp = "<h4>" + _("Exception") + ":</h4>"
            for line in format_exc().splitlines() :
                resp += "<br>" + line
                out += line + "\n"
            merr(out)

            try :
                if isinstance(resp, str) :
                    resp = resp.decode("utf-8")

                resp += "<br/><h2>" + _("Please report the above exception to the author. Thank you") + ".</h2>"
                if "connected" in req.session.value and req.session.value["connected"] :
                    mwarn("Boo other, logging out user now.")
                    req.session.value["connected"] = False
                    req.session.save()
                req.skip_show = True
                return self.bootstrap(req, self.heromsg + "\n<h4 id='gerror'>" + _("Error: Something bad happened") + ": " + str(msg) + "</h4>" \
                                            + resp + "</div>")
            except Exception, e :
                merr("OTHER MICA ********Exception:")
                for line in format_exc().splitlines() :
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

        if os_path.isfile(sfn) :
            mdebug("Loading existing session file: " + sfn)
            fh = open(sfn, 'r')
            sc = fh.read().strip()
            fh.close()
            if sc != "" :
                start = json_loads(sc)
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
        fh.write(json_dumps(self.value))
        fh.close()
        pass

sessions = set()

def expired(uid):
   sfn = params["session_dir"] + uid + ".session"
   mdebug("Session " + uid + " has expired.")
   sessions.remove(uid)
   mdebug("Removing session file.")
   os_remove(sfn)
        
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
        address = req.dest.split(":", 1)[0]
        tossl = "https://" + address + ":" + str(params["sslport"]) + "/" + req.path 
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
    parser.add_option("-e", "--scratch", dest = "scratch", default = False, help = "Location of scratch directory for replicated attachments.")
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
               "scratch" : options.scratch,
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

    sys_settrace(None)

    if not mobile :
        prelang = "en"
        try :
            mdebug("Locale is: " + setlocale(LC_ALL, '')) # use user's preferred locale
            # take first two characters of country code
            prelang = getlocale()[0][0:2]
        except Exception, e :
            mdebug("Could not find locale. Defaulting to english.")

        pre_init_localization(prelang)

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
        params["session_dir"] = params["scratch"] + "mica_session/"

    mdebug("Session dir: " + params["session_dir"])

    sslport = int(params["sslport"])
    if sslport != -1 and (not params["cert"] or not params["privkey"]) :
        merr("Need locations of SSL certificate and private key (options -C and -K). You can generate self-signed ones if you want, see the README.")
        exit(1)

    if not params["scratch"] :
        merr("You must provide the path to a read/write folder where replicated dictionary databases can be placed (particularly on a mobile device.)")
        exit(1)

    if "serialize_couch_on_mobile" not in params :
        params["serialize_couch_on_mobile"] = False

    if not params["keepsession"] :
        if os_path.isdir(params["session_dir"]) :
            mdebug("Destroying all session files")
            try :
                shutil_rmtree(params["session_dir"])
            except Exception, e :
                merr("Failed to remove tree: " + str(e))

    if not os_path.isdir(params["session_dir"]) :
        mdebug("Making new session folder.")
        os_makedirs(params["session_dir"])

    if not mobile :
        if os_path.isdir("/tmp/mica_uploads") :
            mdebug("Deleting old uploaded files.")
            shutil_rmtree("/tmp/mica_uploads")
        os_makedirs("/tmp/mica_uploads")

    mdebug("Registering session adapter.")
    registerAdapter(CDict, Session, IDict)

    mdebug("Initializing logging.")
    mica_init_logging(params["log"], duplicate = params["duplicate_logger"])

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

        params["q"] = Queue_Queue()

        if not mobile :
            if int(params["sslport"]) == -1 :
                if int(params["port"]) != 80:
                    params["oauth"]["redirect"] += ":" + str(params["port"])
            else :
                if int(params["sslport"]) != 443:
                    params["oauth"]["redirect"] += ":" + str(params["sslport"])

            params["oauth"]["redirect"] += "/"

        mica = MICA(db_adapter)

        mverbose("INIT Testing dictionary thread")
        ct = Thread(target=mica.test_dicts)
        ct.daemon = True
        ct.start()

        reactor._initThreadPool()
        site = Site(GUIDispatcher(mica))
        site.sessionFactory = MicaSession
        nonsslsite = Site(NONSSLDispatcher())
        nonsslsite.sessionFactory = MicaSession

        if sslport != -1 :
            from twisted.internet import ssl
            from OpenSSL import SSL

            class ChainedOpenSSLContextFactory(ssl.DefaultOpenSSLContextFactory):
                def __init__(self, privateKeyFileName, certificateChainFileName, sslmethod=SSL.TLSv1_METHOD):
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
                    ctx.set_cipher_list('ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+3DES:!aNULL:!MD5:!DSS')
                    self._context = ctx

            reactor.listenTCP(int(params["port"]), nonsslsite, interface = params["host"])
            reactor.listenSSL(sslport, site, ChainedOpenSSLContextFactory(privateKeyFileName=params["privkey"], certificateChainFileName=params["cert"], sslmethod = SSL.TLSv1_METHOD), interface = params["host"])
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

        minfo("Setting up serialization queues and coroutine.")
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
                except Queue_Empty :
                    pass
            try :
                co.send((req, rq))
            except StopIteration :
                params["q"].task_done()
                continue

            params["q"].task_done()

        rt.join()

    except Exception, e :
        merr("Startup exception: " + str(e))
        for line in format_exc().splitlines() :
            merr(line)

def second_splash() :
    fh = open(cwd + "serve/splash_template.html", 'r')
    output = fh.read()
    fh.close()

    fh = open(cwd + "serve/icon.png", 'r')
    contents = fh.read()
    encoded1 = base64_b64encode(contents)
    fh.close()

    output += "<img src='data:image/jpeg;base64," + str(encoded1) + "' width='100%'/>"
    output += """
</div>
<div class="inner2">
"""
    output += "<p><p><p>"
    fh = open(cwd + "serve/spinner.gif", 'r')
    contents = fh.read() 
    encoded2 = base64_b64encode(contents)
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

