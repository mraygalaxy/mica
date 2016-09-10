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
from traceback import format_exc, print_stack
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
from string import ascii_lowercase as string_ascii_lowercase, ascii_uppercase as string_ascii_uppercase
from binascii import hexlify as binascii_hexlify
from sys import settrace as sys_settrace
from pyratemp import TemplateSyntaxError

import couch_adapter
import processors
from processors import *
from common import *
from serializable import *
from translator import *
from templates import *

uploads_enabled = True

if not mobile :
    from crypticle import *
    from oauthlib.common import to_unicode
    from oauthlib.oauth2.rfc6749.errors import MissingTokenError, InvalidGrantError
    from requests_oauthlib import OAuth2Session
    from requests_oauthlib.compliance_fixes import facebook_compliance_fix
    from requests.exceptions import ConnectionError as requests_ConnectionError
    try :
        import PythonMagick
    except ImportError, e :
        # TODO: not using this boolean anywhere yet....
        uploads_enabled = False
        mdebug("Cannot find PythonMagick: uploads will be disabled on this server.")

mverbose("Initial imports complete")

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
from twisted.internet.error import AlreadyCalled

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

mverbose("Imports complete.")

pdf_punct = ",卜「,\,,\\,,【,\],\[,>,<,】,〈,@,；,&,*,\|,/,-,_,—,,,，,.,。,?,？,:,：,\:,\：,：,\：,\、,\“,\”,~,`,\",\',…,！,!,（,\(,）,\),口,」,了,丫,㊀,。,门,X,卩,乂,一,丁,田,口,匕,《,》,化,*,厂,主,竹,-,人,八,七,，,、,闩,加,。,』,〔,飞,『,才,廿,来,兀,〜,\.,已,I,幺,去,足,上,円,于,丄,又,…,〉".decode("utf-8")

for letter in (string_ascii_lowercase + string_ascii_uppercase) :
    pdf_punct += letter.decode("utf-8")

pdf_expr = r"([" + pdf_punct + "][" + pdf_punct + "]|[\x00-\x7F][\x00-\x7F]|[\x00-\x7F][" + pdf_punct + "]|[" + pdf_punct + "][\x00-\x7F])"

mverbose("Punctuation complete.")

period_mapping = {"days" : "week", "weeks" : "month", "months" : "year", "years" : "decade", "decades" : "decade"}
period_story_mapping = {"week" : "%a", "month" : "%m/%d", "year" : "%b", "decade" : "%Y"}
period_view_mapping = {"days" : "%a %I:%M:%S %p", "weeks" : "%m/%d %I:%M:%S %p", "months" : "%m/%d %I:%M:%S %p", "years" : "%m/%d %I:%M:%S %p", "decades" : "%m/%d/%y %I:%M:%S %p"}
translated_periods = { "days" : _("days"), "day" : _("day"), "weeks" : _("weeks"),
                "week" : _("week"), "months" : _("months"), "month" : _("month"),
                "years" : _("year"), "year" : _("years"), "decade" : _("decades") }

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

mverbose("Setting up prefixes.")
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
    def __init__(self, environ):
        self.pid = "none"
        self.http = Request(environ)
        self.not_replicated = False
        self.human = True if int(self.http.params.get("human", "1")) else False
        self.messages = ""
        self.action = self.http.path[1:] if len(self.http.path) > 0 else None
        self.environ = environ
        minfo("Request: " + self.http.url + " action: " + self.action)
        self.api = False
        if self.action is None or self.action == "":
            self.action = "index"

        if self.action == "api" :
            operation = self.http.params.get("alien", False)
            if not operation :
                mwarn("Parameters initialization bad request")
                raise exc.HTTPBadRequest("init: you did a bad thing")
            self.api = True
            self.action = operation

        self.unparsed_uri = self.http.url
        self.uri = self.http.path
        self.active = None

        if self.action == "index" :
            self.mpath = self.uri + relative_prefix_suffix
            self.bootstrappath = self.uri + relative_prefix_suffix + "/bootstrap"
        else :
            self.mpath = self.uri + "/.." + relative_prefix
            self.bootstrappath = self.uri + "/.." + relative_prefix + "/bootstrap"

class MICA(object):
    def __init__(self, db_adapter):
        self.serial = Serializable(params["serialize_couch_on_mobile"])
        self.general_processor = Processor(self, params)
        self.translation_client = Translator(params["trans_id"], params["trans_secret"], params["trans_scope"], params["trans_access_token_url"], test = params["test"])
        self.mutex = Lock()
        self.jobsmutex = Lock()
        self.transmutex = Lock()
        self.imemutex = Lock()
        self.rollmutex = Lock()
        self.pid = "none"
        self.dbs = {}
        self.userdb = False
        self.db_adapter = db_adapter
        if not mobile :
            self.jabber_crypt = Crypticle(params["jabber_auth"])

        if mobile :
            self.cs = self.db_adapter(params["couch"])
        else :
            if params["admin_user"] and params["admin_pass"] :
                self.cs = self.db_adapter(couch_adapter.credentials(params), params["admin_user"], params["admin_pass"], refresh = True)
                self.userdb = self.cs["_users"]

        self.first_request = {}

        self.views_ready = {}
        self.view_runs = [ #name , #startend key or regular keys
                ('accounts/all', True),
                ('memorized2/allcount', True),
                ('chats/all', True),
                ('stories/original', True),
                ('stories/pages', True),
                ('stories/allpages', True),
                ('stories/all', True),
                ('stories/translating', True),
                ('stories/upgrading', True),
                ('stories/alloriginal', True),
                ('memorized2/all', False),
                ('tonechanges/all', False),
                ('mergegroups/all', False),
                ('splits/all', False),
               ]

        self.processors = {}

        for tofrom, readable in processor_map.iteritems() :
            if processor_map[tofrom] :
                self.processors[tofrom] = getattr(processors, processor_map[tofrom])(self, params)
        try :
            mverbose("Checking database access")
            if mobile :
                self.db = self.cs[params["local_database"]]
                self.sessiondb = self.cs["sessiondb"]
                self.filedb = self.cs["files"]
            else :
                if self.userdb :
                    self.db = self.userdb
                    self.view_check("mica_admin", "accounts")

                    if "mica_admin" not in self.cs :
                        self.make_account(self, "mica_admin", "password", "owner@example.com", "mica", admin = True, dbname = "mica_admin")
                    if "file_admin" not in self.cs :
                        self.make_account(self, "files", "password", "owner@example.com", "mica", admin = False, dbname = "files", extra_roles = ["nobody"])

                    self.verify_db(False, "mica_admin", username = "mica_admin")
                    self.verify_db(False, "files", username = "files")
                    self.sessiondb = self.dbs["mica_admin"]
                    self.filedb = self.dbs["files"]
                else :
                    mwarn("Admin credentials ommitted. Skipping administration setup.")

            if not mobile :
                self.view_check("mica_admin", "conflicts")
                self.view_check("files", "readonly")
                self.view_check("files", "download")
                self.view_check("mica_admin", "sessions")

            if not mobile :
                for name, lgp in self.processors.iteritems() :
                    for f in lgp.get_dictionaries() :
                        if not self.filedb.doc_exist("MICA:filelisting_" + f) :
                            self.filedb["MICA:filelisting_" + f] = {"foo" : "bar"}

                mdebug("Checking if files exist............")
                for name, lgp in self.processors.iteritems() :
                    for f in lgp.get_dictionaries() :
                        listing = self.filedb["MICA:filelisting_" + f]
                        fname = params["scratch"] + f

                        if '_attachments' not in listing or f not in listing['_attachments'] or not self.size_check(f) :
                            if os_path.isfile(fname) :
                                minfo("Opening dict file: " + f)
                                fh = open(fname, 'r')
                                minfo("Uploading " + f + " to file listing...")
                                self.filedb.put_attachment("MICA:filelisting_", f, fh, new_doc = listing)
                                fh.close()
                                minfo("Uploaded.")
                            else :
                                minfo("Cannot Upload " + f + ", not generated yet.")
                        else :
                            mdebug("File " + f + " already exists.")
                            lgp.test_dictionaries(retest = True)

            if not params["keepsession"] :
                current_session_time = int(timest())
                while True :
                    session_delete = []

                    for result in self.sessiondb.view('sessions/all') :
                        sid = result["key"][0]

                        if sid == "debug" :
                            continue

                        session = result["value"]

                        last_refresh = 0

                        if "last_refresh" in session :
                            last_refresh = int(float(session["last_refresh"]))

                        session_diff = (current_session_time - last_refresh)
                        if "last_refresh" not in session or session_diff >= params["timeout"] :
                            mdebug("SESSION EXPIRED: " + str(sid) + " last refresh: " + str(last_refresh) + " diff: " + str(session_diff) + " > " + str(params["timeout"]))
                            session_delete.append(sid)

                    if len(session_delete) > 0 :
                        for sid in session_delete :
                            del self.sessiondb[self.session(str(sid))]
                            mdebug("Deleted session: " + str(sid))

                        session_delete = []
                        continue

                    break


        except TypeError, e :
            out = "Account documents don't exist yet. Probably they are being replicated: " + str(e)
            for line in format_exc().splitlines() :
                mwarn(line)
        except couch_adapter.ResourceNotFound, e :
            mwarn("Account document @ " + self.acct('mica_admin') + " not found: " + str(e))
        except Exception, e :
            for line in format_exc().splitlines() :
                merr(line)
            mwarn("Database not available yet: " + str(e))

        if mobile and params["serialize_couch_on_mobile"] :
            mdebug("Launching runloop timer")
            rt = Thread(target=self.runloop)
            rt.daemon = True
            rt.start()

        if not mobile :
            mverbose("Starting view runner thread")
            vt = Thread(target=self.view_runner_sched)
            vt.daemon = True
            vt.start()

    def tofrom(self, story) :
        return story["source_language"] + "," + story["target_language"]

    def authenticate(self, username, password, auth_url) :
        mdebug("Authenticating to: " + str(auth_url))

        username = username.lower()
        lookup_username = username

        if not password :
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

    def prime_db(self, req, specific_views = False) :
        username = req.session.value["username"].lower()
        self.new_job(req, self.view_runner, False, _("Priming database for you. Please wait."), username, True, args = [username, self.dbs[username]], kwargs = dict(specific_views = specific_views))

    def verify_db(self, req, dbname, cookie = False, password = False, username = False, prime = True) :
        if not username :
            username = req.session.value["username"].lower()

        if username not in self.dbs or not self.dbs[username] :
            mdebug("Database not set. Requesting object.")
            if mobile :
                mdebug("Setting mobile db to prexisting object.")
                self.dbs[username] = self.db
            else :
                address = req.session.value["address"] if (req and "address" in req.session.value) else couch_adapter.credentials(params)
                # In the past, we were interacting with user databases using their
                # own credentials, but due to CouchDB timeouts, we need a reliable
                # way to refresh the cookie without setting our own timeout and
                # without storing user passwords in memory. At the most, they
                # should remain salted and unrecoverable in couchdb.
                # Thus, we depend on the admin password to perform all those
                # interactions, but javascript (via chat) still depeneds on
                # directly communicating with couchdb. We are already doing it
                # this way for oauth-based databases, so it's not a big deal.
                cs = self.db_adapter(address, params["admin_user"], params["admin_pass"], cookie, refresh = True)
                if password :
                    req.session.value["cookie"] = cs.get_cookie(address, username, password)
                    req.session.save()
                self.dbs[username] = cs[dbname]

            self.views_ready[username] = 0

            mdebug("Installing view counter.")
            if username not in self.views_ready :
                self.views_ready[username] = 0

        if req :
            req.db = self.dbs[username]
            #if prime :
            #    self.prime_db(req)
            #    sleep(1)

        if self.dbs[username].doc_exist(self.acct(username)) :
            user = self.dbs[username][self.acct(username)]

    def session(self, sid) :
        return "MICA:sessions:" + sid

    def acct(self, name) :
        return "MICA:accounts:" + name

    def key_common(self, username) :
        return "MICA:" + username

    def story(self, req, key) :
        return self.key_common(req.session.value['username']) + ":stories:" + key

    # How many days since 1970 instead of seconds
    def current_day(self) :
        return (int(timest()) / (params["seconds_in_day"]))

    def current_period(self, period_key, current_day = False):
        return int(current_day if current_day else self.current_day()) / params["counts"][period_key]

    def chat_name(self, period, index, peer, current_day, extra = "") :
        return "chat;" + period + ";" + str(index) + ";" + peer + extra

    def chat(self, req, period, index, peer, current_day, extra = "") :
        return self.story(req, self.chat_name(period, index, peer, current_day, extra))

    def chat_period_name(self, period_key, peer, current_day, extra = "") :
        return self.chat_name(period_key, self.current_period(period_key, current_day), peer, extra)

    def chat_period(self, req, period_key, peer, current_day, extra = "") :
        return self.chat(req, period_key, self.current_period(period_key, current_day), peer, extra)

    def index(self, req, key) :
        return self.key_common(req.session.value['username']) + ":story_index:" + key

    def merge(self, req, key) :
        return self.key_common(req.session.value['username']) + ":mergegroups:" + key

    def splits(self, req, key) :
        return self.key_common(req.session.value['username']) + ":splits:" + key

    def tones(self, req, key) :
        return self.key_common(req.session.value['username']) + ":tonechanges:" + key

    def memorized(self, req, key):
        return self.key_common(req.session.value['username']) + ":memorized:" + key

    def install_local_language(self, req, language = False) :
        if language :
            l = language
        elif "language" in req.session.value :
            l = req.session.value["language"]
        else :
            l = get_global_language()

        catalogs.language = l.split("-")[0]

        return l

    def runloop(self) :
        mdebug("Runloop running.")
        sleep(5)
        while True :
            self.serial.safe_execute(False, self.db.runloop)
            sleep(1)

        self.db.detach_thread()

    def make_account(self, req, username, password, email, source, admin = False, dbname = False, language = "en", extra_roles = []) :
        username = username.lower()

        if not dbname :
            new_uuid = str(uuid_uuid4())
            dbname = "mica_" + new_uuid

        if not self.userdb.doc_exist("org.couchdb.user:" + username) :
            mdebug("Creating user in _user database...")
            user_doc = { "name" : username,
                         "password" : password,
                         "roles": [] if admin else [username + "_master", "nobody"],
                         "type": "user",
                         "mica_database" : dbname,
                         "language" : language,
                         "learnlanguage" : "en",
                         "date" : timest(),
                         "email" : email,
                         "source" : source,
                         "quota" : -1 if admin else 300,
                          }
            mdebug("Putting doc: " + str(user_doc))
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
                              "names" : ["mica_admin"],
                              "roles" : [username + "_master"] if admin else []
                            },
                        "members" :
                            {
                              "names" : ["mica_admin" if admin else "nobody", username],
                              "roles" : [username + "_master"] + extra_roles
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
        self.check_all_views(username)

    @serial
    def view_runner(self, username, db, specific_views = False) :
        # This only primes views for logged-in users.
        # Scaling the backgrounding for all users will need more thought.

        # FIXME: If the session expires, the backgrounding continues. Should we
        # leave it that way?

        mdebug("Priming views for user: " + username)
        self.views_ready[username] = 0

        if specific_views :
            runners = specific_views
        else :
            runners = deepcopy(self.view_runs)

        for (name, startend) in runners :
            if not db.doc_exist("_design/" + name.split("/")[0]) :
                mdebug("View " + name + " does not yet exist. Loading...")
                self.view_check(username, name.split("/")[0], recreate = True)
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

        '''
        mdebug("Auditing stories")

        for result in db.view("stories/all", startkey=[username], endkey=[username, {}]) :
            tmp_story = result["value"]
            tmp_storyname = tmp_story["name"]

            story_view_original = 0
            story_view_original_found = 0
            story_view_pages = 0
            story_view_pages_found = 0
            stories = {}

            for oresult in db.view('stories/original', startkey=[username, tmp_storyname], endkey=[username, tmp_storyname, {}]) :
                story_view_original = oresult['value']
                break

            for presult in db.view('stories/pages', startkey=[username, tmp_storyname], endkey=[username, tmp_storyname, {}]) :
                story_view_pages = presult['value']
                if tmp_storyname not in stories :
                    stories[tmp_storyname] = []
                break

            for sresult in db.view('stories/allpages', startkey=[username, tmp_storyname], endkey=[username, tmp_storyname, {}]) :
                page = int(sresult["key"][2])
                if page not in stories[tmp_storyname] :
                    stories[tmp_storyname].append(page)
            
            if "nb_pages" in tmp_story :
                if tmp_story["nb_pages"] != story_view_pages :
                    mdebug("Story " + tmp_storyname + " says it has " + str(tmp_story["nb_pages"]) + " pages.")
                mdebug("Story " + tmp_storyname + " actually has: " + str(story_view_original) + " originals and " + str(story_view_pages) + " pages.")
                mdebug("Story " + tmp_storyname + " pages: " + str(stories[tmp_storyname]))
            else :
                mdebug("Story " + tmp_storyname + " says unknown pages.")
        '''

        return _("Database optimized.")

    def view_runner_sched(self) :
        mverbose("Execute the view runner one time to get started...")
        for username, db in self.dbs.iteritems() :
            self.view_runner(username, db)

        while True :
            mverbose("View runner complete. Waiting until next time...")
            sleep(1800)
            for username, db in self.dbs.iteritems() :
                self.view_runner(username, db)

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

    @serial
    def run_render(self, req) :
        if 'connected' not in req.session.value :
            mdebug("New session. Setting connected to false.")
            req.session.value["connected"] = False
            # Can't be sure we've authenticated yet
            # Don't save
            # req.session.save()

        if "language" not in req.session.value and "HTTP_ACCEPT_LANGUAGE" in req.environ:
            req.session.value["language"] = req.environ['HTTP_ACCEPT_LANGUAGE'].split("-")[0].split(",")[0]
            mdebug("Setting session language to browser language: " + req.session.value["language"])
            if req.action != "auth" or mobile :
                req.session.save()

        req.source = req.environ["REMOTE_ADDR"]
        req.db = False
        req.dest = ""#prefix(req.unparsed_uri)
        req.front_ads = False
        req.couch_cookie = False

        if not mobile and not params["couch_server"].count("localhost") and not params["couch_server"].count("dev") :
            req.front_ads = True

        try:
            if self.connected(req) :
                username = req.session.value["username"]
                if username not in self.dbs :
                    if mobile :
                        # Couchbase mobile can do cookie authentication, we're just not using it yet....
                        # FIXME to use cookies for replication instead of saving the user's
                        # password in the session file
                        # This is OK for now since we're running on a phone....
                        mdebug("Trying to restart replication...")

                        if not self.db.replicate(req.session.value["address"], username, req.session.value["password"], req.session.value["database"], params["local_database"], self.get_filter_params(req)) :
                            mdebug("Refreshing session failed to restart main replication: Although you have authenticated successfully, we could not start replication successfully. Please try again")
                        req.session.value["port"] = self.db.listen(username, req.session.value["password"], params["local_port"])
                        req.session.save()
                        if not self.filedb.replicate(req.session.value["address"], "files", "password", "files", "files", self.get_filter_params(req)) :
                            mdebug("Refreshing session failed to restart file replication: Although you have authenticated successfully, we could not start replication successfully. Please try again")
                try :
                    self.verify_db(req, req.session.value["database"], prime = False)
                    resp = self.render(req)
                except couch_adapter.CommunicationError, e :
                    merr("Must re-login: " + str(e))
                    self.clean_session(req, force = True)
                    # The user has completed logging out / signing out already - then this message appears.
                    req.messages = _("Disconnected from MICA")
                    resp = self.render_frontpage(req)
                except couch_adapter.ResourceNotFound, e :
                    mwarn("Problem before warn_not_replicated:")
                    for line in format_exc().splitlines() :
                        mwarn(line)
                    resp = self.warn_not_replicated(req)
                except exc.HTTPTemporaryRedirect, e :
                    raise e
                except exc.HTTPUnauthorized, e :
                    raise e
                except exc.HTTPBadRequest, e :
                    raise e
                except TemplateSyntaxError, e :
                    merr(_("Exception") + ":")
                    resp = "<h4>" + _("Exception") + ":</h4>"

                    for line in format_exc().splitlines() :
                        resp += "<br>" + line
                        merr(line)

                    resp += "<br/><h2>" + _("(template) Please report the above exception to the author. Thank you") + ".</h2>"
                except Exception, msg:
                    merr(_("Exception") + ":")
                    resp = "<h4>" + _("Exception") + ":</h4>"

                    for line in format_exc().splitlines() :
                        resp += "<br>" + line
                        merr(line)

                    resp += "<br/><h2>" + _("(unknown) Please report the above exception to the author. Thank you") + ".</h2>"
                    if ((not isinstance(msg, str) and not isinstance(msg, unicode)) or (not msg.count("SAXParseException") and not msg.count("MissingRenderMethod" and not resp.count("TemplateSyntaxError")))) and self.connected(req) :
                        mwarn("Boo other, logging out user now.")
                        self.clean_session(req, force = True)
            else :
                if req.api and req.action not in (([] if mobile else params["oauth"].keys()) + ["connect", "disconnect"]):
                    raise exc.HTTPUnauthorized("you're not logged in anymore.")

                if req.action in ["connect", "disconnect", "privacy", "help", "switchlang", "online", "instant", "auth", "stories" ] + ([] if mobile else params["oauth"].keys() ):
                    self.install_local_language(req)
                    resp = self.render(req)
                else :
                    resp = self.render_frontpage(req)

        except exc.HTTPTemporaryRedirect, e :
            resp = e
            resp.location = req.dest + resp.location
        except exc.HTTPUnauthorized, e:
            resp = e
        except exc.HTTPException, e:
            resp = e
        except couch_adapter.ResourceNotFound, e :
            mwarn("Problem before warn_not_replicated:")
            for line in format_exc().splitlines() :
                mwarn(line)
            resp = self.warn_not_replicated(req)
        except Exception, e :
            # This 'exception' appears when there is a bug in the software and the software is not functioning normally. A report of the details of the bug follow after the word "Exception"
            aout = ""
            resp = "<h4>" + _("Exception") + ":</h4>"
            aout += "Exception\n"
            for line in format_exc().splitlines() :
                resp += "<br>" + line
                aout += line + "\n"
            resp += "<h2>" + _("(outer unknown) Please report the exception above to the author. Thank you.") + "</h2>"
            merr(aout)
            if self.connected(req) :
                mwarn("Not a well-caught exception. Setting connected to false.")
                req.session.value["connected"] = False
                req.session.save(force = True)

        return resp

    def expired(self, uid, mica, session):
        mdebug("Session " + uid + " has expired.")

        if params["keepsession"] :
            mdebug("Need to keep the session")
            return

        if uid == "debug" :
            mdebug("Not expiring debug session.")
            return

        sessions[uid].acquire()
        skey = mica.session(uid)

        try :
            if mica.sessiondb.doc_exist(skey) :
                value = mica.sessiondb[skey]
                if "username" in value :
                    mica.clean_dbs(value["username"])
                del mica.sessiondb[skey]
                mdebug("Deleting session.")
            else :
                mdebug("Not deleting session.")

        except Exception, e :
            for line in format_exc().splitlines() :
                merr(line)

        lock = sessions[uid]
        del sessions[uid]
        lock.release()

    def __call__(self, environ, start_response):
        try :
            # Hack to make WebOb work with Twisted
            setattr(environ['wsgi.input'], "readline", environ['wsgi.input']._wrapped.readline)

            req = Params(environ)
            req.s = start_response.im_self.request.s
            req.s.mica = self
            req.mica = self
            req.session = IDict(req.s)
            self.populate_oauth_state(req)

            if start_response.im_self.request.s.uid not in sessions :
                sessions[start_response.im_self.request.s.uid] = Lock()
                start_response.im_self.request.s.notifyOnExpire(lambda: self.expired(start_response.im_self.request.s.uid, self, req.session))
            resp = self.run_render(req)

        except exc.HTTPUnauthorized, e :
            resp = e
        except exc.HTTPBadRequest, e :
            resp = e
        except Exception, e :
            merr("BAD MICA ********\nException:")
            for line in format_exc().splitlines() :
                merr(line)

        r = None

        try :
            if isinstance(resp, str) or isinstance(resp, unicode):
                if isinstance(resp, str) :
                    resp = resp.decode("utf-8")
                webob_response = Response(resp)
                if not mobile and 'cookie' in req.session.value :
                    cook = req.session.value["cookie"].split("=")[1]
                    webob_response.set_cookie("AuthSession", cook, max_age=params["timeout"])
                r = webob_response(environ, start_response)

            else :
                r = resp(environ, start_response)
        except Exception, e :
            merr("RESPONSE MICA ********\nException:\n")
            for line in format_exc().splitlines() :
                merr(line)

        return r

    def template(self, template_prefix) :
        contents_fh = open(cwd + relative_prefix + "/" + template_prefix + "_template.html", "r")
        contents = contents_fh.read()
        contents_fh.close()
        return contents

    def api(self, req, desc = "", json = False, error = False) :
        req.session.save()
        if not json :
            json = {}

        if req.human :
            return str(json["desc"]) if "desc" in json else desc
        else :
            if "desc" not in json :
                 json["desc"] = desc

            if "success" not in json :
                json["success"] = True if not error else False

            if json["success"] and req.not_replicated :
                mdebug("API request was true, but setting to false because of replication error.")
                json["success"] = False

            if not mobile and "cookie" in req.session.value :
                json["cookie"] = req.session.value["cookie"]

            if "test_success" not in json :
                json["test_success"] = True
                if "success" in json and not json["success"] :
                    json["test_success"] = False

            if "job_running" not in json :
                json["job_running"] = False

            #mverbose("Dumping: " + str(json))
            return json_dumps(json)

    def bad_api(self, req, desc, json = {}) :
        req.session.save()
        return self.api(req, desc = desc, json = json, error = True)

    def get_polyphome_hash(self, correct, source) :
        return hashlib_md5(str(correct).lower() + "".join(source).encode("utf-8").lower()).hexdigest()

    def rehash_correct_polyphome(self, unit):
        unit["hash"] = self.get_polyphome_hash(unit["multiple_correct"], unit["source"])

    @serial
    def test_dicts_handle(self, f) :
        fname = params["scratch"] + f
        exported = False

        try :
            if not os_path.isfile(fname) :
                self.filedb.get_attachment_to_path("MICA:filelisting_" + f, f, fname)
                mdebug("Exported " + f + " to " + fname)

            exported = True
        except couch_adapter.CommunicationError, e :
            mdebug("FILE " + f + " not fully replicated yet. Waiting..." + str(e))
        except couch_adapter.ResourceNotFound, e :
            mdebug("FILE " + f + " not fully replicated yet. Waiting..." + str(e))

        return exported

    @serial
    def size_check(self, f) :
        fname = params["scratch"] + f
        size = os_path.getsize(fname)
        meta = self.filedb.get_attachment_meta("MICA:filelisting_" + f, f)
        if size == meta["length"] :
            return True
        else :
            return False

    def test_dicts(self) :
        exported = False
        if mobile :
            all_found = False

            while not all_found :
                all_found = True
                recheck = False

                for name, lgp in self.processors.iteritems() :
                    for f in lgp.get_dictionaries() :
                        fname = params["scratch"] + f
                        mdebug("Testing for file: " + f)

                        if not os_path.isfile(fname) :
                            all_found = False

                            mdebug("Replicated file " + f + " is missing at " + fname + ". Exporting...")
                            if not self.test_dicts_handle(f) :
                                break
                        else :
                            if not self.size_check(f) :
                                mdebug("Mobile file is different from DB. Deleting and re-exporting: " + f)
                                os_remove(fname)
                                recheck = True
                                all_found = False
                                break

                if not recheck :
                    sleep(30)

        for name, lgp in self.processors.iteritems() :
            try :
                lgp.test_dictionaries(retest = True)
            except Exception, e :
                err = ""
                for line in format_exc().splitlines() :
                    err += line + "\n"
                merr(err)
                merr("Error preloading dictionaries: " + str(e))

            for f in lgp.get_dictionaries() :
                fname = params["scratch"] + f
                size = os_path.getsize(fname)
                emsg = "Exists FILE: " + str(size) + " " + fname
                if mobile :
                    mdebug(emsg)
                else :
                    mverbose(emsg)
                assert(size != 0)

        self.filedb.detach_thread()

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

    @couch_adapter.repeatable(5)
    def progress(self, req, story, progress_idx, grouplen, page) :
        error = False
        if progress_idx % 10 == 0 :
            self.transmutex.acquire()
            try :
                tmpstory = req.db[self.story(req, story['name'])]
                tmpstory["translating_current"] = progress_idx
                tmpstory["translating_page"] = int(page)
                tmpstory["translating_total"] = grouplen
                req.db[self.story(req, story['name'])] = tmpstory
            except couch_adapter.ResourceConflict, e :
                error = e
                mdebug("Failure to sync translating_current. No big deal: " + str(e))
            finally :
                self.transmutex.release()

        if error :
            raise error

    def parse(self, req, story, page = False, live = False, recount = True) :
        name = story['name']
        mverbose("Ready to translate: " + name + ". Counting pages...")

        assert("source_language" in story)

        processor = self.processors[self.tofrom(story)]

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
            parsed = processor.pre_parse_page(page_input)

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
                mverbose("Begin parsing.")
                processor.parse_page(req, story, groups, str(iidx), progress = self.progress if not live else False)
                mverbose("End parsing.")
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
                    mdebug("Storing to: " + page_key)
                    doc = story["pages"][str(iidx)]

                    # This 'translated_at' is because of bug: https://issues.apache.org/jira/browse/COUCHDB-1415
                    # Supposedly fixed in CouchDB 2.0
                    doc["translated_at"] = timest()
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

        if recount :
            self.nb_pages(req, story, force = True)

        mverbose("Translation complete.")

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

        # Beginning of a sentence. Character may also be translated as 'word' if localized to a language that is already romanized, like English -- also the end of the previous sentence. 'Polyphonic' means that a character has multiple sounds for the same character. For other languages, like English, this word can be ignored and should be translated as simply having more than one meaning (not sound).
        # Pinyin means the romanization of a character-based word, such as Chinese
        # Default appears in a list of items and indicates which is the default item
        out = """
            <div style='color: black'>"
                %(thiselement)s (%(source)s) %(explain)s:
                <br/>
            </div>
            <table class='table table-hover table-striped' style='font-size: x-small; color: black'>
                <tr style='color: black'>
                    %(pinyincolumn)s
                    <td style='color: black'>%(definition)s</td>
                    <td style='color: black'>%(defaultchoice)s?</td>
                </tr>

        """ % dict(thiselement = _("This word") if gp.already_romanized else _("This character"),
                   source = ("" if gp.already_romanized else " ").join(unit["source"]),
                   explain = _("has more than one meaning") if gp.already_romanized else _("is polyphonic: (has more than one pronunciation"),
                   pinyincolumn = "<td style='color: black'>" + _("Pinyin") + "</td>" if len(unit["multiple_sromanization"]) else "",
                   definition = _("Definition"),
                   defaultchoice = _("Default")
                   )

        source = "".join(unit["source"])
        total_changes = 0.0
        changes = req.db.try_get(self.tones(req, source))

        if changes :
            total_changes = float(changes["total"])

        for x in range(0, len(unit["multiple_target"])) :
            percent = self.get_polyphome_percentage(x, total_changes, changes, unit)
            if len(unit["multiple_sromanization"]) :
                spy = " ".join(unit["multiple_sromanization"][x])
            else :
                spy = " ".join(unit["multiple_target"][x])

            if unit["multiple_correct"] != -1 and x == unit["multiple_correct"] :
                link = _("Default")
            else :
                link = """
                        <a style='color: black; font-size: x-small' class='btn-default btn-xs'
                           onclick="multiselect('%(uuid)s','%(index)s','%(nb_unit)s','%(trans_id)s','%(spy)s','%(page)s')">%(select)s</a>
                       """ % dict(uuid = uuid,
                                  index = x,
                                  nb_unit = nb_unit,
                                  trans_id = trans_id,
                                  spy = spy,
                                  page = page,
                                  select = _("Select"))

            # 'Select' appears on a button in review mode that allows the user to choose a definition among multiple choices.
            out += """
                    <tr>
                        <td style='color: black'>%(spy)s (%(percent)s %%)</td>
                        <td style='color: black'>%(target)s</td>
                        <td>%(link)s</td>
                    </tr>
            """ % dict(
                        percent = percent,
                        spy = spy,
                        target = " ".join(unit["multiple_target"][x]).replace("\"", "\\\"").replace("\'", "\\\"").replace("/", " /<br/>"),
                        link = link)

        out += "</table>"

        return out

    def view_keys(self, req, name, _units, source_queries = False) :
        sources = []

        if source_queries :
            sources = source_queries

        if _units :
            mverbose("Input units: " + str(len(_units)))
            for unit in _units :
                if name == "memorized2" :
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

    def render_reviewlist(self, req, story) :
        req.page = req.http.params.get("page")
        req.list_mode = self.get_list_mode(req)
        req.story = story
        gp = self.processors[self.tofrom(story)]
        history = []
        found = {}
        uhash = 0
        online = 0
        offline = 0

        error = False
        try :
            page_dict = req.db[self.story(req, story['name']) + ":pages:" + str(req.page)]
        except couch_adapter.ResourceNotFound, e :
            mwarn("Page during review statistics history could not be found.")
            error = True

        if not error :
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
                        history.append([char, str(changes["total"]), "", "<br/>".join(record["target"]), uhash])
                    else :
                        history.append([char, str(changes["total"]), " ".join(record["sromanization"]), " ".join(record["target"]), uhash])

                uhash += 1

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

        return self.api(req, run_template(req, ReviewElement))

    def render_editslist(self, req, story) :
        req.page = str(req.http.params.get("page"))
        req.list_mode = self.get_list_mode(req)
        history = []

        if req.list_mode :
            found = {}
            uhash = 0
            error = False
            try :
                page_dict = req.db[self.story(req, story['name']) + ":pages:" + str(req.page)]
            except couch_adapter.ResourceNotFound, e :
                mwarn("Rendering eidtslist failed to lookup story page: " + str(req.page) + " uuid " + story['uuid'])
                error = True

            if not error :
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
                        history.append([char, str(record["total_splits"]), " ".join(record["sromanization"]), " ".join(record["target"]), uhash, "SPLIT"])
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
                            history.append([char, str(changes["total"]), " ".join(record["sromanization"]), memberlist, uhash, "MERGE"])
                        else :
                            continue

                    if char not in found :
                        found[char] = True
                    uhash += 1

                # Add sort options here
                def by_total( a ):
                    return int(float(a[1]))

                history.sort( key=by_total, reverse = True )

        req.uuid = story['uuid']
        req.story = story
        req.history = history

        return self.api(req, run_template(req, EditElement))

    def view_outline(self, req, uuid, name, story, start_page, view_mode, meaning_mode) :
        if not story["translated"] :
            # Begin long explanation
            ut = _("This story has not yet been converted to reading format.")
            ut += " "
            if mobile :
                ut += _("Translation requires significant computer power, so you must convert (translate) it online first, and then it will be synchronized with this device.")
            else :
                ut += _("Please click 'Translate' in the side panel to proceed.")
            return self.api(req, ut)

        upgrade_needed = 0

        if "format" not in story or story["format"] == 1 :
            # The next series of messages occur when the software releases a new version that uses a database/file format that is not backwards-compatible with a previous version. In these cases, the database needs to be "upgraded". The software directs the users through a procedure to perform this upgrade, as well as any error messages associated with completing the upgrade process.
            out = _("The database for this story") + " (<b>" + name + "</b>) " + _("needs to be upgraded to version 2") + "."
            upgrade_needed = 2

        # Future upgrade numbers go here...

        if upgrade_needed > 0 :
            if mobile :
                out += _("Unfortunately, this can only be performed with the online version. Please login to your account online to perform the upgrade. The changes will then be synchronized to all your devices. Thank you.")
            else :
                out += "<br/><a class='btn btn-default' onclick=\"start_learning('" + req.action + "', 'storyupgrade', " + sdict(uuid = uuid, version = upgrade_needed) + ")\">" + _("Start Upgrade") + "</a>"

            if "last_error" in story and not isinstance(story["last_error"], str) :
                out + "Last upgrade Exception:<br/>"
                for err in story["last_error"] :
                    out += "<br/>" + myquote(err.replace("\n", "<br/>"))

            return self.api(req, out)

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
                # 'Chat' is a mode where users can practice chatting with each other live with the assistance of the software and their learning history.
                req.story_name = _("Chat")
                req.story_name += " " + str(howmany_diff) + " " + print_period + " " + _("ago") + " " + " " + _("w/") + " " + peer
        else :
            req.story_name = story["name"]

        json = {
                 "install_pages" : {
                     "action" : req.action,
                     "pages" : str(self.nb_pages(req, story)),
                     "uuid" : uuid,
                     "start_page" : start_page,
                     "view_mode" : view_mode,
                     "reload" : True,
                     "meaning_mode" : meaning_mode,
                 }
        }

        req.source_language = story["source_language"]
        req.target_language = story["target_language"]

        req.page = str(start_page)
        req.uuid = story['uuid']

        output = run_template(req, ViewElement)
        return self.api(req, desc = output, json = json)

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

    def view_page_start(self, req, name, story, page, chars_per_line, start_trans_id = 9000000, chat = False) :
        lines = []
        gp = self.processors[self.tofrom(story)]

        if mobile and req.session.value["username"] == "demo" and gp.already_romanized :
            chars_per_line = 10

        mverbose("View Page " + str(page) + " story " + str(name) + " start...")

        if name :
            try :
                page_dict = req.db[self.story(req, name) + ":pages:" + str(page)]
            except couch_adapter.ResourceNotFound, e :
                mwarn("Problem before warn_not_replicated:")
                for line in format_exc().splitlines() :
                    mwarn(line)

                return False
        else :
            page_dict = story["pages"]["0"]

        mverbose("View Page " + str(page) + " story " + str(name) + " fetched...")

        units = page_dict["units"]
        words = len(units)
        line = []
        trans_id = start_trans_id
        chars = 0

        for x in range(0, len(units)) :
            unit = units[x]
            source = "".join(unit["source"])
            ret = self.get_parts(unit, self.tofrom(story))

            if ret == False :
                continue

            py, target = ret

            if py in ['\n', u'\n'] or target in ['\n', u'\n']:
               if len(line) > 0 :
                   if chat :
                       lines = [line] + lines
                   else :
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
            if chat :
                lines = [line] + lines
            else :
                lines.append(line)

        mverbose("View Page " + str(page) + " story " + str(name) + " grouped...")

        return lines, units

    # Perform the analytics of recommending whether or not characters should be
    # split or merged together by analyzing their history.
    def view_check_edits(self, prev_merge, sources, unit, py, word_idx, line, source, batch) :
        curr_merge = False
        merge_end = False
        skip_prev_merge = False
        use_batch = False
        tmp_class = []

        if not py :
            prev_merge = False
            return prev_merge, merge_end, use_batch, batch, tmp_class

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
                            mverbose(source + " (" + str(py) + ") and " + endchars + " are not related to each other!")
                            merge_end = True
                            skip_prev_merge = True

                else :
                    merge_end = True

        if curr_merge :
            if not prev_merge :
                if (word_idx == (len(line) - 1)) :
                    merge_end = False
                    curr_merge = False
                elif merge_end:
                    prev_merge = False
                    merge_end = False
                    curr_merge = False
            elif (word_idx == (len(line) - 1)) :
                merge_end = True

        if curr_merge :
            tmp_class.append("mergetop")
            tmp_class.append("mergebottom")
            if not prev_merge :
                batch += 1
                tmp_class.append("mergeleft")
            use_batch = "merge"
        else :
            if not curr_merge :
                sourcesplits = False if source not in sources['splits'] else sources['splits'][source]
                if sourcesplits and unit["hash"] in sourcesplits["record"] :
                    batch += 1
                    use_batch = "split"
                    tmp_class.append('split')

        prev_merge = curr_merge if not skip_prev_merge else False

        return prev_merge, merge_end, use_batch, batch, tmp_class

    def view_check_reviews(self, req, sources, source, unit, py) :
        largest_hcode = False
        largest_index = -1
        largest = -1
        largest_target = False
        home_changes = False if source not in sources['tonechanges'] else sources['tonechanges'][source]
        add_count = ""

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

        if largest_hcode :
            if len(unit["multiple_sromanization"]) :
                largest_target = " ".join(unit["multiple_sromanization"][largest_index])
            else :
                largest_target = " ".join(unit["multiple_target"][largest_index])

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

        return largest_hcode, largest_index, largest_target, color, add_count

    def view_page(self, req, uuid, name, story, action, output, page, chars_per_line, meaning_mode, start_trans_id = 0, tzoffset = 0, chat = False, history = False) :
        mdebug("View Page " + str(page) + " story " + str(name) + " querying...")
        output = [output]
        gp = self.processors[self.tofrom(story)]
        req.gp = gp

        result = self.view_page_start(req, name, story, page, chars_per_line, start_trans_id = start_trans_id, chat = chat)
        if not result :
            return self.warn_not_replicated(req, harmless = True)

        lines, units = result

        sources = {}
        if action == "edit" :
            sources['mergegroups'] = self.view_keys(req, "mergegroups", units)
            sources['splits'] = self.view_keys(req, "splits", units)
        elif action == "home" :
            sources['tonechanges'] = self.view_keys(req, "tonechanges", units)
        elif action == "read" :
            sources['memorized2'] = self.view_keys(req, "memorized2", units)

        mverbose("View Page " + str(page) + " story " + str(name) + " building...")
        batch = -1
        recommendations = False

        for line in lines :
            prev_merge = False
            words = []

            for word_idx in range(0, len(line)) :
                word = line[word_idx]
                target = word[0].replace("\"", "\\\"").replace("\'", "\\\"")
                py = word[1]
                trans_id = str(word[2])
                unit = word[3]
                nb_unit = str(word[4])
                source = word[5]
                uhash = unit["hash"] if py else trans_id
                nb_unit = str(word[4])
                add_count = ""
                row3_target = target
                memorized = False
                tmp_class = []
                rword = {}

                req.template_dict = { "largest_hcode" : False}

                if action == "edit" :
                    prev_merge, req.template_dict["merge_end"], use_batch, batch, tmp_class = self.view_check_edits(prev_merge, sources, unit, py, word_idx, line, source, batch)

                if py :
                    if (py not in gp.punctuation) and not unit["punctuation"] :
                        if action == "home" :
                            largest_hcode, req.template_dict["largest_index"], req.template_dict["largest_target"], req.template_dict["color"], add_count = self.view_check_reviews(req, sources, source, unit, py)

                            if req.template_dict["largest_hcode"] :
                                if not recommendations :
                                    recommendations = 0
                                recommendations += 1

                    if action != "home" :
                        req.template_dict["color"] = "grey" if not unit["punctuation"] else "white"
                    if action == "home" and len(unit["multiple_target"]) :
                        req.template_dict["polyphomes"] = self.polyphomes(req, story, uuid, unit, nb_unit, trans_id, page)

                    if action == 'read' :
                        if unit["hash"] in sources['memorized2'] :
                            memorized = True

                if "timestamp" in unit and unit["punctuation"] :
                    req.template_dict["chatlog"] = source + u": " + " (" + datetime_datetime.fromtimestamp(int(unit["timestamp"]) + tzoffset).strftime(period_view_mapping[story["name"].split(";")[1]]) + ")" + ": "

                req.template_dict.update(dict(
                    default_web_zoom = req.session.value["default_web_zoom"],
                    tmpclass = " ".join(tmp_class),
                    unit = unit,
                    py = py,
                    chat = chat,
                    add_count = add_count,
                    source = source,
                    target = target,
                    trans_id = trans_id,
                    page = page,
                    uuid = uuid,
                    action = action,
                    nb_unit = nb_unit,
                    source_language = story["source_language"] if "source_language" in story else "zh-CHS",
                    target_language = story["target_language"] if "target_language" in story else "en",
                    uhash = uhash,
                    meaning_mode = meaning_mode,
                    quoted_source = myquote(source),
                    row3_target = row3_target.replace("\"", "\\\"").replace("\'", "\\\""),
                    memorized = memorized,
                    link = source if py else target,
                    pinyin = py if py else target,
                    index = unit["multiple_correct"] if py else -1,
                    batch = 'batch' if (action == "edit" and use_batch) else 'none',
                    batchid = batch if (action == "edit" and use_batch) else -1,
                    operation = use_batch if (action == "edit" and use_batch) else "none",
                ))

                if len(req.template_dict["row3_target"]) and req.template_dict["row3_target"][0] == '/' :
                    req.template_dict["row3_target"] = req.template_dict["row3_target"][1:-1]

                rword[1] = run_template(req, Row1Element)
                rword[2] = run_template(req, Row2Element)
                rword[3] = run_template(req, Row3Element)
                words.append(rword)

            # I have the 'meat' of the page right here in front of me, but
            # because I couldn't find any column-driven table toolkits in HTML
            # I have have to convert it to traditional row-based tables.
            line_out = []
            line_out.append("""
                <table %(style)s>
            """ % dict(style = "class='pagetable' style='background-color: #dfdfdf; border-radius: 15px; margin-bottom: 10px'" if (not chat and not history) else "class='chattable'"))

            for row_idx in [1, 2, 3] :
                line_out.append("""
                    <tr>
                    <td style='padding-right: 10px'/>
                """)
                for word in words :
                    line_out.append(word[row_idx])

                line_out.append("""
                    </tr>
                """)

            line_out.append("""
                </table>
            """)

            if chat and history :
                if "peer" in line[0][3] :
                    msgto = line[0][3]["peer"]
                else :
                    msgto = req.session.value["username"]

                chatpage_fh = open(cwd + "serve/chatpage_template.html")
                output.append((chatpage_fh.read() % dict(
                           msgclass = "msgright" if msgto != req.session.value["username"] else "msgleft",
                           background = '#f0f0f0' if not history else 'white',
                           )).replace("RARAPAGECONTENTS", "".join(line_out)))
                chatpage_fh.close()
            else :
                output += line_out

                if recommendations :
                    # This appears on a button in review mode on the right-hand side to allow the user to "Bulk Review" a bunch of words that the system has already found for you.
                    output = ["<b>" + _("Found Recommendations") + ": " + str(recommendations) + "</b><br/><br/>"] + output

        mdebug("View Page " + str(page) + " story " + str(name) + " complete.")
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
                    self.translation_client.access_token = self.translation_client.get_access_token()

                mverbose("Entering online translation.")
                result = self.translation_client.translate_array(requests, lang, from_lang = from_lang)
                mverbose("Online Translation result: " + str(result))

                if not len(result) or "TranslatedText" not in result[0] :
                    mdebug("Probably key expired: " + str(result))
                else :
                    finished = True

            except ArgumentOutOfRangeException, e :
                error = "Missing results (1). Probably we timed out. Trying again: " + str(e)
            except ArgumentException, e :
                error = "Missing results (2). Probably we timed out. Trying again: " + str(e)
            except TranslateApiException, e :
                error = "First-try translation failed: " + str(e)
            except IOError, e :
                error = "Connection error. Will try one more time: " + str(e)
            except urllib2_URLError, e :
                error = "Response was probably too slow. Will try again: " + str(e)
            except socket_timeout, e :
                error = "Response was probably too slow. Will try again: " + str(e)
            except Exception, e :
                for line in format_exc().splitlines() :
                    merr(line)
                error = "Unknown fatal translation error: " + str(e)
                stop = True
            finally :
                mverbose("Attempt: " + str(attempt) + " finally.")
                if not finished and not error :
                    error = "Translation API not available for some reason. =("
                if error :
                    merr(error)
                    self.store_error(req, name, error)

            if finished or stop :
                break

        self.mutex.release()

        if not finished :
            mdebug("Raising fatal error.")
            raise OnlineTranslateException(error)

        return result

    def storyTemplate(self, name) :
        return """
        <div data-role='page' id='collapse""" + name + """'>
            <div data-role='content' id='content_collapse""" + name + """'>
              <h4><b>""" + name + """</b></h4>
              <ul id='listview_collapse""" + name + """' data-role='listview' data-inset='true'>
              """

    def roll_peer(self, req, peer) :
        if "chats" not in req.session.value :
            req.session.value["chats"] = {"days" : {}, "weeks" : {}, "months" : {}, "years" : {}, "decades" : {}}
            req.session.save()
        rolled = True
        while rolled :
            rolled = False
            self.roll_period(req, "years", "decades", peer)
            if self.roll_period(req, "months", "years", peer) :
                rolled = True
            if self.roll_period(req, "weeks", "months", peer) :
                rolled = True
            if self.roll_period(req, "days", "weeks", peer) :
                rolled = True

    def makestorylist(self, req, tzoffset):
        translist = []
        untrans_count = 0
        reading_count = 0
        newstory_count = 0
        chatting = {"week" : [], "month" : [], "year" : [], "decade" : []}
        storynew = [self.storyTemplate("New")]
        reading = [self.storyTemplate("Reading")]
        noreview = [self.storyTemplate("Reviewing")]
        untrans = [self.storyTemplate("Untranslated")]
        finish = [self.storyTemplate("Finished")]
        peer_list = {} 

        items = []
        for result in req.db.view("stories/all", startkey=[req.session.value['username']], endkey=[req.session.value['username'], {}]) :
            tmp_story = result["value"]
            tmp_storyname = tmp_story["name"]
            items.append((tmp_storyname, tmp_story))

        items.sort(key = itemhelp, reverse = True)

        for name, story in items :
            gp = self.processors[self.tofrom(story) if "source_language" in story else "zh-CHS,en"]

            reviewed = "reviewed" in story and story["reviewed"]
            finished = "finished" in story and story["finished"]
            newstory = "new" in story and story["new"]

            if isinstance(story['uuid'], tuple) :
                uuid = story['uuid']
                mdebug("skipping UUID: " + uuid[0])
                continue

            rname = name.replace(".txt","").replace("\n","").replace("_", " ")
            if "filetype" in story and story["filetype"] == "chat" :
                [x, period, howmany, peer] = story["name"].split(";")
                rname = peer + " ("
                if period != "days" :
                    rname += "From "

                rname += datetime_datetime.fromtimestamp((((int(howmany) * params["counts"][period])) * (60*60*24)) + tzoffset).strftime(period_story_mapping[period_mapping[period]]) + ")"
            notsure = []
            notsure.append("\n<li><a onclick=\"explode('")
            notsure.append(story['uuid'] + "', '" + story['name'] + "'")
            notsure.append(", '" + rname + "'")
            notsure.append(", " + ('true' if story["translated"] else 'false'))
            notsure.append(", " + ('true' if finished else 'false'))
            notsure.append(", " + ('true' if reviewed else 'false'))
            notsure.append(", " + ('true' if "filetype" in story and story["filetype"] == "chat" else 'false'))
            notsure.append(", " + ('true' if "download" not in story or not story["download"] else 'false'))

            if not mobile and not gp.already_romanized and (finished or reviewed) :
                notsure.append(", 'true'")
            else :
                notsure.append(", 'false'")

            notsure.append(", " + ('true' if newstory else 'false'))

            notsure.append(");\" title='" + _("Open") + "' style='font-size: x-small' class='btn-default'>")

            notsure.append("<table class='chattable' width='100%'><tr><td style='color: black'>")

            if "source_language" in story :
                notsure.append(" <b>(" + story["source_language"].split("-")[0] + ")</b>")

            notsure.append("<b style='word-break: break-all;'> " + rname + "</b>")

            if (finished or reviewed or story["translated"]) and "pr" in story :
                pr = story["pr"]
                notsure.append("</td><td style='width: 20%; padding-right: 10px; vertical-align: middle'>")
                notsure.append("<div class='progress progress-success progress-striped'><div class='progress-bar' style='width: ")
                notsure.append(pr + "%;'> (" + pr + "%)</div></div></td><td>")

            closing = "</td></tr></table></a></li>"

            if not story["translated"] :
                if newstory :
                    newstory_count += 1
                    storynew += notsure
                    storynew.append(closing)
                else :
                    untrans_count += 1
                    untrans += notsure

                    if not mobile :
                        untrans.append("<div id='transbutton" + story['uuid'] + "'>")
                        if "last_error" in story and not isinstance(story["last_error"], str) :
                            for err in story["last_error"] :
                                untrans.append("<br/>" + myquote(err.replace("\n", "<br/>")))

                        untrans.append("</div>&#160;")

                    untrans.append("<div style='display: inline' id='translationstatus" + story['uuid'] + "'></div>")

                    if "translating" in story and story["translating"] :
                        translist.append(story['uuid'])
                    untrans.append(closing)
            else :
                if finished :
                   finish += notsure
                   finish.append(closing)
                elif reviewed :
                   if "filetype" in story and story["filetype"] == "chat" :
                       period = story["name"].split(";")[1]
                       peer_list[story["name"].split(";")[3]] = True
                       chatting[period_mapping[period]] += notsure
                       chatting[period_mapping[period]].append(closing)
                   else :
                       reading_count += 1
                       reading += notsure
                       reading.append(closing)
                else :
                   noreview += notsure
                   noreview.append(closing)

        if req.http.params.get("force_rotate") :
            for peer in peer_list :
                mdebug("We should roll chat periods for peer: " + str(peer))
                self.new_job(req, self.roll_peer, False, _("Rotating Old Merged Chats From Database"), peer, True, args = [req, peer])
        return [untrans_count, reading, noreview, untrans, finish, reading_count, chatting, storynew, newstory_count, translist]

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

        memorized = self.view_keys(req, "memorized2", units)

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
                    progress.append([py, target, unit, x, unit["hash"] if py else trans_id, page])
                    total_memorized += 1
                    del memorized[unit["hash"]]

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

        processor = self.processors[self.tofrom(story)]

        if operation == "split" :
            nb_unit = int(edit["nbunit"]) + offset
            mindex = int(edit["index"])
            mhash = edit["uhash"]
            page = edit["pagenum"]
            page_dict = req.db[self.story(req, story['name']) + ":pages:" + str(page)]
            units = page_dict["units"]
            before = units[:nb_unit] if (nb_unit > 0) else []
            after = units[nb_unit + 1:] if (nb_unit != (len(units) - 1)) else []
            curr = units[nb_unit]
            groups = []

            for char in curr["source"] :
                groups.append(char.encode("utf-8"))

            processor.parse_page(req, story, groups, page, temp_units = True)

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
            mhash_start = edit["uhash0"]
            mindex_stop = int(edit["index" + str(nb_units - 1)])
            nb_unit_stop = int(edit["nbunit" + str(nb_units - 1)]) + offset
            mhash_stop = edit["uhash" + str(nb_units - 1)]
            page_dict = req.db[self.story(req, story['name']) + ":pages:" + str(page)]
            units = page_dict["units"]
            before = units[:nb_unit_start] if (nb_unit_start > 0) else []
            after = units[nb_unit_stop + 1:] if (nb_unit_stop != (len(units) - 1)) else []
            curr = units[nb_unit_start:(nb_unit_stop + 1)]
            group = ""

            for chargroup in curr :
                for char in chargroup["source"] :
                    group += char.encode("utf-8")

            processor.parse_page(req, story, [group], page, temp_units = True)

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
        return offset

    @serial
    def storyinit(self, req, uuid, name) :
        source = False
        sourcepath = False
        fp = False
        filename = name

        story = req.db[self.story(req, name)]
        filetype = story['filetype']
        source_lang = story['source_language'].encode('utf-8')
        target_lang = story['target_language'].encode('utf-8')

        if filetype == 'txt' and 'txtsource' in story :
            # return API error if key is missing
            source = story['txtsource'] + '\n'
        else :
            sourcepath = "/tmp/mica_uploads/" + binascii_hexlify(os_urandom(4)) + "." + filetype
            mdebug("Will stream upload to " + sourcepath)
            sourcebytes = req.db.get_attachment_to_path(self.story(req, name), filename, sourcepath)
            mdebug("File " + filename + " uploaded to disk. Bytes: " + str(sourcebytes))

        gp = self.processors[source_lang + "," + target_lang]

        removespaces = False if gp.already_romanized else (True if filetype == "txt" else False)

        if removespaces :
            mdebug("Remove spaces requested!")
        else :
            mdebug("Remove spaces not requested.")

        try :
            if filetype == "pdf" :
                fp = open(sourcepath, 'rb')
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
                    flattened.quality(10)
                    blob = PythonMagick.Blob()
                    flattened.write(blob, "jpg")
                    images = [blob.data] + images

                    for image in images :
                        mdebug("Images len: " + str(len(images)) + " blob size: " + str(len(blob.data)) + " first image size " + str(len(image)))

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
                        self.jobsmutex.acquire()
                        try :
                            jobs = req.db["MICA:jobs"]
                            jobs["list"][req.job_uuid]["result"] = _("Page") + ": " + str(pagecount)
                            req.db["MICA:jobs"] = jobs
                            self.jobsmutex.release()
                        except Exception, e :
                            self.jobsmutex.release()
                            raise e

                device.close()
                fp.close()
            else : # TXT format
                if not source :
                    fp = open(sourcepath, 'rb')
                    source = fp.read()
                    mverbose("Source: " + source)

                de_source = source.decode("utf-8") if isinstance(source, str) else source
                mverbose("Page input:\n " + source)
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

            story = req.db[self.story(req, name)]
            story['new'] = False
            if filetype == "txt" and 'txtsource' in story :
                del story['txtsource']
            req.db[self.story(req, name)] = story
            mdebug("Finihed resetting story to old.")
            if filetype != "txt" :
                mdebug("Deleting original file attachment.")
                story = req.db[self.story(req, name)]
                req.db.delete_attachment(story, filename)
                mdebug("Compacting database after deleted attachment")
                self.serial.safe_execute(False, req.db.compact)
                mdebug("Deleted.")

        except Exception, e :
            # Need to make sure we clear the uploaded file before releasing the exception.
            for line in format_exc().splitlines() :
                merr(line)
            if sourcepath and fp:
                fp.close()
                os_remove(sourcepath)
            raise e

        if sourcepath :
            fp.close()
            os_remove(sourcepath)

        return _("Initialization Complete! Story ready for translation") + ": " + filename

    @serial
    def add_story_from_source(self, req, filename, filetype, source_lang, target_lang) :
        if filetype == "chat" :
            assert(not req.db.doc_exist(self.story(req, filename)))
        elif req.db.doc_exist(self.story(req, filename)) :
            return self.bad_api(req, _("Upload Failed! Story already exists") + ": " + filename)

        mdebug("Received new story name: " + filename)

        new_uuid = str(uuid_uuid4())

        '''
          Before, stories were uploaded and initialize immediately.
          But, to make everything fully AJAX and testable, we have
          to split that into the upload of the original content
          as a 'new' story, but not yet unpacked (i.e. PDFs, etc)
          and then later have a thread unpack them asynchronously.

          Chat messages already do this, in fact. Just gotta prepare
          for importing content from literally anywhere.
        '''

        try :
            req.db[self.story(req, filename)] = {
                    'uuid' : new_uuid,
                    'translated' : False if filetype != "chat" else True,
                    'reviewed' : False if filetype != "chat" else True,
                    'new' : True if filetype != "chat" else False,
                    'name' : filename,
                    'filetype' : filetype,
                    'source_language' : source_lang.decode("utf-8"),
                    'target_language' : target_lang.decode("utf-8"),
                    'format' : story_format,
                    'date' : timest(),
                    'nb_pages' : 0,
                }

            req.db[self.index(req, new_uuid)] = { "value" : filename }

            self.clear_story(req)
        except Exception, e :
            for line in format_exc().splitlines() :
                merr(line)
            return self.bad_api(req, str(e))

        return self.api(req, json = {'storykey' : self.story(req, filename), 'uuid' : new_uuid})

    def flush_pages(self, req, name):
        mdebug("Ready to flush translated pages.")
        allpages = []
        for result in req.db.view('stories/allpages', startkey=[req.session.value['username'], name], endkey=[req.session.value['username'], name, {}]) :
            allpages.append(result["key"][2])

        mdebug("List complete.")
        for tmppage in allpages :
            mdebug("Deleting page " + str(tmppage) + " from story " + name)
            while req.db.doc_exist(self.story(req, name) + ":pages:" + str(tmppage)) :
                del req.db[self.story(req, name) + ":pages:" + str(tmppage)]

        mdebug("Completed flushing translated pages.")

        while req.db.doc_exist(self.story(req, name) + ":final") :
            mdebug("Deleting final version from story " + name)
            del req.db[self.story(req, name) + ":final"]

        mdebug("Flush complete.")

    def view_check(self, username, name, recreate = False) :
       fh = open(cwd + "views/" + name + ".js", 'r')
       vc = fh.read()
       fh.close()

       db = False
       if mobile :
           db = self.db
       else :
           dbname = self.userdb["org.couchdb.user:" + username]["mica_database"]
           db = self.cs[dbname]
       
       try :
           if recreate :
               mdebug("Recreate design document requested for view: " + name)
               del db["_design/" + name]
       except Exception, e :
           mwarn("Deleting design document: " + str(e))

       if not db.doc_exist("_design/" + name) :
           mdebug("View " + name + " does not exist. Uploading.")
           db["_design/" + name] = json_loads(vc)

    def clear_chat(self, req, story_name):
        peer = story_name.split(";")[-1]
        mdebug("Checking if peer is in session cache: " + peer)

        if "chats" not in req.session.value :
            req.session.value["chats"] = {"days" : {}, "weeks" : {}, "months" : {}, "years" : {}, "decades" : {}}

        for period_key in params["multipliers"].keys() :
            if period_key not in req.session.value["chats"] :
                req.session.value["chats"][period_key] = {}

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

    @couch_adapter.repeatable(5)
    def set_page(self, req, story, page) :
        if "current_page" not in story or story["current_page"] != str(page) :
            mdebug("Setting story " + story["name"] + " to page: " + str(page))
            tmp_story = req.db[self.story(req, story["name"])]

            pages = self.nb_pages(req, tmp_story)
            if (int(page) + 1) > pages :
                mwarn("Can't set the current page to higher than the number of pages. Clamping to last page.")
                page = pages - 1

            tmp_story["current_page"] = story["current_page"] = str(page)
            req.db[self.story(req, story["name"])] = tmp_story


    def warn_not_replicated(self, req, frontpage = False, harmless = False) :
        req.not_replicated = True
        self.clear_story(req)

        if mobile :
            msg = _("This account is not fully synchronized. Be sure to touch 'Synchronize' for the story before reading it. You can follow the progress at the top of the screen until the 'download' arrow reaches 100.")
        else :
            if not harmless :
                if self.connected(req) :
                    mwarn("Setting to disconnected!")
                    req.session.value["connected"] = False
                    req.session.save(force = True)

            # Indicates a bug in the software due to invalid synchronization between the user's mobile device and the website.
            msg = _("Synchronization error. Please report this to the author. Thank you.")

        if frontpage :
            req.messages = msg
            return self.render_frontpage(req)
        else :
            return msg

    def clean_dbs(self, username) :
        if mobile :
            self.db.stop_replication()
            self.filedb.stop_replication()

        if username in self.dbs :
            del self.dbs[username]

        if username in self.view_runs :
            del self.view_runs[username]

    def clean_session(self, req, force = False) :
        mwarn("Loggin out user now.")
        req.session.value["connected"] = False
        req.session.save(force = force)

        if 'username' in req.session.value :
            self.clean_dbs(req.session.value['username'])

    def check_all_views(self, username) :
        self.view_check(username, "stories")
        self.view_check(username, "tonechanges")
        self.view_check(username, "mergegroups")
        self.view_check(username, "splits")
        self.view_check(username, "memorized2")
        self.view_check(username, "chats")
        if not mobile :
            self.view_check(username, "download")
            self.view_check(username, "conflicts")

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
        conversions = dict(spinyin = u"sromanization",
                           tpinyin = u"tromanization",
                           multiple_english = u"multiple_target",
                           multiple_spinyin = u"multiple_sromanization",
                           english = u"target",
                           match_pinyin = u"match_romanization",
                           pinyin = u"romanization")

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
            design_docs = [ "memorized2", "mergegroups", "tonechanges", "splits" ]

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

        # First-time display of this unit on UI. Don't update.
        if int(mindex) != -1 :
            unit["multiple_correct"] = mindex
            self.rehash_correct_polyphome(unit)
            page_dict["units"][nb_unit] = unit
            req.db[self.story(req, name) + ":pages:" + str(page)] = page_dict

            if record :
                self.add_record(req, unit, mindex, self.tones, "selected")
        return unit

    @serial
    def run_job_complete(self, req, cleanup, self_delete, job) :
        if cleanup :
            cleanup(*args, **kwargs)

        if self_delete and job["success"] :
            mdebug("Deleting job immediately. Not adding to list")
            try :
                self.jobsmutex.acquire()
                jobs = req.db["MICA:jobs"]
                if job["uuid"] in jobs["list"] :
                    del jobs["list"][job["uuid"]]
                    req.db["MICA:jobs"] = jobs
                self.jobsmutex.release()
            except Exception, e :
                self.jobsmutex.release()
                mdebug("Failed to delete immediately: " + str(e))
                while True :
                    sleep(3600)
        else :
            try :
                self.jobsmutex.acquire()
                job["finished"] = True
                jobs = req.db["MICA:jobs"]
                jobs["list"][job["uuid"]] = job
                req.db["MICA:jobs"] = jobs
                self.jobsmutex.release()
            except Exception, e :
                self.jobsmutex.release()
                raise e

    def run_job(self, req, func, cleanup, job, self_delete, args, kwargs) :
        setattr(current_thread(), "in_a_job", True)
        self.install_local_language(req)

        try :
            mdebug("Running job: " + str(job))
            req.job_uuid = job["uuid"]
            job["result"] = func(*args, **kwargs)
            job["success"] = True
            mdebug("Complete job: " + str(job))
        except Exception, e :
            for line in format_exc().splitlines() :
                mwarn(line)
            mdebug("Error job: " + str(job) + " " + str(e))
            job["success"] = False
            job["result"] = str(e)

        delattr(current_thread(), "in_a_job")

        self.run_job_complete(req, cleanup, self_delete, job)

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

        self.jobsmutex.acquire()

        try :
            jobs = req.db.try_get("MICA:jobs")
            if not jobs :
                jobs = {"list" : {}}

            vt = Thread(target=self.run_job, args = [req, func, cleanup, job, self_delete, args, kwargs])
            vt.daemon = True
            jobs["list"][job["uuid"]] = job
            req.db["MICA:jobs"] = jobs

            mdebug("Starting job: " + str(job))

        except Exception, e :
            self.jobsmutex.release()
            # If a background request that was submitted (like uploading a new story) fails to complete,
            # this message will appear to instruct them to try again.
            out = "Error: " + _("Please try your request again.") + ": " + _(description)
            out += str(e)
            mdebug("Error submitting job: " + str(e))
            return out

        self.jobsmutex.release()

        try :
            # This happens when a user uploads a new story, or performs other long-running actions that
            # cannot be completed in a single click. The request goes into a background job and is
            # processed in the background.

            out = self.render_jobs(req, jobs)
            vt.start()
        except Exception, e :
            out = "Error: " + _("Please try your request again.") + ": " + _(description)
            out += str(e)

        mdebug("Submitted: " + str(job))
        return out

    @serial
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
        #self.prime_db(req, [('stories/all', True)])
        return self.api(req)

    @serial
    def deletestory(self, req, uuid, name) :
        mdebug("Checking for " + self.story(req, name) + " existence")
        story_found = False if not name else req.db.doc_exist(self.story(req, name))
        if name and not story_found :
            mdebug(name + " does not exist. =(")
        else :
            mdebug(name + " was found. Looking up.")
            if name :
                tmp_story = req.db[self.story(req, name)]
                mdebug(name + " looked up. Flushing pages.")
                self.flush_pages(req, name)
                if "filetype" not in tmp_story or tmp_story["filetype"] == "txt" :
                    mdebug("Deleting txt original contents.")
                    if "new" not in tmp_story or not tmp_story["new"] :
                        if req.db.try_get(self.story(req, name) + ":original") :
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
                            try :
                                self.jobsmutex.acquire()
                                jobs = req.db["MICA:jobs"]
                                # This appears when a story is being deleted from the database. The page
                                # number will appear at the end of 'Deleted Page' to indicate how many
                                # pages of the story have been deleted.
                                if req.job_uuid in jobs["list"] :
                                    jobs["list"][req.job_uuid]["result"] = _("Deleted Page") + ": " + str(pagecount)
                                    req.db["MICA:jobs"] = jobs
                                self.jobsmutex.release()
                            except Exception, e :
                                self.jobsmutex.release()
                                raise e
                    mdebug("Deleted.")

            if name and story_found :
                while req.db.doc_exist(self.story(req, name)) :
                    mdebug("Deleting story, revision: " + req.db[self.story(req, name)]["_rev"])
                    del req.db[self.story(req, name)]

            if req.db.doc_exist(self.index(req, uuid)) :
                mdebug("Deleting index.")
                del req.db[self.index(req, uuid)]
                mdebug("Re-checking..." + str(req.db.doc_exist(self.index(req, uuid))))
                mdebug("Done...")

        if "current_story" in req.session.value and req.session.value["current_story"] == uuid :
            self.clear_story(req)
            uuid = False
        mdebug("Compacting DB after removed story")
        self.serial.safe_execute(False, req.db.compact)
        mdebug("Delete complete.")
        #self.prime_db(req, [('stories/all', True)])
        return self.api(req, json = {"uuid" : uuid})

    # This needs to be replaced with token authentication
    def api_validate(func):
        def wrapper(self, req, *args, **kwargs):
            mdebug("Validating API credentials before function: " + func.__name__ + " " + self.__class__.__name__)
            if "connected" not in req.session.value or not req.session.value["connected"] :
                if not req.http.params.get("username") or not req.http.params.get("password") :
                    mdebug("401 HTTPUnauthorized API request (not connected). Returning fail.")
                    raise exc.HTTPUnauthorized(_("API access denied"))
                else :
                    username = req.http.params.get("username")
                    password = req.http.params.get("password")
                    auth_user, reason = self.authenticate(username, password, couch_adapter.credentials(params))
                    if not auth_user :
                        mdebug("401 HTTPUnauthorized API request (bad credentials). Returning fail.")
                        raise exc.HTTPUnauthorized(_("API access denied"))
            return func(self, req, *args, **kwargs)
        return wrapper

    def connected(self, req) :
        if "connected" in req.session.value and req.session.value["connected"] :
            return True
        return False

    def render_disconnect(self, req) :
        self.clean_session(req, force = self.connected(req))
        return self.api(req)

    def render_privacy(self, req) :
        self.install_local_language(req)
        return self.api(req, ("<!DOCTYPE html>\n" if not mobile else "") + re_sub(r"([^>]\n)", "\g<1>\n<br/>\n", run_template(req, PrivacyElement)).encode('utf-8'))

    def render_help(self, req) :
        req.tutorial = tutorials[self.install_local_language(req)]
        return self.api(req, ("<!DOCTYPE html>\n" if not mobile else "") + re_sub(r"([^\>]\n)", "\g<1>\n<br/>", run_template(req, HelpElement).replace("https://raw.githubusercontent.com/hinesmr/mica/master", "").encode('utf-8')))

    def render_mainpage(self, req, msg, pageid = "#messages") :
        if req.messages == "" :
            req.messages = msg if msg else "<div></div>"

        req.mica = self
        req.view_percent = '{0:.1f}'.format(float(self.views_ready[req.session.value['username']]) / float(len(self.view_runs)) * 100.0)
        disk_size = req.db.info()["disk_size"]
        mdebug("Raw disk size: " + str(disk_size))
        req.disk_stat = disk_size / 1024 / 1024
        req.quota_stat = req.session.value["quota"]
        req.user = req.db.try_get(self.acct(req.session.value['username']))
        req.username = req.session.value['username']
        if mobile :
            req.database = params["local_database"]
            # This port is the one that was actually selected on the device, in case there was a conflict
            req.credentials = 'http://127.0.0.1:' + str(req.session.value["port"])
        else :
            req.database = req.session.value["database"]
            req.credentials = couch_adapter.credentials(params)
        contents = run_template(req, HeadElement)
        fh = open(cwd + 'serve/head.js')

        bootscript = self.bootscript() + u"""
            if (window.location.hash == "") {
               $.mobile.navigate('""" + pageid + u"""');
            } else {
               $.mobile.navigate(window.location.hash);
            }
        """

        contents = contents.replace(u"BOOTSCRIPTHEAD", bootscript)

        return contents

    def bootscript(self) :
        fh = open(cwd + 'serve/head.js')
        bootscript = fh.read()
        fh.close()
        return bootscript

    def populate_oauth_state(self, req) :
        if "states_urls" in req.session.value :
            states_urls = req.session.value["states_urls"]
        else :
            states_urls = dict(states = {}, urls = {})

            for name, creds in params["oauth"].iteritems() :
                if name == "redirect" :
                    continue
                service = OAuth2Session(creds["client_id"], redirect_uri=params["oauth"]["redirect"] + name, scope = creds["scope"])

                if name == "facebook" :
                    service = facebook_compliance_fix(service)

                if name == "weibo" :
                    service = weibo_compliance_fix(service)

                states_urls["urls"][name], states_urls["states"][name] = service.authorization_url(creds["authorization_base_url"])
            req.session.value["states_urls"] = states_urls
            req.session.save()

    def render_frontpage(self, req) :
        self.install_local_language(req)
        if not mobile :
            req.oauth = params["oauth"]
        req.mica = self
        req.credentials = couch_adapter.credentials(params)
        return (u"<!DOCTYPE html>\n" if not mobile else u"") + run_template(req, FrontPageElement).replace(u"BOOTSCRIPTHEAD", self.bootscript())

    def render_switchlang(self, req) :
        if not req.http.params.get("lang") :
            return 'error'

        req.session.value["language"] = req.http.params.get("lang")
        req.session.save()

        return self.render_frontpage(req)

    def render_auth(self, req) :
        # We only allow jabber to do this from the localhost. Nowhere else.
        mdebug("Auth request from source: " + req.source)

        if not req.http.params.get("exchange") :
            mwarn("Bad request from: " + req.source)
            raise exc.HTTPBadRequest("auth: you did a bad thing")

        input_dict = self.jabber_crypt.loads(unquote(req.http.params.get("exchange").encode("utf-8")))

        username = unquote(input_dict["username"].lower())
        password = unquote(input_dict["password"])

        auth_user = self.userdb.try_get("org.couchdb.user:" + username)

        if not auth_user or "temp_jabber_pw" not in auth_user or password != auth_user["temp_jabber_pw"] :
            auth_user, reason = self.authenticate(username, password, couch_adapter.credentials(params))

            if not auth_user :
                mwarn("reason: " + str(reason))
                return myquote(self.jabber_crypt.dumps('bad'))
            else :
                mdebug("Success jabber auth w/ password: " + username)
        else :
            mdebug("Success jabber auth w/ token: " + username)

        return myquote(self.jabber_crypt.dumps('good'))

    @api_validate
    def render_online(self, req) :
        out = {"success" : True, "desc" : False}
        target_language = req.http.params.get("target_language")
        source_language = req.http.params.get("source_language")
        requests = json_loads(req.http.params.get("requests"))
        language = req.http.params.get("lang")

        self.install_local_language(req, language)
        try :
            out["result"] = self.translate_and_check_array(req, False, requests, target_language, source_language)
        except OnlineTranslateException, e :
            return self.bad_api(req, _("Internet access error. Try again later: "))

        return self.api(req, out)

    # This is the only function that needs to be backwards compatible
    # and support an old API that does not use JSON because it may be used
    # from old mobile devices, hence the explicit check for the missing
    # 'human' parameter, which defaults to 1
    @api_validate
    def render_instant(self, req) :
        human = True if int(req.http.params.get("human", "1")) else False

        target_language = req.http.params.get("target_language")
        source_language = req.http.params.get("source_language")
        source = req.http.params.get("source")
        language = req.http.params.get("lang")
        test_success = True

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
                result.append({"TranslatedText" : _("No internet access. Offline instant translation only.")})
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
            for line in format_exc().splitlines() :
                mwarn(line)

            if human :
                out += _("Internet access error. Offline instant translation only" + ": " + str(e)) + "<br/>"
            else :
                out["whole"] = {"source" : source, "target" : _("Internet access error. Offline translation only" + ": " + str(e))}
                test_success = False

        if human :
            out += "<h4><b>" + _("Offline instant translation") + ":</b></h4>"

        try :
            for idx in range(0, len(requests)) :
                request = requests[idx]
                if gp.already_romanized and len(requests) > 1 and idx == 0 :
                    continue
                request_decoded = request.decode("utf-8")
                tar = gp.get_first_translation(gp.handle, request_decoded, False)
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

        except OSError, e :
            test_success = False
            mdebug("Looking up target instant translation failed: " + str(e))
            return self.bad_api(req, _("Please wait until this account is fully synchronized for an offline instant translation."))

        return self.api(req, out, json = {"test_success" : test_success} )

    def roll_period(self, req, period_key, period_next_key, peer) :
        error = False
        self.imemutex.acquire()
        rolled = False
        try :
            to_delete = []

            for result in req.db.view('chats/all', startkey=[req.session.value['username'], period_key, peer], endkey=[req.session.value['username'], period_key, peer, {}]) :
                tmp_story = result["value"]
                tmp_storyname = tmp_story["name"]

                [x, period, howmany, peer] = tmp_story["name"].split(";")

                period_difference = self.current_period(period_key) - int(howmany)
                period_difference_max = params["multipliers"][period_key] - 1
                if period_difference < period_difference_max :
                    continue

                rolled = True

                to_delete.append((tmp_story["name"], tmp_story["uuid"]))

                pages = self.nb_pages(req, tmp_story)
                for page_nb in range(0, pages) :
                    origkey = self.chat_period(req, period_key, peer, (int(howmany) * params["counts"][period])) + ":original:" + str(page_nb)
                    pagekey = self.chat_period(req, period_key, peer, (int(howmany) * params["counts"][period])) + ":pages:" + str(page_nb)
                    orig = req.db.try_get(origkey)
                    if orig :
                        mverbose("Got original to roll.")
                        old_messages = orig["messages"]
                        page = req.db.try_get(pagekey)
                        if page :
                            mverbose("Got page to roll.")
                            old_units = page["units"]

                            mdebug("Rolling " + str(len(old_messages)) + " messages of period " + period_key + " from peer " + peer + " to next period " + period_next_key)
                            self.add_period(req, period_next_key, peer, old_messages, old_units, tmp_story, int(howmany) * params["counts"][period_key])
                            mverbose("add for roll returned")
                        else :
                            mwarn("Couldn't find page to roll: " + pagekey)
                    else :
                        mwarn("Couldn't find original to roll: " + origkey)

            mverbose("Checking for deletes...")
            for (name, uuid) in to_delete :
                mverbose("Want to delete story: " + name)
                self.deletestory(req, uuid, name)
            mverbose("Roll complete for period: " + period_key)
        except Exception, e :
            for line in format_exc().splitlines() :
                merr(line)
            error = e
        finally :
            self.imemutex.release()
            if error :
                raise e

        return rolled

    def period_keys(self, req, period_key, current_day, peer, page) :
        origkey = self.chat_period(req, period_key, peer, current_day) + ":original:" + str(page)
        pagekey = self.chat_period(req, period_key, peer, current_day) + ":pages:" + str(page)

        return origkey, pagekey

    def add_period_story(self, req, period_key, peer, current_day, story) :
        if not req.db.try_get(self.chat_period(req, period_key, peer, current_day)) :
            mdebug("Adding new story for period " + period_key + " and peer" + peer)
            self.add_story_from_source(req, self.chat_period_name(period_key, peer, current_day), "chat", story["source_language"], story["target_language"])
        mverbose("Looking up story for period " + period_key + " and peer" + peer)
        story = req.db[self.chat_period(req, period_key, peer, current_day)]
        req.session.value["chats"][period_key][peer] = story
        req.session.save()

        return story

    def add_period(self, req, period_key, peer, messages, new_units, story, current_day = False) :
            story = self.add_period_story(req, period_key, peer, current_day, story)
            if peer not in req.session.value["chats"][period_key] :
                mdebug("Peer not in session. Checking for story...")
                csession = story
            else :
                csession = req.session.value["chats"][period_key][peer]
                mdebug("Using csession: " + str(csession["name"]) + " should be " + self.chat_period_name(period_key, peer, current_day))

            page = str(max(0, int(csession["nb_pages"]) - 1))

            changed_page = False
            while True :
                origkey, pagekey = self.period_keys(req, period_key, current_day, peer, page)
                mdebug("Adding message to period " + period_key + " to page key: " + pagekey)

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
                    mverbose("Adding new page over 20 messages.")
                    changed_page = True
                    page = int(page) + 1

                    origkey, pagekey = self.period_keys(req, period_key, current_day, peer, page)

                    if req.db.try_get(origkey) or req.db.try_get(pagekey) :
                        mwarn("There is a discrepancy between cached pages and db pages. Resetting")
                        mwarn("Orig exists? " + "yes" if req.db.try_get(origkey) else "no")
                        mwarn("Page exists? " + "yes" if req.db.try_get(pagekey) else "no")
                        story["name"] = self.chat_period_name(period_key, peer, current_day)
                        story = self.add_period_story(req, period_key, peer, current_day, story)
                        try :
                            page = str(self.nb_pages(req, story, force = True) - 1)
                        except Exception, e :
                            merr("Failed to force recount pages: " + story["name"] + ": " + str(e))
                            raise e

                    continue
                break

            chat_orig["messages"] += messages
            mverbose("Adding to: " + origkey)
            req.db[origkey] = chat_orig
            mverbose("Adding to: " + pagekey)
            chat_page["units"] += new_units
            req.db[pagekey] = chat_page
            mverbose("Finished adding")

            if changed_page or csession["nb_pages"] == 0 :
                mverbose("Recounting: " + pagekey)
                story["name"] = self.chat_period_name(period_key, peer, current_day)
                story["nb_pages"] = str(int(page) + 1)
                req.session.value["chats"][period_key][peer] = story
                req.session.save()
                self.nb_pages(req, story, force = True)
            mverbose("Add complete")

    def render_chat_ime(self, req) :
        if "chats" not in req.session.value :
            req.session.value["chats"] = {"days" : {}, "weeks" : {}, "months" : {}, "years" : {}, "decades" : {}}
            req.session.save()

        hard_error = False
        result_now = False
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

            start_trans_id = int(req.http.params.get("start_trans_id", 12000000))
            story = {
               "name" : "ime",
               "target_language" : supported_map[req.http.params.get("target_language")],
               "source_language" : supported_map[req.http.params.get("source_language")],
            }

            gp = self.processors[self.tofrom(story)]
            lens = []
            chars = []
            source = ""
            if orig :
                imes = int(req.http.params.get("ime"))
                #mdebug("Type: " + str(type(orig)))
                #start = timest()
                char_result = gp.get_chars(orig, retest = False)
                #mdebug("IME time: " + str(timest() - start) + " for " + str(orig))

                if not char_result :
                    mdebug("No result from search for: " + orig)
                    if not gp.already_romanized :
                        result_now = self.bad_api(req, _("No result"), json = { "test_success" : True })
                        return

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
            hard_error = e

        finally :
            if hard_error :
                self.imemutex.release()
                raise hard_error
            if result_now :
                self.imemutex.release()
                return result_now

        cerror = False
        failed = True
        out = {}
        try :
            try :
                #sys_settrace(tracefunc)
                #start = timest()
                self.parse(req, story, live = True, recount = False)
                #sys_settrace(None)
                #mdebug("Parse time: " + str(timest() - start) + " for " + str(orig))
                #call_report()

            except Exception, e :
                merr("Cannot parse chat: " + str(e))
                cerror = e
            finally :
                if cerror :
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

                before = gp.add_unit([msgfrom], msgfrom, [msgfrom], punctuation = True, timestamp = timestamp, peer = msgto)
                self.rehash_correct_polyphome(before)
                self.add_period(req, "days", peer, messages, [before] + story["pages"]["0"]["units"], story)

            failed = False
            out["result"] = {"chars" : chars, "lens" : lens, "word" : orig}

            # This '1' is important. It's the first index of the list of choices in the chat
            # to choose from.
            select_idx = 1
            for unit_idx in range(2, min(len(story["pages"]["0"]["units"]), (len(chars) * 2 + 1)), 2) :
                story["pages"]["0"]["units"][unit_idx]["select_idx"] = select_idx
                select_idx += 1

            out["result"]["human"] = self.view_page(req, False, False, story, mode, "", "0", "100", "false", start_trans_id = start_trans_id, chat = True if not peer else False)


        except OSError, e :
            merr("OSError: " + str(e))
            mwarn("Problem before warn_not_replicated:")
            for line in format_exc().splitlines() :
                mwarn(line)
            out["desc"] = self.warn_not_replicated(req)
        except processors.NotReady, e :
            merr("Translation processor is not ready: " + str(e))
            mwarn("Problem before warn_not_replicated:")
            for line in format_exc().splitlines() :
                mwarn(line)
            out["desc"] = self.warn_not_replicated(req)
        except Exception, e :
            err = ""
            for line in format_exc().splitlines() :
                err += line + "\n"
            merr(err)
            out["desc"] = _("Chat error") + ": " + source

        self.imemutex.release()

        return self.api(req, _("Chat error"), json = out, error = failed)

    def render_uploadfile(self, req) :
        filetype = req.http.params.get("filetype")
        langtype = req.http.params.get("languagetype")
        filename = req.http.params.get("filename")
        source_lang, target_lang = langtype.split(",")
        return self.add_story_from_source(req, filename.lower().replace(" ","_").replace(",","_").replace(";","_"), filetype, source_lang, target_lang)

    def render_uploadtext(self, req) :
        filename = req.http.params.get("storyname").lower().replace(" ","_").replace(",","_").replace(";","_")
        langtype = req.http.params.get("languagetype")
        source_lang, target_lang = langtype.split(",")
        return self.add_story_from_source(req, filename, "txt", source_lang, target_lang)

    def render_tstatus(self, req, story) :
        uuid = story["uuid"]
        if not req.db.doc_exist(self.index(req, uuid)) :
            return self.api(req, json = {"translated" : { "translating" : 'error', "percent" : 25, "page" : 0, "pages" : 0 }})
        else :
            if "translating" not in story or not story["translating"] :
                return self.api(req, json = {"translated" : { "translating" : 'no', "percent" : 0, "page" : 0, "pages" : 0 }, "uuid" : uuid})
            else :
                result = { "translated" : {"translating" : 'yes'}, "uuid" : uuid}
                curr = float(int(story["translating_current"]))
                total = float(int(story["translating_total"]))

                result["translated"]["percent"] = str(int(curr / total * 100))
                result["translated"]["page"] = str(story["translating_page"]) if "translating_page" in story else "0"
                result["translated"]["pages"] = str(story["translating_pages"]) if "translating_pages" in story else "1"
                return self.api(req, json = result)

    @couch_adapter.repeatable(5)
    def render_finished(self, req, story) :
        name = story["name"]
        finished = True if req.http.params.get("finished") == "1" else False
        tmp_story = req.db[self.story(req, name)]
        tmp_story["finished"] = finished
        req.db[self.story(req, name)] = tmp_story
        # Finished reviewing a story in review mode.
        return self.api(req, _("Finished"), json = {"uuid" : story["uuid"]})

    @couch_adapter.repeatable(5)
    def render_reviewed(self, req, story) :
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

                    result = self.view_page_start(req, name, story, str(page), \
                        req.session.value["app_chars_per_line"] if mobile else req.session.value["web_chars_per_line"])

                    if not result :
                        return self.bad_api(req, self.warn_not_replicated(req), harmless = True)

                    final_output = ""
                    lines, units = result
                    for line in lines :
                        for word in line :
                            target = word[0].replace("\"", "\\\"").replace("\'", "\\\"")
                            py = word[1]
                            final_output += (("hold" if py == u' ' else py) if py else target).lower() + " "
                        final_output += "\n"
                    final[str(page)] = final_output

                req.db[self.story(req, name) + ":final"] = final
        req.db[self.story(req, name)] = tmp_story
        return self.api(req, _("Reviewed"), json = {"uuid" : uuid})

    def render_translate(self, req, story) :
        output = ""
        if story["translated"] :
            output += _("Story already translated. To re-translate, please select 'Forget'.")
        else :
            pt = Thread(target = self.parse, args = [req, story])
            pt.daemon = True
            pt.start()
            '''
            try :
            except OSError, e :
                mwarn("Problem before warn_not_replicated:")
                for line in format_exc().splitlines() :
                    mwarn(line)
                output += self.warn_not_replicated(req)
            except Exception, e :
                output += _("Failed to translate story") + ": " + str(e)
            output += _("Translation complete!")
            '''
        return self.api(req, output, json = {"uuid" : story["uuid"]})

    def render_jobs(self, req, jobs) :
        out = _("MICA is busy processing the following. Please wait") + ":<br/>\n"
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
            try :
                self.jobsmutex.acquire()
                curr_jobs = req.db["MICA:jobs"]
                for job in finished :
                    if job["uuid"] in curr_jobs["list"] :
                        del curr_jobs["list"][job["uuid"]]
                req.db["MICA:jobs"] = curr_jobs
                self.jobsmutex.release()
            except Exception, e :
                self.jobsmutex.release()
                raise e

        return out

    def render_multiple_select(self, req, story) :
        nb_unit = int(req.http.params.get("nb_unit"))
        mindex = int(req.http.params.get("index"))
        trans_id = int(req.http.params.get("trans_id"))
        page = req.http.params.get("page")
        unit = self.multiple_select(req, True, nb_unit, mindex, trans_id, page, story["name"])

        return self.api(req, self.polyphomes(req, story, story["uuid"], unit, nb_unit, trans_id, page))

    def render_memorizednostory(self, req, story) :
        memorized = int(req.http.params.get("memorizednostory"))
        multiple_correct = int(req.http.params.get("multiple_correct"))
        source = req.http.params.get("source")
        source_language = req.http.params.get("source_language")
        target_language = req.http.params.get("target_language")
        mdebug("Received memorization request without story: " + str(memorized) + " " + str(multiple_correct) + " " + source)
        nshash = self.get_polyphome_hash(multiple_correct, source)

        if memorized :
            unit = self.general_processor.add_unit([source], source, [source])
            unit["multiple_correct"] = multiple_correct
            unit["date"] = timest()
            unit["hash"] = nshash
            unit["source_language"] = source_language
            unit["target_language"] = target_language
            if not req.db.doc_exist(self.memorized(req, nshash)) :
                req.db[self.memorized(req, nshash)] = unit
        else :
            if req.db.doc_exist(self.memorized(req, nshash)) :
                del req.db[self.memorized(req, nshash)]

        return self.api(req)

    def render_memorized(self, req, story) :
        memorized = int(req.http.params.get("memorized"))
        nb_unit = int(req.http.params.get("nb_unit"))
        page = req.http.params.get("page")
        source_language = req.http.params.get("source_language")
        target_language = req.http.params.get("target_language")

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
            unit["source_language"] = source_language
            unit["target_language"] = target_language
            if not req.db.doc_exist(self.memorized(req, unit["hash"])) :
                req.db[self.memorized(req, unit["hash"])] = unit
        else :
            if req.db.doc_exist(self.memorized(req, unit["hash"])) :
                del req.db[self.memorized(req, unit["hash"])]

        return self.api(req)

    def render_storyupgrade(self, req, story) :
        name = story["name"]
        if mobile :
            return self.render_mainpage(req, _("Story upgrades not allowed on mobile devices."))

        version = int(req.http.params.get("version"))

        original = 0
        if "format" not in story or story["format"] == 1 :
            if version != 2 :
                return self.render_mainpage(req, _("Invalid upgrade parameters 1") + " =>" + str(version))
            original = 1

        # Add new story upgrades to this list here, like this:
        #elif "format" in story and story["format"] == 2 :
        #    if version != 3 :
        #        return self.render_mainpage(req, _("Invalid upgrade parameters 2") + " =>" + str(version))
        #    original = 2
        #    mdebug("Will upgrade from version 2 to 3")

        elif "format" in story and story["format"] == story_format and (not "upgrading" in story or not story["upgrading"]) :
            return self.render_mainpage(req, _("Upgrade complete"))
        else :
            return self.render_mainpage(req, _("Invalid request."))

        if version > story_format :
            # 'format' referring to the database format the we are upgrading to
            return self.render_mainpage(req, _("No such story format") + " :" + str(version))

        if "upgrading" in story and story["upgrading"] :
            curr_page = story["upgrade_page"] if "upgrade_page" in story else 0
            nbpages = self.nb_pages(req, story)
            assert(nbpages > 0)
            percent = float(curr_page) / float(nbpages) * 100
            out = _("Story upgrade status") + ": " + _("Page") + " " + str(curr_page) + "/" + str(nbpages) + ", " + '{0:.1f}'.format(percent) + "% ..."
            if "last_error" in story and not isinstance(story["last_error"], str) :
                out += "<br/>" + _("Last upgrade Exception") + ":<br/>"
                for err in story["last_error"] :
                    out += "<br/>" + err.replace("\n", "<br/>")
                del story["upgrading"]
                del story["last_error"]
                req.db[self.story(req, name)] = story
                story = req.db[self.story(req, name)]
            return self.render_mainpage(req, out)

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
        return self.render_mainpage(req, _("Story upgrade started. You may refresh to follow its status."))

    def render_memolist(self, req, story) :
        req.list_mode = self.get_list_mode(req)
        req.page = req.http.params.get("page")
        req.memresult = self.memocount(req, story, req.page)
        req.memallcount = 0
        req.story = story

        if req.memresult :
            slang = story["source_language"] if "source_language" in story else "zh-CHS"
            for result in req.db.view('memorized2/allcount', startkey=[req.session.value['username'], slang], endkey=[req.session.value['username'], slang, {}]) :
                req.memallcount = str(result['value'])

            if req.list_mode :
                total_memorized, total_unique, unique, progress = req.memresult
                req.mempercent = str(int((float(total_memorized) / float(total_unique)) * 100)) if total_unique > 0 else 0

        return self.api(req, desc = run_template(req, ReadElement))

    def render_story(self, req, uuid, start_page) :
        req.viewpageresult = False
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
                return self.api(req, _("Edit mode is only supported for learning character-based languages") + ".")

            if req.http.params.get("page") and not req.http.params.get("retranslate") :
                page = req.http.params.get("page")
                mdebug("Request for page: " + str(page) + str(type(page)) + " start_page " + str(start_page))
                if page == u'-1' or page == '-1' or page == -1 :
                    page = start_page
                mdebug("Request for page: " + str(page) + str(type(page)) + " start_page " + str(start_page))

                if req.http.params.get("image") :
                    nb_image = req.http.params.get("image")
                    output = "<br/><br/>"
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
                    return self.api(req, output)
                else :
                    output = ""
                    chat = history = True if ("filetype" in story and story["filetype"] == "chat") else False
                    if chat :
                        output += "<table style='width: 100%'>\n"
                    req.session.value["last_view_mode"] = req.action
                    output = self.view_page(req, uuid, name, story, req.action, output, page, req.session.value["app_chars_per_line"] if mobile else req.session.value["web_chars_per_line"], meaning_mode, chat = chat, history = history)
                    self.set_page(req, story, page)
                    if chat :
                        output += "</table>"
                    return self.api(req, "<br/><br/>" + output)
            return self.view_outline(req, uuid, name, story, start_page, view_mode, meaning_mode)
        else :
            # Beginning of a message.
            output += _("No story loaded. Go to the 'Stories' tab")
            if mobile :
                output += ".<p><br/><h5>" + _("Brand new stories cannot (yet) be created/uploaded yet on the device. You must first create them on the website. (New stories require a significant amount of computer resources to prepare. Thus, they can only be synchronized to the device for regular use.") + ")</h5>"
            else :
                # end of a message
                output += "<br/>" + _("or create one by going to Account => Upload New Story") + "."
                output += "<br/><br/>"
                output += "<h4>"
                # Beginning of a message
                output += _("If this is your first time here") + ", <a data-role='none' class='btn btn-default' href='#help'>"
                # end of a message
                output += _("please read the tutorial") + "</a>"
                output += "</h4>"

        return self.api(req, output)

    def render_stories(self, req, story) :
        ftype = "txt" if "filetype" not in story else story["filetype"]
        if ftype != "txt" :
            # words after 'a' indicate the type of the story's original format, such as PDF, or TXT or EPUB, or whatever...
            # Tho original story format as it was imported, that is
            return self.api(req, _("Story is a") + " " + ftype + ". " + _("Viewing original not yet implemented"))

        which = req.http.params.get("type")
        assert(which)

        if which == "original" :
            original = _("Here is the original story. Choose from one of the options in the above navigation bar to begin learning with this story.") + "<br/>"
            original += req.db[self.story(req, story["name"]) + ":original"]["value"]
            return self.api(req, original.encode("utf-8").replace("\n","<br/>"))
        elif which == "pinyin" :
            final = req.db[self.story(req, story["name"]) + ":final"]["0"]
            return self.api(req, final.encode("utf-8").replace("\n","<br/>"))

    def render_account(self, req, story) :
        json = { "test_success" : False }
        req.accountpageresult = False
        username = req.session.value["username"].lower()
        user = req.db.try_get(self.acct(username))
        disk_size = req.db.info()["disk_size"]
        mdebug("Raw disk size: " + str(disk_size))
        req.disk_stat = disk_size / 1024 / 1024
        req.quota_stat = req.session.value["quota"]
        out = ""

        if not user :
            mwarn("Problem before warn_not_replicated:")
            print_stack()
            return self.warn_not_replicated(req)

        if req.http.params.get("pack") :
            mdebug("Compacting...")
            self.serial.safe_execute(False, req.db.compact)
            self.serial.safe_execute(False, req.db.cleanup)
            design_docs = ["memorized2", "stories", "mergegroups",
                           "tonechanges", "accounts", "splits", "chats" ]

            if not mobile :
                design_docs.append("download")

            for name in design_docs :
                if req.db.doc_exist("_design/" + name) :
                    mdebug("Compacting view " + name)
                    req.db.compact(name)

            # The user requested that the software's database be "cleaned" or compacted to make it more lean and mean. This message appears when the compaction operation has finished.
            json["test_success"] = True
            req.accountpageresult = _("Database compaction complete for your account")
        elif req.http.params.get("changepassword") :
            if mobile :
                # The next handful of mundane phrases are associated with the creation
                # and management of user accounts in the software program and the relevant
                # errors that can occur while performing operations on a user's account.
                req.accountpageresult = _("Please change your password on the website, first")
            else :
                oldpassword = req.http.params.get("oldpassword")
                newpassword = req.http.params.get("password")
                newpasswordconfirm = req.http.params.get("confirm")

                if len(newpassword) < 8 :
                    req.accountpageresult = _("Password must be at least 8 characters! Try again")
                else :
                    if newpassword != newpasswordconfirm :
                        req.accountpageresult = _("Passwords don't match! Try again")
                    else :
                        auth_user, reason = self.authenticate(username, oldpassword, req.session.value["address"])
                        if not auth_user :
                            req.accountpageresult = _("Old passwords don't match! Try again") + ": " + str(reason)
                        else :
                            try :
                                auth_user['password'] = newpassword
                                del self.dbs[username]
                                self.verify_db(req, "_users")
                                req.db["org.couchdb.user:" + username] = auth_user
                                del self.dbs[username]
                                self.verify_db(req, req.session.value["database"], password = newpassword)
                                req.accountpageresult = _("Success!") + " " + _("User") + " " + username + " " + _("password changed")
                                json["test_success"] = True
                            except Exception, e :
                                json["success"] = False
                                req.accountpageresult = _("Password change failed") + ": " + str(e)
        elif req.http.params.get("resetpassword") :
            if mobile :
                req.accountpageresult = _("Please change your password on the website, first")
            else :
                newpassword = binascii_hexlify(os_urandom(4))

                auth_user, reason = self.authenticate(username, False, req.session.value["address"])
                if not auth_user :
                    req.accountpageresult = _("Could not lookup your account! Try again") + ": " + str(reason)
                else :
                    try :
                        auth_user['password'] = newpassword
                        del self.dbs[username]
                        self.verify_db(req, "_users")
                        req.db["org.couchdb.user:" + username] = auth_user
                        del self.dbs[username]
                        self.verify_db(req, req.session.value["database"], password = newpassword)
                        req.accountpageresult = _("Success!") + " " + _("User") + " " + username + " " + _("password changed") + ": " + newpassword
                        json["test_success"] = True
                        json["oldpassword"] = newpassword
                    except Exception, e :
                        out = ""
                        for line in format_exc().splitlines() :
                            out += line + "\n"
                        merr(out)
                        req.accountpageresult = _("Password change failed") + ": " + str(e)
        elif req.http.params.get("newaccount") :
            if not self.userdb :
                # This message appears only on the website when used by administrators to indicate that the server is misconfigured and does not have the right privileges to create new accounts in the system.
                req.accountpageresult = _("Server not configured correctly. Can't make accounts")
            else :
                newusername = req.http.params.get("username").lower()
                newpassword = req.http.params.get("password")
                newpasswordconfirm = req.http.params.get("confirm")
                admin = True if req.http.params.get("isadmin", 'off') == 'on' else False
                email = req.http.params.get("email")
                language = req.http.params.get("language")

                if newusername in ["mica_admin", "files"] :
                    req.accountpageresult = _("Invalid account name! Try again")
                else :
                    if len(newpassword) < 8 :
                        req.accountpageresult = _("Password must be at least 8 characters! Try again")
                    else :
                        if newpassword != newpasswordconfirm :
                            req.accountpageresult = _("Passwords don't match! Try again")
                        else :
                            if not req.session.value["isadmin"] :
                                req.accountpageresult = _("Non-admin users can't create admin accounts. What are you doing?!")
                            else :
                                if self.userdb.doc_exist("org.couchdb.user:" + newusername) :
                                    req.accountpageresult = _("Account already exists! Try again")
                                else :
                                    if newusername.count(":") or newusername.count(";") :
                                        req.accountpageresult = _("We're sorry, but you cannot have colon ':' characters in your account name or email address.")
                                    else :
                                        # FIXME: This complains if an account was created, then deleted, then created again
                                        # because the old revision is still in couchdb
                                        self.make_account(req, newusername, newpassword, email, "mica", admin = admin, language = language)

                                        req.accountpageresult = _("Success! New user was created") + ": " + newusername
                                        json["test_success"] = True
        elif req.http.params.get("deleteaccount") and req.http.params.get("username") :
            if mobile :
                req.accountpageresult = _("Please delete your account on the website and then uninstall the application. Will support mobile in a future version.")
            else :
                username = req.http.params.get("username").lower()

                if not self.userdb :
                    # This message appears only on the website when used by administrators to indicate that the server is misconfigured and does not have the right privileges to create new accounts in the system.
                    req.accountpageresult = _("Server not configured correctly. Can't make accounts")
                    json["success"] = False
                else :
                    if not self.userdb.doc_exist("org.couchdb.user:" + username) :
                        mdebug("No such account. Returning fail.")
                        req.accountpageresult = _("No such account. Cannot delete it.")
                        json["success"] = False
                        json["test_success"] = True 
                    else :
                        auth_user = self.userdb["org.couchdb.user:" + username]

                        bad_role_length = False
                        if req.session.value["username"] != username :
                            if not req.session.value["isadmin"] :
                                # Translator: This message is for hackers attempting to break into the website. It's meant to be mean on purpose.
                                req.accountpageresult = _("Go away and die.")
                                bad_role_length = True 
                            else :
                                role_length = len(self.userdb["org.couchdb.user:" + username]["roles"])

                                if role_length == 0 :
                                    bad_role_length = True
                                    req.accountpageresult = _("Admin accounts can't be deleted by other people. The admin must delete their own account.")

                        if not bad_role_length :
                            dbname = auth_user["mica_database"]
                            mdebug("Confirming database before delete: " + dbname)

                            todelete = self.cs[dbname]

                            del self.userdb["org.couchdb.user:" + username]
                            del self.cs[dbname]

                            if req.session.value["username"] != username :
                                req.accountpageresult = _("Success! Account was deleted") + ": " + username
                                json["test_success"] = True
                            else :
                                self.clean_session(req, force = True)
                                req.messages = _("Your account has been permanently deleted.")
                                return self.render_frontpage(req)
                        else :
                            json["success"] = False
        elif req.http.params.get("changequota") and req.http.params.get("username") and req.http.params.get("quota") :
            if mobile :
                req.accountpageresult = _("Quota requests need to be done on the website.")
                json["success"] = False
            else :
                username = req.http.params.get("username").lower()

                if not self.userdb :
                    # This message appears only on the website when used by administrators to indicate that the server is misconfigured and does not have the right privileges to create new accounts in the system.
                    req.accountpageresult = _("Server not configured correctly. Can't modify quotas")
                    json["success"] = False
                else :
                    if not self.userdb.doc_exist("org.couchdb.user:" + username) :
                        mdebug("No such account. Returning fail.")
                        req.accountpageresult = _("No such account. Cannot quotas.")
                        json["success"] = False
                    else :
                        auth_user = self.userdb["org.couchdb.user:" + username]

                        bad_role_length = False
                        if req.session.value["username"] != username :
                            if not req.session.value["isadmin"] :
                                # Translator: This message is for hackers attempting to break into the website. It's meant to be mean on purpose.
                                req.accountpageresult = _("Go away and die.")
                                bad_role_length = True 
                            else :
                                role_length = len(self.userdb["org.couchdb.user:" + username]["roles"])

                                if role_length == 0 :
                                    bad_role_length = True
                                    req.accountpageresult = _("Admin accounts can't be deleted by other people. The admin must delete their own account.")

                        if not bad_role_length :
                            try :
                                newquota = int(req.http.params.get("quota"))
                                mdebug("Changing quota for " + username + " to: " + str(newquota))
                                if newquota == -1 and not req.session.value["isadmin"] :
                                    req.accountpageresult = _("Go away and die.")
                                    json["success"] = False
                                elif newquota < -1 :
                                    req.accountpageresult = _("Go away and die.")
                                    json["success"] = False
                                else :
                                    auth_user["quota"] = newquota
                                    self.userdb["org.couchdb.user:" + username] = auth_user
                                    req.accountpageresult = _("Success! Quota was changed") + ": " + (str(newquota) if newquota != -1 else _("unlimited")) + " MB " + _("for user") + ": " + username
                                    json["test_success"] = True
                            except ValueError, e :
                                json["success"] = False
                                req.accountpageresult = _("Error: Quota could not be changed") + ": " + str(req.http.params.get("quota")) + " MB " + _("for user") + ": " + username + ": " + str(e)
                                json["success"] = False
                        else :
                            json["success"] = False
                                
        elif req.http.params.get("changelanguage") :
            language = req.http.params.get("language")
            if language in supported_map :
                user["language"] = language
                req.db[self.acct(username)] = user
                req.session.value["language"] = language
                self.install_local_language(req)
                req.accountpageresult = _("Success! Language changed")
                json["test_success"] = True
            else :
                merr("No such language: " + language)
                req.accountpageresult = "No such language: " + language
                json["success"] = False

        elif req.http.params.get("changelearnlanguage") :
            language = req.http.params.get("learnlanguage")
            if language in supported_map :
                user["learnlanguage"] = language
                req.session.value["learnlanguage"] = language
                req.db[self.acct(username)] = user
                self.install_local_language(req)
                req.accountpageresult = _("Success! Learning Language changed")
                json["test_success"] = True
            else :
                merr("No such language: " + language)
                req.accountpageresult = "No such language: " + language
                json["success"] = False
        elif req.http.params.get("changeemail") :
            email = req.http.params.get("email")
            if len(email) > 50 :
                req.accountpageresult = _("Sorry. Why is your email so long?")
            elif email.count(" ") :
                req.accountpageresult = _("Sorry. Email with spaces in it?")
            elif not email.count("@") :
                req.accountpageresult = _("Sorry. Invalid email address.")
            else :
                email_user = self.userdb["org.couchdb.user:" + username]
                email_user['email'] = email
                self.userdb["org.couchdb.user:" + username] = email_user
                user["email"] = email
                req.db[self.acct(username)] = user
                req.accountpageresult = _("Success! Email changed")
                json["test_success"] = True

        elif req.http.params.get("tofrom") :
            tofrom = req.http.params.get("tofrom")
            remove = int(req.http.params.get("remove"))

            if tofrom not in processor_map :
                # Someone supplied invalid input to the server indicating a dictionary that does not exist.
                req.accountpageresult = _("No such dictionary. Please try again") + ": " + tofrom
                json["success"] = False
            else :
                if "filters" not in user :
                   user["filters"] = {'files' : [], 'stories' : [] }

                if remove == 0 :
                    if tofrom not in user["filters"]['files'] :
                        user["filters"]['files'].append(tofrom)
                else :
                    if tofrom in user["filters"]['files'] :
                        user["filters"]['files'].remove(tofrom)

                req.session.value["filters"] = user["filters"]

                replication_failed = False
                if mobile :
                    self.filedb.stop_replication()

                    if not self.filedb.replicate(req.session.value["address"], "files", "password", "files", "files", self.get_filter_params(req)) :
                        req.accountpageresult = _("Failed to intiate download of this dictionary. Please try again") + ": " + tofrom
                        replication_failed = True

                if not replication_failed :
                    req.db[self.acct(username)] = user

                    if mobile :
                        if remove == 0 :
                            req.accountpageresult = _("Success! We will start downloading that dictionary") + ": " + supported[tofrom]
                        else :
                            req.accountpageresult = _("Success! We will no longer download that dictionary") + ": " + supported[tofrom]
                    else :
                        if remove == 0 :
                            req.accountpageresult = _("Success! We will start distributing that dictionary to your devices") + ": " + supported[tofrom]
                        else :
                            req.accountpageresult = _("Success! We will no longer distribute that dictionary to your devices") + ": " + supported[tofrom]
                    json["test_success"] = True

        elif req.http.params.get("setappchars") :
            try :
                chars_per_line = int(req.http.params.get("setappchars"))

                if chars_per_line > 1000 or chars_per_line < 5 :
                    # This number of characters refers to a limit of the number of words or characters that are allowed to be displayed on a particular line of a page of a story. This allows the user to adapt the viewing mode manually to big screens and small screens.
                    req.accountpageresult = _("Number of characters can't be greater than 1000 or less than 5")
                else :
                    user["app_chars_per_line"] = chars_per_line
                    req.db[self.acct(username)] = user
                    req.session.value["app_chars_per_line"] = chars_per_line
                    # Same as before, but specifically for a mobile device
                    req.accountpageresult = _("Success! Mobile Characters-per-line in a story set to:") + " " + str(chars_per_line)
                    json["test_success"] = True
            except ValueError, e :
                json["success"] = False
                merr("That's not a number.")
                req.accountpageresult = "Mysterious."
        elif req.http.params.get("setwebchars") :
            try :
                chars_per_line = int(req.http.params.get("setwebchars"))
                if chars_per_line > 1000 or chars_per_line < 5:
                    req.accountpageresult = _("Number of characters can't be greater than 1000 or less than 5")
                else :
                    user["web_chars_per_line"] = chars_per_line
                    req.db[self.acct(username)] = user
                    req.session.value["web_chars_per_line"] = chars_per_line
                    # Same as before, but specifically for a website
                    req.accountpageresult = _("Success! Web Characters-per-line in a story set to:") + " " + str(chars_per_line)
                    json["test_success"] = True
            except ValueError, e :
                json["success"] = False
                merr("That's not a number.")
                req.accountpageresult = "Mysterious."
        elif req.http.params.get("setappzoom") :
            try :
                zoom = float(req.http.params.get("setappzoom"))
                if zoom > 3.0 or zoom < 0.5 :
                    # The 'zoom-level' has a similar effect to the number of characters per line, except that it controls the whole layout of the application (zoom in or zoom out) and not just individual lines.
                    req.accountpageresult = _("App Zoom level must be a decimal no greater than 3.0 and no smaller than 0.5")
                else :
                    user["default_app_zoom"] = zoom
                    req.db[self.acct(username)] = user
                    req.session.value["default_app_zoom"] = zoom
                    # Same as before, but specifically for an application running on a mobile device
                    req.accountpageresult = _("Success! App zoom level set to:") + " " + str(zoom)
                    json["test_success"] = True
            except ValueError, e :
                json["success"] = False
                merr("That's not a number.")
                req.accountpageresult = "Mysterious."
        elif req.http.params.get("setwebzoom") :
            try :
                zoom = float(req.http.params.get("setwebzoom"))
                if zoom > 3.0 or zoom < 0.5 :
                    # Same as before, but specifically for an application running on the website
                    req.accountpageresult = _("Web Zoom level must be a decimal no greater than 3.0 and no smaller than 0.5")
                else :
                    user["default_web_zoom"] = zoom
                    req.db[self.acct(username)] = user
                    req.session.value["default_web_zoom"] = zoom
                    # Same as before, but specifically for an application running on the website
                    req.accountpageresult = _("Success! Web zoom level set to:") + " " + str(zoom)
                    json["test_success"] = True
            except ValueError, e :
                json["success"] = False
                merr("That's not a number.")
                req.accountpageresult = "Mysterious."
        else :
            # Just show the account page normally.
            json["test_success"] = True

        req.default_zoom = str(user["default_app_zoom" if mobile else "default_web_zoom"])
        req.chars_per_line = str(user["app_chars_per_line"] if mobile else user["web_chars_per_line"])
        req.supported = supported
        req.user = user
        req.processors = self.processors
        req.scratch = params["scratch"]
        req.userdb = self.userdb
        return self.api(req, out + run_template(req, AccountElement), json = json)

    def render_chat(self, req, unused_story) :
        if "jabber_key" not in req.session.value :
            req.session.value["jabber_key"] = binascii_hexlify(os_urandom(4))

        if "chats" not in req.session.value :
            req.session.value["chats"] = {"days" : {}, "weeks" : {}, "months" : {}, "years" : {}, "decades" : {}}

        if req.http.params.get("history") :
            def by_date(story):
                return int((story["name"].split(";")[2]))

            peer = req.http.params.get("history")
            tzoffset = int(req.http.params.get("tzoffset"))

            if not mobile :
                self.new_job(req, self.roll_peer, False, _("Rotating Old Merged Chats From Database"), peer, True, args = [req, peer])

            out = "<table width='100%'>\n"
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
                        out += self.view_page(req, tmp_story["uuid"], tmp_story["name"], tmp_story, "read", "", str(nb_pages - 1), "100", "false", tzoffset = tzoffset, chat = True, history = True, start_trans_id = 5000000)
                        break

                    if added :
                        break

            out += "\n</table>"
            return self.api(req, out)

        req.main_server = params["main_server"]

        story = {
           "target_language" : supported_map[req.session.value["language"]],
           "source_language" : supported_map[req.session.value["learnlanguage"]],
        }

        if self.tofrom(story) not in self.processors :
            return self.bad_api(req, _("We're sorry, but chat for this language pair is not supported") + ": " + lang[story["source_language"]] + " " + _("to") + " " + lang[story["target_language"]] + " (" + _("as indicated by your account preferences") + "). " + _("Please choose a different 'Learning Language' in your accout preferences. Thank you."))

        req.gp = self.processors[self.tofrom(story)]
        req.source_language = story["source_language"]
        req.target_language = story["target_language"]

        return self.api(req, run_template(req, ChatElement))

    def render_storylist(self, req, unused_story) :
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
                self.filedb.stop_replication()

                if not self.db.replicate(req.session.value["address"], req.session.value["username"], req.session.value["password"], req.session.value["database"], params["local_database"], self.get_filter_params(req)) :
                    return self.bad_api(req, _("Failed to change primary synchronization. Please try again") + ": " + tofrom)
                if not self.filedb.replicate(req.session.value["address"], "files", "password", "files", "files", self.get_filter_params(req)) :
                    return self.bad_api(req, _("Failed to change file synchronization. Please try again") + ": " + tofrom)

            req.db[self.story(req, tmpname)] = tmpstory
            req.db[self.acct(req.session.value["username"])] = tmpuser

            return self.api(req, "changed")

        if not req.http.params.get("tzoffset") :
            return self.api(req, json = dict(reload = True))

        tzoffset = int(req.http.params.get("tzoffset"))

        storylist = []

        untrans_count, reading, noreview, untrans, finish, reading_count, chatting, newstory, newstory_count, translist = self.makestorylist(req, tzoffset)

        reading.append(u"\n</ul></div></div>\n")
        noreview.append(u"\n</ul></div></div>\n")
        untrans.append(u"\n</ul></div></div>\n")
        finish.append(u"\n</ul></div></div>\n")
        newstory.append(u"\n</ul></div></div>\n")

        chat_all = [self.storyTemplate("Chatting")]

        for period in [ "week", "month", "year", "decade" ] :
            if len(chatting[period]) :
                chat_all.append("<li>" + _("Recent") + " " + translated_periods[period] + ":</li>")
                chat_all += chatting[period]

        chat_all.append(u"\n</ul></div></div>\n")

        storylist += newstory + reading + chat_all + untrans + noreview + finish

        firstload = "reviewing"
        if newstory_count :
            firstload = "newstory"
        elif untrans_count :
            firstload = "untranslated"
        elif reading_count :
            firstload = "reading"

        try :
            return self.api(req, json = dict(firstload = firstload, translist = translist, reload = False, storylist = u"".join(storylist)))
        except Exception, e:
            merr("Storylist fill failed: " + str(e))
            return self.bad_api(req, _("Storylist failed") + ": " + str(e))

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

    def render_oauth(self, req) :
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
                    return False, _("We're sorry you feel that way, but we need your authorization to use this service. You're welcome to try again later. Thanks.")
                else :
                    # Social networking service denied our request to authenticate and create an account for some reason. Notify and move on.
                    return False, _("Our service could not create an account from you") + ": " + desc + " (" + str(reason) + ")."
            else :
                # Social networking service experienced some unknown error when we tried to authenticate the user before creating an account.
                return False, _("There was an unknown error trying to authenticate you before creating an account. Please try again later") + "."

        if not req.http.params.get("code") :
            raise exc.HTTPBadRequest("Code is missing. Who are you?")

        if not req.http.params.get("state") :
            raise exc.HTTPBadRequest("State is missing. Who are you?")

        state = req.http.params.get("state")
        code = req.http.params.get("code")

        if not req.http.params.get("finish") :
            return False, """
                <img src='%(mpath)s/%(spinner)s' width='15px'/>&#160;%(signin)s...
                <script>
                    finish_new_account('%(code)s', '%(who)s', '%(state)s');
                </script>
            """ % dict(mpath = req.mpath,
                       spinner = spinner,
                       code = code,
                       who = who,
                       state = state,
                       signin = _("Signing you in, Please wait"))

        if "states_urls" not in req.session.value :
            raise exc.HTTPUnauthorized("Your session doesn't have a state. Try again.")

        states_urls = req.session.value["states_urls"]

        if states_urls["states"][who] != state :
            raise exc.HTTPBadRequest("Invalid state. Who are you?")

        try :
            service.fetch_token(creds["token_url"], client_secret=creds["client_secret"], code = code)
            mdebug("Token fetched successfully: " + str(service.token))

            if who == "baidu" :
                del service.token["token_type"]

            lookup_url = creds["lookup_url"]

            if "force_token" in creds and creds["force_token"] :
                lookup_url += "?access_token=" + service.token["access_token"]

            mdebug("Looking up to: " + lookup_url)

            r = service.get(lookup_url)
        except MissingTokenError, e :
            for line in format_exc().splitlines() :
                merr(line)
            return True, _("The oauth protocol had an error") + ": " + str(e) + "." + _("Please report the above exception to the author. Thank you")
        except InvalidGrantError, e :
            for line in format_exc().splitlines() :
                merr(line)
            merr("Someone tried to use an old URL with an old Code")
            return False, _("The oauth protocol had an error") + ": " + str(e) + "." + _("Please try again. Thank you")
        except requests_ConnectionError, e :
            for line in format_exc().splitlines() :
                merr(line)
            return False, _("The oauth protocol had an error") + ": " + str(e) + "." + _("Please try again. Thank you")

        mdebug("MICA returned content is: " + str(r.content))
        values = json_loads(r.content)

        if creds["verified_key"] :
            vkeys = creds["verified_key"].split(",")
            try :
                if not getFromDict(values, vkeys) :
                    return False, _("You have successfully signed in with the 3rd party, but they cannot confirm that your account has been validated (that you are a real person). Please try again later.")
            except KeyError, e :
                return False, _("We're sorry, but the oauth provider is missing information for your account") + ":  " + who + ": " + str(vkeys) + ": " + str(e)

        email_found = False

        if creds["email_key"] :
            vkeys = creds["email_key"].split(",")
            try :
                values["email"] = getFromDict(values, vkeys)
            except KeyError, e :
                mdebug("Couldn't find email from: " + str(vkeys) + ", dict: " + str(values))
                return False, _("We're sorry. You have declined to share your email address, but we need a valid email address in order to create an account for you")

        password = binascii_hexlify(os_urandom(4))
        if "locale" not in values :
            language = "en"
        else :
            language = values["locale"].split("-")[0] if values['locale'].count("-") else values["locale"].split("_")[0]

        values["username"] = values["email"]
        from_third_party = values

        if not self.userdb.doc_exist("org.couchdb.user:" + values["username"]) :
            if values["email"].count(":") or values["email"].count(";") :
                return False, _("We're sorry, but you cannot have colon ':' characters in your account name or email address.") + ":&#160;" + _("Original login service") + ":&#160;<b>" + source + "</b>&#160;." + _("Please choose a different service and try again")

            self.make_account(req, values["email"], password, values["email"], who, language = language)
            mdebug("Language: " + language)

            output = """
                <br/><br/>%(welcome)s
                <br/><br/>Save this Password: %(password)s
                <br/><br/>%(firsttime)s,&#160;
                <a rel='external' data-role='none' class='btn btn-default' href='/help'>%(tutorial)s</a>
                <br/><br/>%(happy)s!</h4>
                <br/><a rel='external' data-role='none' class='btn btn-default' href='/'>%(start)s</a>
                <script>
                    $('#maindisplay').attr('style', 'display: none');
                    $('#leftpane').attr('style', 'display: none');
                </script>
            """ % dict(tutorial = _("please read the tutorial"),
                       happy = _("Happy Learning"),
                       start = _("Start learning!"),
                       password = password,
                       firsttime = _("If this is your first time here"),
                       welcome = _("We have created a default password to be used with your mobile device(s). Please write it down somewhere. You will need it only if you want to synchronize your mobile devices with the website. If you do not want to use the mobile application, you can ignore it. If you do not want to write it down, you will have to come back to your account preferences and reset it before trying to login to the mobile application. You are welcome to go to your preferences now and change this password."))

            req.messages = output
        else :
            auth_user = self.userdb["org.couchdb.user:" + values["username"]]

            if "source" not in auth_user or ("source" in auth_user and auth_user["source"] != who) :
                source = "mica" if "source" not in auth_user else auth_user["source"]
                return False, _("We're sorry, but someone has already created an account with your credentials") + ":&#160;" + _("Original login service") + ":&#160;<b>" + source + "</b>&#160;." + _("Please choose a different service and try again")
            req.messages = "<h3 style='color: white'>" + _("Redirecting") + "...</h3><script>window.location.href='/';</script>"

        from_third_party["password"] = password

        return True, from_third_party

    def render_connect(self, req, from_third_party) :
        password = False
        username = False

        if from_third_party :
            username = from_third_party["email"].lower()
            password = from_third_party["password"]
        else :
            if params["mobileinternet"] and params["mobileinternet"].connected() == "none" :
                # Internet access refers to the wifi mode or 3G mode of the mobile device. We cannot connect to the website without it...
                return self.bad_api(req, _("To login for the first time and begin synchronization with the website, you must activate internet access."))

            username = req.http.params.get('username').lower()
            password = req.http.params.get('password')

        if req.http.params.get("address") :
            address = req.http.params.get('address')
        elif "adddress" in req.session.value and req.session.value["address"] != None :
            address = req.session.value["address"]
        else :
            address = couch_adapter.credentials(params)

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


        mdebug("authenticating...")

        auth_user, reason = self.authenticate(username, password, address)

        if not auth_user :
            mwarn("Login failed; " + str(reason))
            # User provided the wrong username or password. But do not translate as 'username' or 'password' because that is a security risk that reveals to brute-force attackers whether or not an account actually exists.
            return self.bad_api(req, _("Invalid credentials"))

        req.session.value["isadmin"] = True if len(auth_user["roles"]) == 0 else False
        req.session.value["database"] = auth_user["mica_database"]

        mdebug("verifying...")
        self.verify_db(req, auth_user["mica_database"], password = password)

        update_user = False

        if not mobile :
            if "temp_jabber_pw" not in params :
                auth_user["temp_jabber_pw"] = req.session.value["temp_jabber_pw"]
                update_user = True

        if "quota" not in auth_user :
            if req.session.value["isadmin"] :
                auth_user["quota"] = -1
            else :
                auth_user["quota"] = 300
            if not mobile :
                update_user = True

        if not mobile and update_user :
                try :
                    self.userdb["org.couchdb.user:" + username] = auth_user
                except couch_adapter.CommunicationError, e :
                    mwarn("User database access expired...")
                    # If the userdb times out, we do have to reacquire it,
                    # even though its used in other places. Login-time will be the only
                    # place it gets updated.
                    self.cs = self.db_adapter(couch_adapter.credentials(params), params["admin_user"], params["admin_pass"], refresh = True)
                    self.userdb = self.cs["_users"]
                    if self.userdb :
                        self.db = self.userdb
                    mwarn("Retrying userdb access...")
                    self.userdb["org.couchdb.user:" + username] = auth_user

        req.session.value["quota"] = auth_user["quota"]

        if mobile :
            if req.db.doc_exist("MICA:appuser") :
               mdebug("There is an existing user. Verifying it is the same one.")
               appuser = req.db["MICA:appuser"]
               if appuser["username"] != username :
                    # Beginning of a message
                    return self.bad_api(req, _("We're sorry. The MICA Reader database on this device already belongs to the user") + " " + \
                        appuser["username"] + " " + _("and is configured to stay in synchronization with the server") + ". " + \
                        _("If you want to change users, you will need to clear this application's data or reinstall it and re-synchronize the app with") + " " + \
                        _("a new account. This requirement is because MICA databases can become large over time, so we want you to be aware of that. Thanks."))
            else :
               mdebug("First time user. Reserving this device: " + username)
               appuser = {"username" : username}
               req.db["MICA:appuser"] = appuser

            tmpuser = req.db.try_get(self.acct(username))
            if tmpuser and "filters" in tmpuser :
                mdebug("Found old filters.")
                req.session.value["filters"] = tmpuser["filters"]
            if not req.db.replicate(address, username, password, req.session.value["database"], params["local_database"], self.get_filter_params(req)) :
                # This 'synchronization' refers to the ability of the story to keep the user's learning progress and interactive history and stories and all other data in sync across both the website and all devices that the user owns.
                return self.bad_api(req, _("Although you have authenticated successfully, we could not start synchronization successfully. Please try again."))
            if not self.filedb.replicate(address, "files", "password", "files", "files", self.get_filter_params(req)) :
                return self.bad_api(req, _("Although you have authenticated successfully, we could not start synchronization successfully. Please try again."))

        if mobile :
            if "local_username" in params and params["local_username"] and "local_password" in params and params["local_password"] :
                # This is just for testing. It will break the app story uploads on mobile, but will allow us to connect to the device and debug things.
                req.session.value["port"] = req.db.listen(params["local_username"], params["local_password"], params["local_port"])
            else :
                req.session.value["port"] = req.db.listen(username, req.session.value["password"], params["local_port"])

        req.action = "home"
        req.session.value["connected"] = True
        req.s.timeout(params["timeout"])

        if req.http.params.get('remember') and req.http.params.get('remember') == 'on' :
            req.session.value["last_username"] = username
            req.session.value["last_remember"] = 'checked'
        elif 'last_username' in req.session.value :
            del req.session.value["last_username"]
            req.session.value["last_remember"] = ''

        self.clear_story(req)

        req.session.value["last_refresh"] = str(timest())

        user = req.db.try_get(self.acct(username))
        if not user :
            mwarn("Problem before warn_not_replicated:")
            print_stack()
            return self.bad_api(req, self.warn_not_replicated(req))

        if not mobile :
            try :
                self.jobsmutex.acquire()
                jobs = req.db.try_get("MICA:jobs")
                if not jobs :
                    req.db["MICA:jobs"] = {"list" : {}}
                self.jobsmutex.release()
            except Exception, e :
                self.jobsmutex.release()
                req.session.save()
                raise e

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
            self.view_check(req.session.value["username"], "stories", recreate = True)
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

        if not mobile :
            try :
                if req.db.doc_exist("MICA:filelisting") :
                    del req.db["MICA:filelisting"]

                for name, lgp in self.processors.iteritems() :
                    for f in lgp.get_dictionaries() :
                        if req.db.doc_exist("MICA:filelisting_" + f) :
                            mdebug("Deleting old file: " + f)
                            del req.db["MICA:filelisting_" + f]
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

    def render_logged_in_check(self, req) :
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
            self.check_all_views(username)

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
                    self.view_check(req.session.value["username"], "stories", recreate = True)

                for result in req.db.view("stories/upgrading", startkey=[req.session.value["username"]], endkey=[req.session.value['username'], {}]) :
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

            try :
                self.jobsmutex.acquire()
                tmpjobs = req.db.try_get("MICA:jobs")

                if tmpjobs and len(tmpjobs["list"]) > 0 :
                    mdebug("Resettings jobs for user.")
                    tmpjobs["list"] = {}
                    req.db["MICA:jobs"] = tmpjobs
                self.jobsmutex.release()
            except Exception, e :
                self.jobsmutex.release()
                raise e

            self.first_request[username] = True
            req.session.value["last_refresh"] = str(timest())
            req.session.save()

    def render_bulkreview(self, req, name) :
        count = int(req.http.params.get("count"))

        mdebug("Going to perform reviews for " + str(count) + " words.")

        for idx in range(0, count) :
            nb_unit = int(req.http.params.get("nbunit" + str(idx)))
            mindex = int(req.http.params.get("index" + str(idx)))
            trans_id = int(req.http.params.get("transid" + str(idx)))
            page = req.http.params.get("page" + str(idx))

            mdebug("Review word: " + str(idx) + " index: " + str(mindex) + " unit " + str(nb_unit) + " id " + str(trans_id))
            self.multiple_select(req, False, nb_unit, mindex, trans_id, page, name)
        req.viewpageresult = _("Bulk review complete")

    def render_oprequest(self, req, story) :
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
                offset = self.operation(req, story, edit, offset)
            except OSError, e :
                mwarn("Problem before warn_not_replicated:")
                for line in format_exc().splitlines() :
                    mwarn(line)
                return self.bad_api(req, self.self.warn_not_replicated(req))
            except AttributeError, e :
                mwarn("Problem before warn_not_replicated:")
                for line in format_exc().splitlines() :
                    mwarn(line)
                return self.bad_api(req, self.self.warn_not_replicated(req))

    def render_rest(self, req, from_third_party) :
        pageid = "#messages"
        if from_third_party and "output" in from_third_party :
            return from_third_party["output"] + "<br/><b>" + _("Start learning!") + "</b>"
        elif from_third_party and "redirect" in from_third_party :
            return from_third_party["redirect"]
        else :
            # This occurs when you come back to the webpage, and were previously reading a story, but need to indicate in which mode to read the story (of three modes).
            out = _("Read, Review, or Edit, my friend?") + "<br/><br/>"
            out += _("If this is your first time here") + ", <a data-role='none' class='btn btn-primary' href='#help'>"
            out += _("please read the tutorial") + "</a>"
            if "last_view_mode" in req.session.value :
                pageid = "#learn"

        if "last_view_mode" in req.session.value :
            out += "<div id='lastmode'>" + req.session.value["last_view_mode"] + "</div>"

        return self.render_mainpage(req, out, pageid = pageid)


    def get_list_mode(self, req) :
        list_mode = True

        if "list_mode" in req.session.value :
            list_mode = req.session.value["list_mode"]
        else :
            req.session.value["list_mode"] = list_mode
            req.session.save()

        return list_mode

    def render(self, req) :
        global times
        mverbose(str(req.http.params))
        if req.action in ["disconnect", "privacy", "help", "switchlang", "online", "instant" ] :
            func = getattr(self, "render_" + req.action)
            return func(req)

        if req.action == "auth" and not mobile :
            return self.render_auth(req)

        from_third_party = False

        if not mobile and req.action in params["oauth"].keys() :
            api, oauth_result = self.render_oauth(req)
            if isinstance(oauth_result, str) or isinstance(oauth_result, unicode) :
                # polled oauth provider successfully, but have not created
                # account in the system (which is slow). Need print the front
                # page again and wait for an ajax request to do that stuff.
                # There might also be an error here.

                # api == False means both:
                # 1. We need the 2nd-state ajax to complete the login (good)
                # 2. There was an error.
                if api :
                    return self.api(req, oauth_result)
                else :
                    req.messages = oauth_result
                    return self.render_frontpage(req)

            # This is a response to the ajax request that the account was
            # finished being created (finish=1), but we have no yet set the
            # user to 'connected' yet, which happens below.
            from_third_party = oauth_result

        if req.http.params.get("connect") or from_third_party != False :
            if not mobile and req.http.params.get("username") and  req.http.params.get("username") == "demo" :
                # The demo account is provided for users who want to give the software a try without committing to it.
                mwarn("Demo account bad request.")
                return self.bad_api(req, _("Demo Account is readonly. You must install the mobile application for interactive use of the demo account."))

            # We could be connecting for both local accounts and oauth
            connect_result = self.render_connect(req, from_third_party)
            if connect_result :
                # There was an error with anything
                return connect_result

            # This is a response to an ajax request to complete the
            # connection
            if from_third_party :
                return self.api(req, req.messages)

            # Local account. Nothing to do.
            return self.api(req)

        self.install_local_language(req)

        if "connected" not in req.session.value or req.session.value["connected"] != True :
            if req.api :
                mdebug("401 HTTPUnauthorized API request. Returning fail.")
                raise exc.HTTPUnauthorized("you're not logged in anymore.")

            return self.render_frontpage(req)

        self.render_logged_in_check(req)

        if req.action == "chat_ime" :
            return self.render_chat_ime(req)

        for param in ["uploadfile", "uploadtext"] :
            if req.http.params.get(param) :
                return getattr(self, "render_" + param)(req)

        start_page = "0"
        uuid = False
        name = False
        story = False

        if req.http.params.get("uuid") :
            uuid = req.http.params.get("uuid")
            try :
                name = req.db[self.index(req, uuid)]["value"]
            except couch_adapter.ResourceNotFound, e :
                mwarn("UUID " + uuid + " not found. =(")
                name = False
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
            else :
                return self.bad_api(req, "We can't satisfy your request.")

        if req.http.params.get("delete") :
            return self.api(req, self.new_job(req, self.deletestory, False, _("Deleting Story From Database"), name, False, args = [req, uuid, name]), { "job_running" : True })

        if req.http.params.get("storyinit") :
            return self.api(req, self.new_job(req, self.storyinit, False, _("Initializing Story in Database"), name, False, args = [req, uuid, name]), { "job_running" : True })

        if uuid :
            if not req.db.doc_exist(self.index(req, uuid)) :
                self.clear_story(req)
                # The user tried to access a story that does not exist (probably because they deleted it), but because they navigated to an old webpage address, they provide the software with a UUID (identifier) of a non-existent story by accident due to the browser probably having cached the address in the browser's history.
                return self.render_mainpage(req, _("Invalid story uuid") + ": " + uuid)

        for param in ["tstatus", "finished", "reviewed", "translate"] :
            if req.http.params.get(param) :
                return getattr(self, "render_" + param)(req, story)

        if req.http.params.get("forget") :
            # Resetting means that we are dropping the translate contents of the original story. We are
            # not deleteing the story itself, nor the user's memorization data, only the translated
            # version of the story itself.
            return self.api(req, self.new_job(req, self.forgetstory, False, _("Resetting Story In Database"), name, False, args = [req, uuid, name]), { "job_running" : True, "uuid" : uuid })

        if req.http.params.get("switchmode") :
            rmode = req.http.params.get("switchmode")
            if rmode in ["text", "images", "both"] :
                req.session.value["view_mode"] = rmode
                return self.api(req)
            return self.bad_api(req, "No such mode: " + rmode)

        if req.http.params.get("meaningmode") :
            req.session.value["meaning_mode"] = req.http.params.get("meaningmode")
            return self.api(req)

        if req.http.params.get("switchlist") :
            req.session.value["list_mode"] = True if int(req.http.params.get("switchlist")) == 1 else False
            return self.api(req, json = {"list_mode" : req.session.value["list_mode"]})

        # We want the job list to appear before using any story-related functions
        # User must wait.
        jobs = req.db.try_get("MICA:jobs")

        if jobs and len(jobs["list"]) > 0 and req.action not in ["chat_ime"] :
            rjobs = self.render_jobs(req, jobs)
            return self.api(req, self.render_mainpage(req, rjobs) if req.human else rjobs, json = {"job_running" : True} )

        # Functions only go here if they are actions against the currently reading story
        # Functions above here can happen on any story

        if "current_story" in req.session.value :
            if uuid :
                if req.session.value["current_story"] != uuid :
                    self.clear_story(req)
                req.session.value["current_story"] = uuid
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
                    print_stack()
                    return self.warn_not_replicated(req)

            if "current_page" in tmp_story :
                start_page = tmp_story["current_page"]
                mdebug("Loading start page: " + str(start_page))
                pages = self.nb_pages(req, tmp_story)
                if (int(start_page) + 1) > pages :
                    mwarn("Can't load a start page that's higher than the number of pages. Clamping to last page.")
                    start_page = pages - 1

            start_page = str(max(0, int(str(start_page))))

        for param in ["multiple_select", "reviewlist", "editslist", "memorizednostory", "memorized", "storyupgrade", "memolist", "oprequest" ] :
            if req.http.params.get(param) :
                result = getattr(self, "render_" + param)(req, story)
                # Oprequests still need to return a rendered page.
                if param != "oprequest" :
                    return result

        if req.http.params.get("retranslate") :
            page = req.http.params.get("page")
            try :
                self.parse(req, story, page = page)
            except OSError, e :
                mwarn("Problem before warn_not_replicated:")
                for line in format_exc().splitlines() :
                    mwarn(line)
                req.viewpageresult = self.warn_not_replicated(req)

        if req.http.params.get("bulkreview") :
            self.render_bulkreview(req, name)

        if req.action in ["home", "read", "edit" ] :
            return self.render_story(req, uuid, start_page)

        if req.action in ["stories", "storylist", "account", "chat"] :
            func = getattr(self, "render_" + req.action)
            return func(req, story)

        return self.render_rest(req, from_third_party)

class IDict(Interface):
    value = Attribute("Dictionary for holding session keys and values.")

class CDict(object):
    implements(IDict)
    def __init__(self, session):
        self.mica = session.mica
        start = {}
        uid = session.uid

        if params["keepsession"] :
            skey = self.mica.session("debug")
        else :
            skey = self.mica.session(uid)

        if self.mica.sessiondb.doc_exist(skey) :
            mdebug("Loading existing session: " + skey)
            start = self.mica.sessiondb[skey]
        else :
            mdebug("No session existing: " + skey)

        self.value = start
        self.value["session_uid"] = uid

    def save(self, ignore_expired = False, force = False) :
        in_a_job = False
        try :
            in_a_job = getattr(current_thread(), "in_a_job")
        except AttributeError, e :
            pass

        uid = self.value["session_uid"]
        if params["keepsession"] :
            skey = self.mica.session("debug")
        else :
            skey = self.mica.session(self.value["session_uid"])

        if uid not in sessions :
            mwarn("4) We expired, don't take lock.")
            raise exc.HTTPUnauthorized("you're not logged in anymore.")

        if force or ("connected" in self.value and self.value["connected"]) :
            sessions[uid].acquire()
            mdebug("Saving to session: " + skey)
            if self.mica.sessiondb.doc_exist(skey) :
                old_doc = self.mica.sessiondb[skey]
                self.value["_rev"] = old_doc["_rev"]
                mdebug("Using revision: " + old_doc["_rev"])
            else :
                if in_a_job :
                    mwarn("3) We expired, but we're just a background job, so it's fine.")
                    sessions[uid].release()
                    return

                if "_rev" in self.value :
                    # We didn't race. We're good.
                    # expired() already cleaned everything up
                    # Just kick the user out, even in the middle of a request
                    sessions[uid].release()
                    raise exc.HTTPUnauthorized("you're not logged in anymore.")
            try :
                self.value["updated_at"] = timest()
                self.mica.sessiondb[skey] = self.value
                #sessions[self.value["session_uid"]] = Lock()
            except couch_adapter.ResourceConflict, e :
                if in_a_job :
                    mwarn("1) We expired, but we're just a background job, so it's fine.")
                else :
                    sessions[uid].release()
                    for line in format_exc().splitlines() :
                        merr(line)
                    raise e
            except couch_adapter.ResourceNotFound, e :
                if in_a_job :
                    mwarn("2) We expired, but we're just a background job, so it's fine.")
                else :
                    sessions[uid].release()
                    for line in format_exc().splitlines() :
                        merr(line)
                    raise e

            mdebug("Session updated: " + skey)
            sessions[uid].release()
        else :
            mdebug("Session not connected. Won't save yet: " + skey)

sessions = {}

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

        request.s = request.getSession()

        if name.count(relative_prefix_suffix):
            return self.serve
        #if name.count("stories") :
        #    return self.stories
        if name.count("favicon.ico"):
            return self.icon
        #elif name.count("git"):
        #    return self.git
        else :
            return self.app

class MicaSession(Session) :
    sessionTimeout = 600 # timeout for sessions that don't actually login

    def timeout(self, timeout) :
        mdebug("Setting new timeout to: " + str(timeout))
        self.sessionTimeout = timeout
        try :
            self.touch()
        except AlreadyCalled, e :
            mwarn("Touch didn't work. Ignore")

class NONSSLRedirect(object) :
    def __init__(self):
        pass

    def __call__(self, environ, start_response):
        req = Params(environ)
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
        request.s = request.getSession()
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

    parser.add_option("-z", "--couchpath", dest = "couchpath", default = "", help = "couchdb path after port name")

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
               "couch_path" : options.couchpath,
    }

    return params

slaves = {}
params = None

class MicaSite(Site) :
    def __init__(self, *args, **kwargs) :
        Site.__init__(self, *args, **kwargs)
    
    def getSession(self, uid):
        if uid in self.sessions :
            return self.sessions[uid]

        if params["keepsession"] :
            skey = self.mica.session("debug")
        else :
            skey = self.mica.session(uid)

        try :
            if self.mica.sessiondb.doc_exist(skey) :
                mdebug("Loading existing session: " + skey)
                start = self.mica.sessiondb[skey]
                session = self.sessions[uid] = self.sessionFactory(self, uid)
                session.timeout(params["timeout"])
                session.startCheckingExpiration()
                return session
        except Exception, e :
            merr("Error checking for DB session: " + str(e))

        raise KeyError

def go(p) :
    global params
    params = p

    if "multipliers" not in params :
        params["multipliers"] = { "days" : 7, "weeks" : 4, "months" : 12, "years" : 10, "decades" : 10 }
        # All the months are not the same.... not sure what to do about that

    if "counts" not in params :
        params["counts"] = { "days" : 1, "weeks" : 7, "months" : 30, "years" : 365, "decades" : 3650 }

    if "seconds_in_day" not in params :
        params["seconds_in_day"] = 60*60*24

    if "timeout" not in params :
        params["timeout"] = 604800

    sys_settrace(None)

    if not mobile :
        prelang = "en"
        try :
            mverbose("Locale is: " + setlocale(LC_ALL, '')) # use user's preferred locale
            # take first two characters of country code
            prelang = getlocale()[0][0:2]
        except Exception, e :
            mdebug("Could not find locale. Defaulting to english.")

        pre_init_localization(prelang)

    mverbose("Verifying options.")

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

    sslport = int(params["sslport"])
    if sslport != -1 and (not params["cert"] or not params["privkey"]) :
        merr("Need locations of SSL certificate and private key (options -C and -K). You can generate self-signed ones if you want, see the README.")
        exit(1)

    if "test" not in params :
        params["test"] = False

    if "trans_scope" not in params :
        params["trans_scope"] = "http://api.microsofttranslator.com"

    if "trans_access_token_url" not in params :
        params["trans_access_token_url"] = "https://datamarket.accesscontrol.windows.net/v2/OAuth2-13"

    if params["test"] :
        mdebug("Will run inputs and outputs in test mode.")

    if not params["scratch"] :
        merr("You must provide the path to a read/write folder where replicated dictionary databases can be placed (particularly on a mobile device.)")
        exit(1)

    if "serialize_couch_on_mobile" not in params :
        params["serialize_couch_on_mobile"] = False

    if not mobile :
        if os_path.isdir("/tmp/mica_uploads") :
            mverbose("Deleting old uploaded files.")
            shutil_rmtree("/tmp/mica_uploads")
        os_makedirs("/tmp/mica_uploads")

    mverbose("Registering session adapter.")
    registerAdapter(CDict, Session, IDict)

    mverbose("Initializing logging.")
    mica_init_logging(params["log"], duplicate = params["duplicate_logger"])

    if params["tlog"] :
        if params["tlog"] != 1 :
            mverbose("Initializing twisted log.")
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
        site = MicaSite(GUIDispatcher(mica))
        site.sessionFactory = MicaSession
        site.mica = mica
        nonsslsite = MicaSite(NONSSLDispatcher())
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
            mwarn("SSL not requested. Be careful =)")
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

        mverbose("Setting up serialization queues and coroutine.")
        if mobile :
            rt = Thread(target = reactor.run, kwargs={"installSignalHandlers" : 0})
        else :
            rt = Thread(target = reactor.run)

        rt.daemon = True
        rt.start()

        mica.serial.consume()

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

    fh = open(cwd + "serve/" + spinner, 'r')
    contents = fh.read()
    encoded2 = base64_b64encode(contents)
    fh.close()

    mverbose("Rendering template: " + output)
    outresult = output % dict(encoded1 = encoded1,
                         encoded2 = encoded2,
                         pleasewait = _("Please wait..."))
    mverbose("Render complete.")
    return outresult

if __name__ == "__main__":
    mdebug("Ready to go.")
    params = get_options()
    params["couch_adapter_type"] = "MicaServerCouchDB"
    go(params)

